//! The Keychain Tier-1 backend.
//!
//! **Authority:** ADR-0018 CB-7 (whole-blob atomic replacement, "the shape
//! Keychain / Keystore / DPAPI / libsecret actually have"); ADR-0020 §11.3's
//! macOS rows, ST-5/ST-6 (the accessibility class), ST-22 (the anchor is
//! co-located with the identity key), §10.5 (the item ACL binds to the
//! code-signing identity, so a Team-ID change is a store migration).
//!
//! # Compile-only, and stated as such
//!
//! Every line here is `#[cfg(target_os = "macos")]`. `make cross-check` type-checks
//! it against the real `security-framework-sys` for `aarch64-apple-darwin`, which
//! proves the API shapes and the `OSStatus` handling and **proves nothing about
//! behaviour**. It is kept thin by giving it nothing to decide:
//! [`crate::custody::KeychainItemSpec`] carries the whole item shape as data,
//! chosen at construction and tested on the Linux host, and this module turns that
//! data into CF objects.
//!
//! # Why `SecItemAdd` then `SecItemUpdate` and never delete-then-add
//!
//! [`twinvpn_platform::SecureStore::secure_item_write_atomic`] is atomic **per
//! item**, because "a torn write of the SEK would make the whole vault unreadable,
//! and ADR-0020's recovery ladder cannot recover a key it never received". A
//! delete followed by an add has a window in which the item does not exist, and a
//! crash in that window loses the SEK permanently. `SecItemUpdate` replaces the
//! value in one transaction; `SecItemAdd` is tried first because update on an
//! absent item is `errSecItemNotFound` rather than an insert.

#![cfg(target_os = "macos")]

use core_foundation_sys::base::{
    kCFAllocatorDefault, CFGetTypeID, CFRelease, CFTypeRef, TCFTypeRef,
};
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID};
use core_foundation_sys::dictionary::{
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreateMutable,
    CFDictionaryRef, CFDictionarySetValue,
};
use core_foundation_sys::number::{kCFBooleanFalse, kCFBooleanTrue};
use core_foundation_sys::string::{kCFStringEncodingUTF8, CFStringCreateWithBytes};
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecUseDataProtectionKeychain,
    kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

extern "C" {
    /// `kSecAttrAccessible`. Not exported by `security-framework-sys` 2.17, which
    /// declares the *values* (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`)
    /// but not the attribute key they go under. Declared here with its
    /// `<Security/SecItem.h>` type rather than worked around, because ST-5/ST-6
    /// make the accessibility class mandatory and an item written without it takes
    /// the platform default — `kSecAttrAccessibleWhenUnlocked`, which those rules
    /// forbid.
    static kSecAttrAccessible: core_foundation_sys::string::CFStringRef;

    /// `kSecMatchLimitOne`. Also absent from the sys crate, which exports only
    /// `kSecMatchLimitAll`. A read that matched *all* would return a `CFArray`
    /// where this code expects a `CFData`, and the type check below would refuse
    /// it — a correct refusal of a query nobody meant to write.
    static kSecMatchLimitOne: core_foundation_sys::string::CFStringRef;
}

use twinvpn_platform::PlatformError;

use crate::custody::{Accessibility, CustodyClass, KeychainItemSpec, Tier1Store};
use crate::oserr::{self, Context};

/// A Core Foundation reference this code owns, released exactly once on drop.
///
/// The same discipline as [`crate::dynstore`]'s: one release per `Create`/`Copy`,
/// on the error path as well as the happy one.
struct CfOwned(CFTypeRef);

impl Drop for CfOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from a CF `Create` or `Copy` function, this
            // code holds the one reference to it, and the type has no other
            // constructor and no `Copy`.
            unsafe { CFRelease(self.0) };
        }
    }
}

impl CfOwned {
    fn new(reference: CFTypeRef, call: &'static str) -> Result<Self, PlatformError> {
        if reference.is_null() {
            return Err(oserr::unavailable(call, libc::ENOMEM));
        }
        Ok(Self(reference))
    }

    const fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

fn cf_string(text: &str) -> Result<CfOwned, PlatformError> {
    let Ok(length) = core_foundation_sys::base::CFIndex::try_from(text.len()) else {
        return Err(oserr::unavailable("CFStringCreateWithBytes", libc::EOVERFLOW));
    };
    // SAFETY: `text` is valid for `text.len()` bytes for the duration of the call,
    // which is all `CFStringCreateWithBytes` reads; it copies. `0` says the bytes
    // are not an external representation, which is correct for UTF-8 with no BOM.
    let reference = unsafe {
        CFStringCreateWithBytes(
            kCFAllocatorDefault,
            text.as_ptr(),
            length,
            kCFStringEncodingUTF8,
            0,
        )
    };
    CfOwned::new(reference.as_void_ptr(), "CFStringCreateWithBytes")
}

fn cf_data(bytes: &[u8]) -> Result<CfOwned, PlatformError> {
    let Ok(length) = core_foundation_sys::base::CFIndex::try_from(bytes.len()) else {
        return Err(oserr::unavailable("CFDataCreate", libc::EOVERFLOW));
    };
    // SAFETY: `bytes` is valid for `bytes.len()` for the duration of the call and
    // `CFDataCreate` copies.
    let reference = unsafe {
        core_foundation_sys::data::CFDataCreate(
            kCFAllocatorDefault,
            bytes.as_ptr(),
            length,
        )
    };
    CfOwned::new(reference.as_void_ptr(), "CFDataCreate")
}

fn cf_dictionary() -> Result<CfOwned, PlatformError> {
    // SAFETY: zero capacity is "unbounded"; both callback statics are CF's own and
    // live for the process.
    let reference = unsafe {
        CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            0,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    CfOwned::new(reference.as_void_ptr(), "CFDictionaryCreateMutable")
}

/// Sets one key. The dictionary's type callbacks retain both, so the caller's own
/// releases remain correct.
fn set(dictionary: &CfOwned, key: CFTypeRef, value: CFTypeRef) {
    // SAFETY: `dictionary` holds a live mutable dictionary created with the type
    // callbacks; `key` and `value` are live CF objects for the duration of the
    // call. The `cast_mut` recovers the mutability `CFDictionaryCreateMutable`
    // returned and `CfOwned` erased; no shared reference to the dictionary exists,
    // because `CfOwned` has no `Clone` and this is the only accessor.
    unsafe {
        CFDictionarySetValue(dictionary.as_ptr().cast_mut().cast(), key, value);
    }
}

/// The Keychain-backed Tier-1 store.
#[derive(Debug)]
pub struct KeychainStore {
    spec: KeychainItemSpec,
    /// What this build truthfully is. **Declared, not sniffed**: whether the key
    /// is behind a Secure Enclave is a packaging fact (which of ADR-0020's four
    /// macOS rows this build is), and an adapter that probed for a SEP and then
    /// reported what it found would be deciding its own custody class.
    custody: CustodyClass,
}

impl KeychainStore {
    /// Binds the store to an item shape and a declared custody class.
    #[must_use]
    pub const fn new(spec: KeychainItemSpec, custody: CustodyClass) -> Self {
        Self { spec, custody }
    }

    /// The query that identifies exactly one item.
    ///
    /// Class, service and account, plus the keychain selector. Deliberately **not**
    /// the accessibility attribute: `kSecAttrAccessible` is part of an item's
    /// identity on some releases and not on others, and including it in a *query*
    /// makes a lookup miss an item the previous version of this code wrote.
    fn query(&self, account: &str) -> Result<CfOwned, PlatformError> {
        let dictionary = cf_dictionary()?;
        let service = cf_string(&self.spec.service)?;
        let account = cf_string(account)?;
        // SAFETY of every `set`: the statics are CF strings CF owns for the life
        // of the process, and each local is live until the end of this function.
        unsafe {
            set(&dictionary, kSecClass.cast(), kSecClassGenericPassword.cast());
            set(&dictionary, kSecAttrService.cast(), service.as_ptr());
            set(&dictionary, kSecAttrAccount.cast(), account.as_ptr());
            set(
                &dictionary,
                kSecAttrSynchronizable.cast(),
                // ADR-0020 excludes Tier 1 from sync. An item that reached iCloud
                // Keychain would put the SEK on every device the Owner signs into,
                // which is the opposite of `ThisDeviceOnly`.
                kCFBooleanFalse.cast(),
            );
            if self.spec.accessibility.uses_data_protection_keychain() {
                set(
                    &dictionary,
                    kSecUseDataProtectionKeychain.cast(),
                    kCFBooleanTrue.cast(),
                );
            }
        }
        if let Some(group) = &self.spec.access_group {
            let group = cf_string(group)?;
            // SAFETY: as above.
            unsafe { set(&dictionary, kSecAttrAccessGroup.cast(), group.as_ptr()) };
            // `group` must outlive the `set`, and does: the dictionary retained it.
            drop(group);
        }
        Ok(dictionary)
    }

    /// The query plus the attributes only an **insert** carries.
    fn insert_attributes(&self, account: &str, value: &[u8]) -> Result<CfOwned, PlatformError> {
        let dictionary = self.query(account)?;
        let data = cf_data(value)?;
        // SAFETY: as in `query`.
        unsafe {
            set(&dictionary, kSecValueData.cast(), data.as_ptr());
            if matches!(
                self.spec.accessibility,
                Accessibility::AfterFirstUnlockThisDeviceOnly
            ) {
                // ST-5/ST-6. `kSecAttrAccessibleWhenUnlocked` is forbidden: a
                // daemon runs with no user session, and an item it cannot read is
                // an agent that cannot start.
                set(
                    &dictionary,
                    kSecAttrAccessible.cast(),
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.cast(),
                );
            }
        }
        drop(data);
        Ok(dictionary)
    }
}

impl Tier1Store for KeychainStore {
    fn read(&self, account: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        let query = self.query(account)?;
        // SAFETY: the statics are CF's own; `query` holds a live dictionary.
        unsafe {
            set(&query, kSecReturnData.cast(), kCFBooleanTrue.cast());
            set(&query, kSecMatchLimit.cast(), kSecMatchLimitOne.cast());
        }
        let mut result: CFTypeRef = core::ptr::null();
        // SAFETY: `query` is a live dictionary; `result` is a live pointer we own.
        // `SecItemCopyMatching` follows the Copy Rule, so a non-null result is
        // owned and is released by `CfOwned` below.
        let status = unsafe { SecItemCopyMatching(query.as_ptr().cast::<CFDictionaryRef>().cast(), &raw mut result) };
        if status == errSecItemNotFound {
            // **Absent is not an error.** The seam's contract: "'absent' enrols
            // and 'unavailable' must not", and collapsing the two would make a
            // locked keychain look like a first run and enrol a second identity.
            return Ok(None);
        }
        if status != 0 {
            return Err(oserr::from_os_status(
                i64::from(status),
                "SecItemCopyMatching",
                Context::SecureStore,
            ));
        }
        let owned = CfOwned::new(result, "SecItemCopyMatching")?;
        // SAFETY: `owned` holds a live CF object; `CFGetTypeID` reads its header.
        let is_data = unsafe { CFGetTypeID(owned.as_ptr()) == CFDataGetTypeID() };
        if !is_data {
            return Err(oserr::unavailable("SecItemCopyMatching.type", libc::EINVAL));
        }
        // SAFETY: `owned` is a live `CFData`. `CFDataGetBytePtr` returns a pointer
        // valid while it lives, and `CFDataGetLength` its true length, so the
        // slice below is in bounds for the whole copy.
        let bytes = unsafe {
            let pointer = CFDataGetBytePtr(owned.as_ptr().cast());
            let length = CFDataGetLength(owned.as_ptr().cast());
            let Ok(length) = usize::try_from(length) else {
                // A negative length is a `CFData` this build does not understand.
                return Err(oserr::unavailable("CFDataGetLength", libc::EINVAL));
            };
            if pointer.is_null() {
                return Err(oserr::unavailable("CFDataGetBytePtr", libc::EINVAL));
            }
            core::slice::from_raw_parts(pointer, length).to_vec()
        };
        Ok(Some(bytes))
    }

    fn write(&self, account: &str, value: &[u8]) -> Result<(), PlatformError> {
        let attributes = self.insert_attributes(account, value)?;
        // SAFETY: `attributes` is a live dictionary; a null result pointer is the
        // documented "I do not want the item back" form.
        let status = unsafe {
            SecItemAdd(
                attributes.as_ptr().cast::<CFDictionaryRef>().cast(),
                core::ptr::null_mut(),
            )
        };
        if status == 0 {
            return Ok(());
        }
        // The item already exists. Replace its value **in one transaction**: a
        // delete-then-add has a window in which the SEK does not exist, and a
        // crash there loses the vault permanently.
        let query = self.query(account)?;
        let update = cf_dictionary()?;
        let data = cf_data(value)?;
        // SAFETY: as above.
        unsafe { set(&update, kSecValueData.cast(), data.as_ptr()) };
        // SAFETY: both are live dictionaries for the duration of the call.
        let status = unsafe {
            SecItemUpdate(
                query.as_ptr().cast::<CFDictionaryRef>().cast(),
                update.as_ptr().cast::<CFDictionaryRef>().cast(),
            )
        };
        drop(data);
        if status == 0 {
            Ok(())
        } else {
            Err(oserr::from_os_status(
                i64::from(status),
                "SecItemUpdate",
                Context::SecureStore,
            ))
        }
    }

    fn delete(&self, account: &str) -> Result<(), PlatformError> {
        let query = self.query(account)?;
        // SAFETY: `query` is a live dictionary for the duration of the call.
        let status = unsafe { SecItemDelete(query.as_ptr().cast::<CFDictionaryRef>().cast()) };
        // Idempotent: an item that was already absent is the state the caller
        // wanted.
        if status == 0 || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(oserr::from_os_status(
                i64::from(status),
                "SecItemDelete",
                Context::SecureStore,
            ))
        }
    }

    fn custody_class(&self) -> CustodyClass {
        self.custody
    }
}
