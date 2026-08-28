//! `SCDynamicStore`: the `LaunchDaemon`'s resolver carrier.
//!
//! **Authority:** ADR-0011 §11.6 and §11.9's macOS rows; DN-18 (restore point
//! first); ADR-0016 PS-6; ADR-0018 CB-3 and DP-4.
//!
//! # The most unverifiable module in this crate, and why it is still small
//!
//! Everything here is `#[cfg(target_os = "macos")]` and none of it runs on this
//! host. `make cross-check` type-checks it against the real
//! `system-configuration-sys` and `core-foundation-sys` for
//! `aarch64-apple-darwin`, which proves the API shapes and the ownership
//! signatures and **proves nothing about behaviour**.
//!
//! It is kept as thin as it can be by giving it nothing to decide:
//! [`crate::resolver::plan`] computes the whole programme as data, tested on this
//! host, and this module walks it. There is no `DnsConfig` in this file, no
//! `.local` filter, no limit check and no ordering — only "turn these three value
//! shapes into CF objects and hand them to `configd`".
//!
//! # Core Foundation ownership, stated once
//!
//! CF's rule is the *Create Rule*: a function with `Create` or `Copy` in its name
//! returns a reference **you own** and must `CFRelease`; everything else returns a
//! borrow you must not release. Every `Create`/`Copy` result below is wrapped in
//! [`CfOwned`], whose `Drop` is the release — so there is exactly one release per
//! create and it happens on the error path too, which is where a hand-written
//! `CFRelease` gets forgotten.

#![cfg(target_os = "macos")]

use core_foundation_sys::array::{
    kCFTypeArrayCallBacks, CFArrayAppendValue, CFArrayCreateMutable, CFArrayGetCount,
    CFArrayGetValueAtIndex, CFArrayRef,
};
use core_foundation_sys::base::{
    kCFAllocatorDefault, CFGetTypeID, CFRelease, CFTypeRef, TCFTypeRef,
};
use core_foundation_sys::dictionary::{
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreateMutable,
    CFDictionaryGetTypeID, CFDictionaryGetValue, CFDictionaryRef, CFDictionarySetValue,
};
use core_foundation_sys::number::{kCFNumberSInt32Type, CFNumberCreate};
use core_foundation_sys::string::{
    kCFStringEncodingUTF8, CFStringCreateWithBytes, CFStringGetCString, CFStringGetTypeID,
    CFStringRef,
};
use system_configuration_sys::dynamic_store::{
    SCDynamicStoreCopyValue, SCDynamicStoreCreate, SCDynamicStoreRef, SCDynamicStoreRemoveValue,
    SCDynamicStoreSetValue,
};

use twinvpn_platform::PlatformError;

use crate::oserr::{self, Context};
use crate::resolver::{dns_key, ResolverPlan, RestorePoint, ScValue};

extern "C" {
    /// `SCError()` — the last `SystemConfiguration` error for this thread.
    ///
    /// Not declared by `system-configuration-sys` 0.6, so it is declared here with
    /// its `<SystemConfiguration/SCPrivate.h>` signature. Without it every failure
    /// would reach the seam as an unexplained `false`, which is exactly what §4.2
    /// forbids.
    fn SCError() -> libc::c_int;
}

/// A Core Foundation reference this code owns, released exactly once on drop.
struct CfOwned(CFTypeRef);

impl Drop for CfOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from a CF `Create` or `Copy` function, so this
            // code holds one reference to it and has not released it — the type
            // has no other constructor and no `Copy`. `CFRelease` on a non-null
            // owned reference is the documented balance for that.
            unsafe { CFRelease(self.0) };
        }
    }
}

impl CfOwned {
    /// Wraps a `Create`/`Copy` result, refusing null.
    fn new(reference: CFTypeRef, call: &'static str) -> Result<Self, PlatformError> {
        if reference.is_null() {
            return Err(sc_error(call));
        }
        Ok(Self(reference))
    }

    fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

/// The last `SCError`, mapped to the seam's vocabulary.
fn sc_error(call: &'static str) -> PlatformError {
    // SAFETY: `SCError` takes no arguments, touches no memory this code owns and
    // returns a plain `int`.
    let code = unsafe { SCError() };
    oserr::from_sc_error(i64::from(code), call, Context::Resolver)
}

/// A `CFString` for `text`.
fn cf_string(text: &str) -> Result<CfOwned, PlatformError> {
    // The length is checked before the pointer is handed over. A `CFIndex` is
    // signed, and a string long enough to wrap it would make CF read a negative
    // count — `ownership.md` §6 rule 9's discipline applied to an FFI length.
    let Ok(length) = core_foundation_sys::base::CFIndex::try_from(text.len()) else {
        return Err(oserr::unavailable(
            "CFStringCreateWithBytes",
            libc::EOVERFLOW,
        ));
    };
    // SAFETY: `text.as_ptr()` is valid for `text.len()` bytes for the duration of
    // the call, which is all `CFStringCreateWithBytes` reads; it copies. The
    // length is the slice's own, so it cannot over-read. `false` says the bytes
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

/// A `CFArray` of `CFString`.
fn cf_string_array(items: &[String]) -> Result<CfOwned, PlatformError> {
    // SAFETY: a zero capacity means "unbounded"; `kCFTypeArrayCallBacks` is a
    // static CF provides and is valid for the process's lifetime.
    let array =
        unsafe { CFArrayCreateMutable(kCFAllocatorDefault, 0, &raw const kCFTypeArrayCallBacks) };
    let owned = CfOwned::new(array.as_void_ptr(), "CFArrayCreateMutable")?;
    for item in items {
        let value = cf_string(item)?;
        // SAFETY: `array` is the mutable array just created and still owned;
        // `value` is a live `CFString`. `CFArrayAppendValue` retains it under
        // `kCFTypeArrayCallBacks`, so `value`'s own release on drop is correct.
        unsafe { CFArrayAppendValue(array, value.as_ptr()) };
    }
    Ok(owned)
}

/// A `CFArray` of `CFNumber`.
fn cf_number_array(items: &[i32]) -> Result<CfOwned, PlatformError> {
    // SAFETY: as above.
    let array =
        unsafe { CFArrayCreateMutable(kCFAllocatorDefault, 0, &raw const kCFTypeArrayCallBacks) };
    let owned = CfOwned::new(array.as_void_ptr(), "CFArrayCreateMutable")?;
    for item in items {
        // SAFETY: `item` is a live `i32` and `kCFNumberSInt32Type` declares
        // exactly that width, so `CFNumberCreate` reads four bytes it may read.
        let number = unsafe {
            CFNumberCreate(
                kCFAllocatorDefault,
                kCFNumberSInt32Type,
                std::ptr::from_ref(item).cast(),
            )
        };
        let number = CfOwned::new(number.as_void_ptr(), "CFNumberCreate")?;
        // SAFETY: as for the string array.
        unsafe { CFArrayAppendValue(array, number.as_ptr()) };
    }
    Ok(owned)
}

/// The dictionary for one [`crate::resolver::ScEntry`].
fn cf_dictionary(
    entries: &std::collections::BTreeMap<String, ScValue>,
) -> Result<CfOwned, PlatformError> {
    // SAFETY: zero capacity is "unbounded"; both callback statics are CF's own and
    // live for the process.
    let dictionary = unsafe {
        CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            0,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    let owned = CfOwned::new(dictionary.as_void_ptr(), "CFDictionaryCreateMutable")?;
    for (key, value) in entries {
        let cf_key = cf_string(key)?;
        let cf_value = match value {
            ScValue::Text(text) => cf_string(text)?,
            ScValue::Strings(items) => cf_string_array(items)?,
            ScValue::Numbers(items) => cf_number_array(items)?,
        };
        // SAFETY: `dictionary` is the mutable dictionary just created and still
        // owned; both key and value are live CF objects. The type callbacks retain
        // them, so the local releases on drop are correct.
        unsafe { CFDictionarySetValue(dictionary, cf_key.as_ptr(), cf_value.as_ptr()) };
    }
    Ok(owned)
}

/// Reads a `CFString` back as a Rust `String`.
fn read_cf_string(reference: CFStringRef) -> Option<String> {
    if reference.is_null() {
        return None;
    }
    let mut buffer = [0 as libc::c_char; 512];
    let Ok(capacity) = core_foundation_sys::base::CFIndex::try_from(buffer.len()) else {
        return None;
    };
    // SAFETY: `reference` is a live `CFString` borrowed from a dictionary we hold;
    // `buffer` is a live 512-byte array we own and its length is passed truthfully,
    // so `CFStringGetCString` cannot write past it. It NUL-terminates on success.
    let ok = unsafe {
        CFStringGetCString(
            reference,
            buffer.as_mut_ptr(),
            capacity,
            kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
        .collect();
    String::from_utf8(bytes).ok()
}

/// Reads a `CFArray` of `CFString` back as a `Vec<String>`.
fn read_cf_string_array(array: CFArrayRef) -> Vec<String> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: `array` is a live `CFArray` borrowed from a dictionary we hold.
    let count = unsafe { CFArrayGetCount(array) };
    let mut out = Vec::new();
    for index in 0..count {
        // SAFETY: `index` is in `0..count`, which is the array's own reported
        // length, so `CFArrayGetValueAtIndex` is in bounds. The result is a
        // BORROW — the Get Rule — and is not released here.
        let item = unsafe { CFArrayGetValueAtIndex(array, index) };
        if item.is_null() {
            continue;
        }
        // SAFETY: the element is a live CF object; `CFGetTypeID` reads only its
        // header. The type is checked before it is treated as a `CFString`,
        // because `configd`'s dictionaries are not schema-enforced and a
        // non-string here would otherwise be read as one.
        let is_string = unsafe { CFGetTypeID(item) == CFStringGetTypeID() };
        if !is_string {
            continue;
        }
        if let Some(text) = read_cf_string(item.cast()) {
            out.push(text);
        }
    }
    out
}

/// The `SCDynamicStore` resolver engine.
#[derive(Debug)]
pub struct DynamicStoreEngine {
    restore_point_path: std::path::PathBuf,
}

impl DynamicStoreEngine {
    /// Binds the engine. The restore-point path is **injected, never discovered**
    /// (CD-2).
    #[must_use]
    pub fn new(restore_point_path: std::path::PathBuf) -> Self {
        Self { restore_point_path }
    }

    /// Opens a session.
    ///
    /// A session per operation rather than one held open: `configd` restarts, and
    /// a cached `SCDynamicStoreRef` across a restart is a handle that silently
    /// stops working. The cost is one Mach round trip per programme, which happens
    /// once per contract generation.
    #[allow(clippy::unused_self)]
    fn session(&self) -> Result<(CfOwned, SCDynamicStoreRef), PlatformError> {
        // The session name `configd` shows in `scutil`. Deliberately the
        // PRODUCT's and not a component's: `ownership.md` §9.6 X-7 moved the
        // authority out of the `twinvpnd` daemon and into the NE system
        // extension, and a name that tracked whichever component happened to
        // hold the store would make an operator's `scutil` output disagree with
        // the process list after a topology change.
        let name = cf_string("net.twinvpn.agent")?;
        // SAFETY: `name` is a live `CFString`; the two null pointers are the
        // documented "no callback, no context" form, which is correct for a
        // session used only for get/set/remove.
        let store = unsafe {
            SCDynamicStoreCreate(
                kCFAllocatorDefault,
                name.as_ptr().cast(),
                None,
                std::ptr::null_mut(),
            )
        };
        let owned = CfOwned::new(store.cast(), "SCDynamicStoreCreate")?;
        Ok((owned, store))
    }
}

impl crate::netcfg::ResolverEngine for DynamicStoreEngine {
    fn capture(&self, service_id: &str) -> Result<RestorePoint, PlatformError> {
        let (_session, store) = self.session()?;
        let key = cf_string(&dns_key(service_id))?;
        // SAFETY: `store` is the live session held by `_session`; `key` is a live
        // `CFString`. `SCDynamicStoreCopyValue` follows the Copy Rule, so the
        // result is owned and released by `CfOwned` below.
        let value = unsafe { SCDynamicStoreCopyValue(store, key.as_ptr().cast()) };
        if value.is_null() {
            // Absent is not an error. A service with no DNS dictionary is restored
            // by REMOVING ours, not by writing an empty one.
            return Ok(RestorePoint::absent(service_id));
        }
        let owned = CfOwned::new(value, "SCDynamicStoreCopyValue")?;
        // SAFETY: `owned` holds a live CF object; `CFGetTypeID` reads its header.
        let is_dictionary = unsafe { CFGetTypeID(owned.as_ptr()) == CFDictionaryGetTypeID() };
        if !is_dictionary {
            return Ok(RestorePoint::absent(service_id));
        }
        let dictionary: CFDictionaryRef = owned.as_ptr().cast();
        let servers_key = cf_string("ServerAddresses")?;
        let search_key = cf_string("SearchDomains")?;
        // SAFETY: `dictionary` is the live dictionary held by `owned`; both keys
        // are live `CFString`s. `CFDictionaryGetValue` follows the Get Rule, so
        // the results are BORROWS and are not released.
        let servers = unsafe { CFDictionaryGetValue(dictionary, servers_key.as_ptr()) };
        let search = unsafe { CFDictionaryGetValue(dictionary, search_key.as_ptr()) };
        Ok(RestorePoint {
            service_id: service_id.to_owned(),
            servers: read_cf_string_array(servers.cast()),
            search_domains: read_cf_string_array(search.cast()),
            existed: true,
        })
    }

    fn persist(&self, point: &RestorePoint) -> Result<(), PlatformError> {
        // Written before anything is mutated (DN-18), and to a file rather than to
        // memory (PS-6): a restore point held in a process that may be SIGKILLed
        // is not a restore point.
        if let Some(parent) = self.restore_point_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| oserr::from_errno(&e, "mkdir(restore)", Context::Resolver))?;
        }
        std::fs::write(&self.restore_point_path, point.encode())
            .map_err(|e| oserr::from_errno(&e, "write(restore)", Context::Resolver))
    }

    fn apply(&self, plan: &ResolverPlan) -> Result<(), PlatformError> {
        let (_session, store) = self.session()?;
        for entry in &plan.sets {
            let key = cf_string(&entry.key)?;
            let dictionary = cf_dictionary(&entry.dictionary)?;
            // SAFETY: `store` is the live session; `key` and `dictionary` are live
            // CF objects. `SCDynamicStoreSetValue` copies into `configd` and takes
            // no ownership of either.
            let ok =
                unsafe { SCDynamicStoreSetValue(store, key.as_ptr().cast(), dictionary.as_ptr()) };
            if ok == 0 {
                return Err(sc_error("SCDynamicStoreSetValue"));
            }
        }
        for key_text in &plan.removes {
            let key = cf_string(key_text)?;
            // SAFETY: as above.
            let ok = unsafe { SCDynamicStoreRemoveValue(store, key.as_ptr().cast()) };
            if ok == 0 {
                // A key that was already absent reports `kSCStatusNoKey`, which is
                // the state the caller wanted. Every other failure is real.
                let error = sc_error("SCDynamicStoreRemoveValue");
                if error.os_detail().map(|d| d.code) != Some(crate::oserr::sc::NO_KEY) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}
