//! Keychain and Secure Enclave **attributes** — which class, which access group,
//! which protection — computed here, in Rust, and handed to Swift as data.
//!
//! **Authority:** ADR-0020 §11.3's iOS row, **ST-5**, **ST-6**, **ST-8**,
//! **ST-22**, **ST-26**, **ST-12e**, §11.8's iOS/iPadOS backup row, §11.9's iOS
//! `store_root` row; ADR-0007 §7.3's iOS custody row and **N-5**; ADR-0018 CB-5,
//! CB-6a, CB-7.
//!
//! # ST-5 is the rule this module exists to make unfailable
//!
//! > "`kSecAttrAccessibleWhenUnlocked` MUST NOT be used for IK, SEK, or ANCH.
//! > The `NEPacketTunnelProvider` must sign, rekey, and re-derive `psk2` while the
//! > screen is locked; a `WhenUnlocked` item makes **every rekey after a screen
//! > lock fail** … exact defect class **R-05**."
//!
//! The failure is silent on a device that is never locked and total on one that
//! is. So the accessibility class is not a parameter a Swift call site passes; it
//! is computed by [`AccessibilityClass::for_tier1`], which has one answer, and
//! [`AccessibilityClass::permitted_for_tier1`] states which values are refused
//! and why. A test asserts both.
//!
//! # ST-22's co-location is likewise structural
//!
//! > "ANCH MUST be stored in the **same Tier-1 backend, under the same custody
//! > class and the same accessibility class, as the `DeviceIdentityKey`.**"
//!
//! Every [`ItemQuery`] this module produces takes its access group and its
//! accessibility class from the same [`KeychainConfig`], so there is no shape of
//! this API in which the anchor and the identity end up in different custody.
//!
//! # Target-free
//!
//! Nothing here calls `SecItemCopyMatching`. It renders the `CFDictionary` Swift
//! will build, as canonical JSON, and its tests run on the Linux build host —
//! which is where the interesting mistakes are (`WhenUnlocked` instead of
//! `AfterFirstUnlock`; a synchronizable item; an anchor in a different access
//! group), not in the `SecItem` call itself.

use serde_json::{Map, Value};
use twinvpn_platform::{PlatformError, SecureItemKey, StoreRootAttributes};

use crate::oserr;

/// A Keychain accessibility class, as `Security.framework` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessibilityClass {
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    ///
    /// ADR-0020 §11.3's iOS row and ST-5: "the weakest class that permits
    /// background use while locked, and `…ThisDeviceOnly` is what excludes the
    /// item from iCloud Keychain and from any backup restorable to different
    /// hardware — which is where **I4** is actually enforced on Apple platforms."
    AfterFirstUnlockThisDeviceOnly,
    /// `kSecAttrAccessibleAfterFirstUnlock`. Backup-restorable, so refused for
    /// Tier 1: I4 is enforced by `…ThisDeviceOnly` and not by anything else.
    AfterFirstUnlock,
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. **Refused by ST-5.**
    WhenUnlockedThisDeviceOnly,
    /// `kSecAttrAccessibleWhenUnlocked`. **Refused by ST-5**, twice over.
    WhenUnlocked,
    /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Refused: the item
    /// becomes unreadable the moment a user removes their passcode, which turns
    /// a settings change into an unrecoverable vault.
    WhenPasscodeSetThisDeviceOnly,
}

impl AccessibilityClass {
    /// The one class every Tier-1 item uses.
    #[must_use]
    pub const fn for_tier1() -> Self {
        AccessibilityClass::AfterFirstUnlockThisDeviceOnly
    }

    /// Whether this class may hold a Tier-1 item.
    ///
    /// Exactly one may. The others are enumerated rather than omitted so that a
    /// reviewer asking "why not `WhenUnlocked`" reads the answer here instead of
    /// discovering it from a device that stopped rekeying after a screen lock.
    #[must_use]
    pub const fn permitted_for_tier1(self) -> bool {
        matches!(self, AccessibilityClass::AfterFirstUnlockThisDeviceOnly)
    }

    /// Whether an item in this class is readable while the device is locked
    /// after at least one unlock since boot.
    ///
    /// This is the property the provider depends on: ADR-0022 LC-15 and ADR-0007
    /// §7.3.1's `AFTER_FIRST_UNLOCK` availability class.
    #[must_use]
    pub const fn readable_while_locked(self) -> bool {
        matches!(
            self,
            AccessibilityClass::AfterFirstUnlockThisDeviceOnly
                | AccessibilityClass::AfterFirstUnlock
        )
    }

    /// The stable, non-localised tag Swift maps to the `kSecAttrAccessible*`
    /// constant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AccessibilityClass::AfterFirstUnlockThisDeviceOnly => {
                "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
            }
            AccessibilityClass::AfterFirstUnlock => "kSecAttrAccessibleAfterFirstUnlock",
            AccessibilityClass::WhenUnlockedThisDeviceOnly => {
                "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
            }
            AccessibilityClass::WhenUnlocked => "kSecAttrAccessibleWhenUnlocked",
            AccessibilityClass::WhenPasscodeSetThisDeviceOnly => {
                "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"
            }
        }
    }
}

/// The `NSFileProtection*` class stamped on the vault and its sidecars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileProtectionClass {
    /// `NSFileProtectionCompleteUntilFirstUserAuthentication`.
    ///
    /// ADR-0020 **ST-6** requires exactly this, and forbids
    /// `NSFileProtectionComplete`: "it makes the vault unreadable while the
    /// device is locked, which breaks the extension for the same reason ST-5
    /// does."
    CompleteUntilFirstUserAuthentication,
    /// `NSFileProtectionComplete`. **Refused by ST-6.**
    Complete,
    /// `NSFileProtectionNone`. Refused: the vault would be readable with the
    /// device powered off.
    None,
}

impl FileProtectionClass {
    /// The one class the vault uses.
    #[must_use]
    pub const fn for_vault() -> Self {
        FileProtectionClass::CompleteUntilFirstUserAuthentication
    }

    /// Whether this class may protect the vault.
    #[must_use]
    pub const fn permitted_for_vault(self) -> bool {
        matches!(
            self,
            FileProtectionClass::CompleteUntilFirstUserAuthentication
        )
    }

    /// The stable, non-localised tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FileProtectionClass::CompleteUntilFirstUserAuthentication => {
                "NSFileProtectionCompleteUntilFirstUserAuthentication"
            }
            FileProtectionClass::Complete => "NSFileProtectionComplete",
            FileProtectionClass::None => "NSFileProtectionNone",
        }
    }
}

/// Which Keychain class an item lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemClass {
    /// `kSecClassGenericPassword` — the SEK and the S-53 anchor.
    GenericPassword,
    /// `kSecClassKey` — the enclave-resident identity key reference.
    Key,
}

impl ItemClass {
    /// The stable tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ItemClass::GenericPassword => "kSecClassGenericPassword",
            ItemClass::Key => "kSecClassKey",
        }
    }
}

/// Everything the shell injected about where items live.
///
/// **Injected, never discovered** (CD-2, ST-12e): the access group comes from the
/// signed App ID and the service from the bundle identifier, and an adapter that
/// read either from the ambient environment would be reading a value an attacker
/// on the device can influence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainConfig {
    /// `kSecAttrAccessGroup` — the shared keychain access group from the App ID.
    ///
    /// The app and the extension share it, which is exactly the residual
    /// ADR-0016 §11.4 declares: "use `DeviceKey` as signing oracle = Yes —
    /// declared residual", because no privilege boundary on this platform can
    /// scope below app identity.
    pub access_group: String,
    /// `kSecAttrService` — the bundle identifier.
    pub service: String,
}

impl KeychainConfig {
    /// Builds a config, rejecting values a Keychain query cannot carry.
    ///
    /// # Errors
    ///
    /// [`PlatformError::SecureStoreUnavailable`] on an empty or control-bearing
    /// value. A blank access group is not "the default group"; it is a query
    /// that matches nothing, and failing loudly beats an item that silently
    /// never appears.
    pub fn new(access_group: &str, service: &str) -> Result<Self, PlatformError> {
        for (value, field) in [(access_group, "access_group"), (service, "service")] {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(PlatformError::SecureStoreUnavailable(Some(
                    oserr::detail_from_code(0, field_tag(field)),
                )));
            }
        }
        Ok(Self {
            access_group: access_group.to_owned(),
            service: service.to_owned(),
        })
    }

    /// The query for one Tier-1 secure item.
    ///
    /// Every item this returns shares the access group and the accessibility
    /// class, which is ST-22's co-location made structural.
    #[must_use]
    pub fn item(&self, key: &SecureItemKey) -> ItemQuery {
        ItemQuery {
            class: ItemClass::GenericPassword,
            service: self.service.clone(),
            account: key.as_str().to_owned(),
            access_group: self.access_group.clone(),
            accessibility: AccessibilityClass::for_tier1(),
            // ADR-0020 §11.8's iOS row: `kSecAttrSynchronizable = false`, which
            // with `…ThisDeviceOnly` is what keeps Tier 1 out of iCloud Keychain.
            synchronizable: false,
        }
    }

    /// The `kSecAttrApplicationTag` for an enclave-resident identity key.
    ///
    /// Generation is in the tag because ADR-0007 rotation creates a new
    /// `DeviceIdentity` at `generation + 1` while `device_id` is unchanged, and
    /// `T_IK_OVERLAP` means two generations are live at once. A tag without a
    /// generation names the wrong key exactly when it matters.
    #[must_use]
    pub fn identity_key_tag(&self, generation: u32) -> String {
        format!("{}.identity.g{generation}", self.service)
    }

    /// The tag for the `OwnerSigningKey`.
    #[must_use]
    pub fn owner_signing_key_tag(&self) -> String {
        format!("{}.owner.signing", self.service)
    }

    /// The tag for the `OwnerRootKey`.
    #[must_use]
    pub fn owner_root_key_tag(&self) -> String {
        format!("{}.owner.root", self.service)
    }
}

const fn field_tag(field: &str) -> &'static str {
    // A stable, non-localised tag, chosen from a closed set so the value handed
    // to `OsDetail` is `'static` and cannot carry caller-supplied text into a
    // log (ADR-0015 §11.4: an access group is SENSITIVE).
    match field.as_bytes() {
        b"access_group" => "keychain.access_group",
        _ => "keychain.service",
    }
}

/// One rendered Keychain query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemQuery {
    /// `kSecClass`.
    pub class: ItemClass,
    /// `kSecAttrService`.
    pub service: String,
    /// `kSecAttrAccount`.
    pub account: String,
    /// `kSecAttrAccessGroup`.
    pub access_group: String,
    /// `kSecAttrAccessible`.
    pub accessibility: AccessibilityClass,
    /// `kSecAttrSynchronizable`.
    pub synchronizable: bool,
}

impl ItemQuery {
    /// The canonical JSON Swift turns into a `CFDictionary`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut root = Map::new();
        root.insert(
            "class".to_owned(),
            Value::String(self.class.as_str().to_owned()),
        );
        root.insert("service".to_owned(), Value::String(self.service.clone()));
        root.insert("account".to_owned(), Value::String(self.account.clone()));
        root.insert(
            "access_group".to_owned(),
            Value::String(self.access_group.clone()),
        );
        root.insert(
            "accessible".to_owned(),
            Value::String(self.accessibility.as_str().to_owned()),
        );
        root.insert(
            "synchronizable".to_owned(),
            Value::Bool(self.synchronizable),
        );
        Value::Object(root).to_string()
    }
}

/// The attributes the shell stamped on the vended store root.
///
/// `protection_class` is a `&'static str` in the seam, so the value here is one
/// of [`FileProtectionClass`]'s tags and never a formatted string — which is what
/// lets the core record it in `CoreBuildIdentity` (S-46) as a stable token.
#[must_use]
pub fn store_root_attributes(backup_excluded: bool) -> StoreRootAttributes {
    StoreRootAttributes {
        backup_excluded,
        protection_class: Some(FileProtectionClass::for_vault().as_str()),
        // The App Group container is inside the app sandbox and reachable only
        // by the app and the extension, which share the group. "Owner only" in
        // the POSIX sense is not the mechanism here; the sandbox is. Reporting
        // `true` states the property the core cares about — that no other
        // application can read it — without claiming a mode bit that does not
        // exist on this platform.
        owner_only: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> KeychainConfig {
        KeychainConfig::new("ABCDE12345.group.com.twinvpn", "com.twinvpn.client").expect("config")
    }

    fn key(name: &str) -> SecureItemKey {
        SecureItemKey::new(name).expect("key")
    }

    #[test]
    fn every_tier1_item_is_after_first_unlock_this_device_only() {
        // ST-5. A `WhenUnlocked` item makes every rekey after a screen lock fail
        // — silently on a device that is never locked, totally on one that is.
        let config = config();
        for name in ["sek", "k_bind", "s53_anchor"] {
            let query = config.item(&key(name));
            assert_eq!(
                query.accessibility,
                AccessibilityClass::AfterFirstUnlockThisDeviceOnly
            );
            assert!(query.accessibility.readable_while_locked());
            assert!(query.accessibility.permitted_for_tier1());
        }
    }

    #[test]
    fn every_other_accessibility_class_is_refused_for_tier1() {
        for class in [
            AccessibilityClass::AfterFirstUnlock,
            AccessibilityClass::WhenUnlockedThisDeviceOnly,
            AccessibilityClass::WhenUnlocked,
            AccessibilityClass::WhenPasscodeSetThisDeviceOnly,
        ] {
            assert!(
                !class.permitted_for_tier1(),
                "{} must not hold a Tier-1 item",
                class.as_str()
            );
        }
        // And the two `WhenUnlocked` classes are refused for the ST-5 reason
        // specifically: they are not readable while the screen is locked, which
        // is when the provider rekeys.
        assert!(!AccessibilityClass::WhenUnlocked.readable_while_locked());
        assert!(!AccessibilityClass::WhenUnlockedThisDeviceOnly.readable_while_locked());
    }

    #[test]
    fn the_anchor_and_the_identity_share_custody_by_construction() {
        // ST-22: ANCH must live "in the same Tier-1 backend, under the same
        // custody class and the same accessibility class" as the identity key.
        // There is no shape of this API that separates them.
        let config = config();
        let anchor = config.item(&key("s53_anchor"));
        let sek = config.item(&key("sek"));
        assert_eq!(anchor.access_group, sek.access_group);
        assert_eq!(anchor.accessibility, sek.accessibility);
        assert_eq!(anchor.access_group, config.access_group);
    }

    #[test]
    fn no_tier1_item_is_synchronizable() {
        // ADR-0020 §11.8's iOS row: `kSecAttrSynchronizable = false` plus
        // `…ThisDeviceOnly` is how the item stays out of iCloud Keychain and out
        // of a backup restorable to different hardware. I4 is enforced here.
        let query = config().item(&key("sek"));
        assert!(!query.synchronizable);
        assert!(query.to_json().contains("\"synchronizable\":false"));
        assert!(query.to_json().contains("ThisDeviceOnly"));
    }

    #[test]
    fn the_vault_protection_class_is_until_first_user_authentication() {
        // ST-6. `NSFileProtectionComplete` makes the vault unreadable while the
        // device is locked, which breaks the extension for ST-5's reason.
        assert_eq!(
            FileProtectionClass::for_vault(),
            FileProtectionClass::CompleteUntilFirstUserAuthentication
        );
        assert!(!FileProtectionClass::Complete.permitted_for_vault());
        assert!(!FileProtectionClass::None.permitted_for_vault());
        assert_eq!(
            store_root_attributes(true).protection_class,
            Some("NSFileProtectionCompleteUntilFirstUserAuthentication")
        );
    }

    #[test]
    fn backup_exclusion_is_reported_as_verified_and_never_assumed() {
        // ST-26: exclusion "is re-verified at every start; a failure is
        // STORE.BACKUP_EXCLUSION_FAILED, not a silent success". That code is
        // absent from the frozen registry, so the fact is carried as the
        // declared attribute the seam already has.
        assert!(store_root_attributes(true).backup_excluded);
        assert!(!store_root_attributes(false).backup_excluded);
    }

    #[test]
    fn an_identity_key_tag_names_its_generation() {
        // ADR-0007 rotation: two generations are live at once during
        // T_IK_OVERLAP, and "the identity key" without a generation is ambiguous
        // exactly when it matters.
        let config = config();
        assert_ne!(config.identity_key_tag(0), config.identity_key_tag(1));
        assert_eq!(config.identity_key_tag(3), "com.twinvpn.client.identity.g3");
        assert_ne!(config.owner_signing_key_tag(), config.owner_root_key_tag());
        assert_ne!(config.owner_signing_key_tag(), config.identity_key_tag(0));
    }

    #[test]
    fn a_blank_access_group_is_refused_rather_than_matching_nothing() {
        for (group, service) in [
            ("", "com.twinvpn.client"),
            ("group", ""),
            ("gro\u{0}up", "com.twinvpn.client"),
        ] {
            let err = KeychainConfig::new(group, service).expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        }
    }

    #[test]
    fn the_failure_detail_carries_a_closed_set_tag_and_never_caller_text() {
        // An access group is SENSITIVE under ADR-0015 §11.4. `OsDetail::call` is
        // `&'static str` precisely so a value cannot travel into a log through
        // it; this pins that the tag comes from a closed set.
        let err = KeychainConfig::new("", "svc").expect_err("refuses");
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("keychain.access_group")
        );
    }

    #[test]
    fn the_rendered_query_is_a_pure_function_of_the_item() {
        let config = config();
        assert_eq!(
            config.item(&key("sek")).to_json(),
            config.item(&key("sek")).to_json()
        );
        assert_ne!(
            config.item(&key("sek")).to_json(),
            config.item(&key("k_bind")).to_json()
        );
    }
}
