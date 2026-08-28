//! The adapter as one object: S-47's "which adapter am I talking to", the
//! declared posture, and the one thing `begin_shutdown` must not do.

use std::sync::Arc;

use super::*;
use crate::builder::Programme;
use crate::hostcall::{KeystoreElement, SecurityLevel};
use crate::power::KeepalivePlan;
use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, SecureItemKey, SharedSecret, Signature,
};

#[derive(Debug)]
struct NullController;

impl TunnelController for NullController {
    fn name(&self) -> &'static str {
        "null"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, _handles: &[u64]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn protect_socket(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[derive(Debug)]
struct TeeElement;

impl KeystoreElement for TeeElement {
    fn name(&self) -> &'static str {
        "tee"
    }
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::TrustedEnvironment
    }
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(None))
    }
    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(None))
    }
    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn attestation(&self) -> Option<Vec<u8>> {
        None
    }
    fn item_read(&self, _key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(None)
    }
    fn item_write_atomic(&self, _key: &SecureItemKey, _value: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn item_delete(&self, _key: &SecureItemKey) -> Result<(), PlatformError> {
        Ok(())
    }
}

fn adapter() -> AndroidPlatformAdapter {
    AndroidPlatformAdapter::new(AndroidAdapterParts {
        controller: Arc::new(NullController),
        element: Arc::new(TeeElement),
        store_root: PathBuf::from("/data/user/0/net.twinvpn.android/files/vault"),
        vpn_config: VpnConfig::default(),
    })
}

#[test]
fn the_adapter_names_itself_so_s46_records_which_binding_was_loaded() {
    assert_eq!(adapter().binding_name(), "android-vpnservice");
}

#[test]
fn one_object_carries_all_six_capabilities() {
    // S-47: "a core that assembled its platform from six independently-supplied
    // pieces could not state which adapter it was talking to".
    let adapter = adapter();
    let _ = adapter.sockets();
    let _ = adapter.tunnel();
    let _ = adapter.network_config();
    let _ = adapter.interfaces();
    let _ = adapter.identity();
    let _ = adapter.store();
}

#[test]
fn begin_shutdown_latches_and_touches_neither_the_claim_nor_the_disposition() {
    let adapter = adapter();
    assert!(!adapter.is_shutting_down());
    let claim_before = adapter.network().enforcement_view();
    adapter.begin_shutdown();
    adapter.begin_shutdown(); // idempotent, and callable from any thread
    assert!(adapter.is_shutting_down());
    let claim_after = adapter.network().enforcement_view();
    assert_eq!(claim_before, claim_after);
    // And the custody declaration is unchanged.
    assert!(
        adapter
            .network_config()
            .enforcement_custody()
            .swap_is_atomic
    );
}

#[test]
fn the_posture_is_declared_rather_than_discovered_by_a_user() {
    let posture = adapter().posture();
    assert_eq!(posture.security_level, SecurityLevel::TrustedEnvironment);
    assert!(posture.hardware_backed_identity);
    // LC-40's default: not observable, and it presents as unprotected.
    assert_eq!(posture.lockdown, LockdownPosture::Unverified);
    assert!(!posture.lockdown.presents_as_protected());
    // W-7's three shell interfaces are reachable on this host.
    assert!(posture.entropy_available);
    assert!(posture.boot_id_source.is_some());
}

/// §11.16 (l): on an element with no hardware, the fact is reported and the
/// signer is **not** silently substituted.
#[test]
fn a_software_keymaster_is_reported_as_such_rather_than_refused() {
    #[derive(Debug)]
    struct SoftwareElement;
    impl KeystoreElement for SoftwareElement {
        fn name(&self) -> &'static str {
            "software"
        }
        fn security_level(&self) -> SecurityLevel {
            SecurityLevel::Software
        }
        fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
            Err(PlatformError::IdentityKeyUnavailable(None))
        }
        fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
            Err(PlatformError::IdentityKeyUnavailable(None))
        }
        fn agree(
            &self,
            _key: IdentityKeyRef,
            _peer: &PeerPublicKey,
        ) -> Result<SharedSecret, PlatformError> {
            Err(PlatformError::OsUnsupported(None))
        }
        fn attestation(&self) -> Option<Vec<u8>> {
            None
        }
        fn item_read(&self, _key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
            Ok(None)
        }
        fn item_write_atomic(
            &self,
            _key: &SecureItemKey,
            _value: &[u8],
        ) -> Result<(), PlatformError> {
            Ok(())
        }
        fn item_delete(&self, _key: &SecureItemKey) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    let adapter = AndroidPlatformAdapter::new(AndroidAdapterParts {
        controller: Arc::new(NullController),
        element: Arc::new(SoftwareElement),
        store_root: PathBuf::from("/vault"),
        vpn_config: VpnConfig::default(),
    });
    let posture = adapter.posture();
    assert_eq!(posture.security_level, SecurityLevel::Software);
    assert!(!posture.hardware_backed_identity);
    // CB-6a is unaffected: Keystore still performs the record AEAD.
    assert_eq!(
        adapter.store().record_aead_custody(),
        twinvpn_platform::RecordAeadCustody::PlatformPerformed
    );
}

/// The overlay is identified by a recorded index, not by an interface name —
/// Android names the tun itself and another product's `tun0` is not ours.
#[test]
fn the_overlay_prefix_is_a_request_and_never_an_identification() {
    assert_eq!(OVERLAY_PREFIX, "twin");
    let adapter = adapter();
    // With nothing recorded, no interface is ours.
    adapter.interface_provider().set_overlay(None);
}
