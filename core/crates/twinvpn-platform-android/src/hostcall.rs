//! The two traits the JNI layer implements — and the **only** two places this
//! crate reaches into the JVM.
//!
//! **Authority:** ADR-0018 CB-1, CB-2, CB-5, CB-7, §11.5's Android rows;
//! `docs/implementation/ownership.md` §10.4 (the wave-3 bridge ruling), §10.2;
//! ADR-0012 KS-9(1); ADR-0020 §11's Android rows.
//!
//! # Why two traits and not thirty `extern "C"` entry points
//!
//! `ownership.md` §10.4 rules that the capabilities `twinvpn.h`'s F-9 vtable
//! lacks — sockets, the NAT ladder, interface enumeration, ruleset read-back,
//! `current_generation` — stay **in Rust, in-process**, and that Swift and
//! Kotlin *marshal, they do not decide*. Concentrating every JVM call behind
//! these two traits is how that is made checkable:
//!
//! - every method takes and returns **bytes, handles, and platform-typed
//!   values**. No method takes or returns a `ConnectionState`, a `ReasonCode`
//!   class, a policy verdict, or a candidate priority — §10.4's own list of what
//!   would be a CB-2 violation on the wrong side of the line;
//! - both traits are implementable **without a JVM**, which is what lets the
//!   `NetworkConfig`, `TunnelDevice`, `SecureStore` and `IdentityCustody`
//!   implementations above them be exercised by `make test` on this Linux host;
//! - a reviewer asking *what does this adapter ask Android to do* reads two
//!   trait definitions rather than grepping for `jni`.
//!
//! # `protect_socket` is not optional, and Android is not iOS
//!
//! ADR-0012 KS-9(1) says of the bootstrap exception's first clause:
//! *"iOS/Android — implicit, the provider's own sockets are excluded from its
//! own tunnel by construction."* **That is true on iOS and false on Android.**
//! An Android `VpnService` claiming `0.0.0.0/0` captures its *own* process's
//! sockets like any other app's; the exclusion is an explicit
//! `VpnService.protect(int)` call per file descriptor, and a socket that misses
//! it routes its packets into the tunnel it is trying to carry — an immediate
//! loop, and with the tunnel down, an immediate loss of the bootstrap path that
//! `BLOCKED` needs to recover from.
//!
//! So [`TunnelController::protect_socket`] is on the critical path of KS-9 on
//! this platform, and [`crate::sock`] calls it for **every** socket it opens,
//! before the socket is ever used. Reported as a finding: KS-9(1)'s Android
//! clause understates what the platform requires.

use std::fmt::Debug;

use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, PlatformError, SecureItemKey, SharedSecret,
    Signature,
};

use crate::builder::Programme;
use crate::power::KeepalivePlan;

/// A raw file descriptor, as both bionic and glibc understand it.
///
/// Spelled out rather than taken from `std::os::fd` so the type is the same on
/// the host build and the Android build without a `cfg`.
pub type RawFd = i32;

/// The `VpnService`-side operations, as the JNI layer implements them.
///
/// Every method is a **mechanism**. What to claim is [`crate::builder`]'s;
/// when to claim it is the core's.
pub trait TunnelController: Send + Sync + Debug {
    /// A stable, non-localised name for this controller, e.g. `"vpnservice"`.
    ///
    /// Recorded in `CoreBuildIdentity` (S-46) alongside the binding name so a
    /// support case can tell a device from a test harness.
    fn name(&self) -> &'static str;

    /// Walks `programme` on a fresh `VpnService.Builder` and calls
    /// `establish()`, returning the detached tun descriptor.
    ///
    /// **PB-1: one JNI call at setup, then direct reads.** The descriptor is
    /// detached from its `ParcelFileDescriptor` and owned by this crate
    /// thereafter, so the datapath crosses no language boundary per packet.
    ///
    /// # Errors
    ///
    /// [`PlatformError::VpnPermissionDenied`] where consent is absent or another
    /// app holds the platform's single VPN slot;
    /// [`PlatformError::RouteProgrammingDenied`] where the builder refused an
    /// operation.
    fn establish(&self, programme: &Programme) -> Result<RawFd, PlatformError>;

    /// Closes the tun descriptor. **Idempotent; safe after a crash.**
    fn close_tun(&self, fd: RawFd) -> Result<(), PlatformError>;

    /// `VpnService.setUnderlyingNetworks(Network[])`.
    ///
    /// `handles` are `Network.getNetworkHandle()` values, in preference order;
    /// an empty slice means "the system default", which is what
    /// `setUnderlyingNetworks(null)` expresses.
    ///
    /// `docs/networking.md` §5.4's Android roaming row requires this to be
    /// **kept current** across Wi-Fi/cellular handoff, "so the system accounts
    /// and routes correctly". It is a marshalling call: which networks underlie
    /// the tunnel is a fact the core already knows.
    fn set_underlying_networks(&self, handles: &[u64]) -> Result<(), PlatformError>;

    /// `VpnService.protect(int)` — excludes `fd` from our own tunnel.
    ///
    /// See the module documentation. Not optional on Android.
    fn protect_socket(&self, fd: RawFd) -> Result<(), PlatformError>;

    /// Requests a kernel-side `SocketKeepalive` on `fd`.
    ///
    /// A [`KeepalivePlan::Unavailable`] plan is a no-op that returns `Ok`: the
    /// core has already been told the platform cannot serve the interval, and
    /// failing here as well would report one condition twice.
    ///
    /// # Errors
    ///
    /// [`PlatformError::OsUnsupported`] where the platform refused the request
    /// it had declared it could serve.
    fn request_keepalive(&self, fd: RawFd, plan: KeepalivePlan) -> Result<(), PlatformError>;
}

/// Which Keystore `SecurityLevel` backs a key.
///
/// ADR-0020 §11's Android row: `setIsStrongBoxBacked(true)` where available,
/// falling back to the TEE, falling back to a software keymaster — and the level
/// reached is reported, never assumed. ADR-0018 §11.16 (l): *the core MUST NOT
/// substitute a file-backed signer silently.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// `KeyProperties.SECURITY_LEVEL_STRONGBOX` — a discrete secure element.
    StrongBox,
    /// `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` — the TEE.
    TrustedEnvironment,
    /// `SECURITY_LEVEL_SOFTWARE` — a software keymaster. ADR-0020 maps this to
    /// `SOFTWARE_LOCAL`, and it is **not** hardware-backed.
    Software,
    /// No usable Keystore at all. Reported truthfully; every operation refuses.
    Absent,
}

impl SecurityLevel {
    /// Whether the private half genuinely lives in hardware.
    ///
    /// ADR-0020 §11's assurance ladder: StrongBox and TEE are
    /// `HARDWARE_ATTESTED`/`HARDWARE_UNATTESTED`; a software keymaster is
    /// `SOFTWARE_LOCAL` and is not. A `false` here is *a fact to record*, never a
    /// reason to refuse.
    #[must_use]
    pub const fn hardware_backed(self) -> bool {
        matches!(
            self,
            SecurityLevel::StrongBox | SecurityLevel::TrustedEnvironment
        )
    }

    /// A stable, non-localised tag for S-46 and the diagnostic bundle.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            SecurityLevel::StrongBox => "strongbox",
            SecurityLevel::TrustedEnvironment => "tee",
            SecurityLevel::Software => "software-keymaster",
            SecurityLevel::Absent => "absent",
        }
    }
}

/// The Android Keystore, as the JNI layer implements it.
///
/// Both CB-5 (identity operations inside the element) and CB-7 (Tier-1 whole
/// blobs) land here, because on Android they are one platform object. **No
/// method returns private key material**, and no parameter accepts any: CD-I4's
/// invariant is held at this trait's signature exactly as it is at
/// [`twinvpn_platform::custody`]'s.
pub trait KeystoreElement: Send + Sync + Debug {
    /// A stable, non-localised name, e.g. `"android-keystore"`.
    fn name(&self) -> &'static str;

    /// The level the key material actually reached.
    fn security_level(&self) -> SecurityLevel;

    /// The public identity, its generation, and its identifiers.
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] on a locked device before first
    /// unlock (ADR-0022 LC-15) or where no identity has been enrolled.
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError>;

    /// Signs inside the element. ES256, never exported (§11.16 (c)).
    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError>;

    /// Agrees inside the element.
    ///
    /// §11.16 (c) is explicit that in-element **agree** is not required on every
    /// target, so [`PlatformError::OsUnsupported`] is a legitimate answer and is
    /// **not** a licence for the core to fall back to a private key it does not
    /// have. Android Keystore does offer ECDH on P-256 from API 31; below that,
    /// and for X25519 at any level, the honest answer is `OsUnsupported`.
    fn agree(
        &self,
        key: IdentityKeyRef,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError>;

    /// The Android Key Attestation chain, DER-encoded, if one was obtainable.
    ///
    /// `None` is `HARDWARE_UNATTESTED` in ADR-0020's ladder — "some Android OEM
    /// builds" — and a peer MUST NOT treat hardware backing as evidence without
    /// it (ADR-0007 N-6).
    fn attestation(&self) -> Option<Vec<u8>>;

    /// Reads a Tier-1 item, **decrypted by Keystore** (CB-6a).
    ///
    /// `Ok(None)` means absent, which is a normal first-run state. The
    /// distinction from "unavailable" matters because absent enrols and
    /// unavailable must not.
    fn item_read(&self, key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Writes a Tier-1 item **atomically**, encrypted by Keystore.
    ///
    /// ADR-0020 §11's Android row: an AES-256-GCM Keystore key at the same
    /// `SecurityLevel` as the identity key, with
    /// `setRandomizedEncryptionRequired(true)`. That flag is what makes Android
    /// one of the **two of ten** targets with mandatory platform AEAD, and it is
    /// why [`twinvpn_platform::RecordAeadCustody::PlatformPerformed`] is this
    /// adapter's answer.
    fn item_write_atomic(&self, key: &SecureItemKey, value: &[u8]) -> Result<(), PlatformError>;

    /// Deletes a Tier-1 item. Idempotent.
    fn item_delete(&self, key: &SecureItemKey) -> Result<(), PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_strongbox_and_the_tee_are_hardware_backed() {
        assert!(SecurityLevel::StrongBox.hardware_backed());
        assert!(SecurityLevel::TrustedEnvironment.hardware_backed());
        assert!(
            !SecurityLevel::Software.hardware_backed(),
            "a software keymaster is SOFTWARE_LOCAL in ADR-0020's ladder"
        );
        assert!(!SecurityLevel::Absent.hardware_backed());
    }

    #[test]
    fn the_levels_are_ordered_from_strongest_so_a_fallback_reads_downward() {
        assert!(SecurityLevel::StrongBox < SecurityLevel::TrustedEnvironment);
        assert!(SecurityLevel::TrustedEnvironment < SecurityLevel::Software);
        assert!(SecurityLevel::Software < SecurityLevel::Absent);
    }

    #[test]
    fn every_level_has_a_stable_non_localised_tag() {
        for (level, tag) in [
            (SecurityLevel::StrongBox, "strongbox"),
            (SecurityLevel::TrustedEnvironment, "tee"),
            (SecurityLevel::Software, "software-keymaster"),
            (SecurityLevel::Absent, "absent"),
        ] {
            assert_eq!(level.tag(), tag);
            assert!(!level.tag().contains(' '), "a tag is not a sentence");
        }
    }
}
