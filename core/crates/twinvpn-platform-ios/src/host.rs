//! The provider host: what the Swift `NEPacketTunnelProvider` supplies, and the
//! **only** thing it supplies.
//!
//! **Authority:** ADR-0018 CB-1, CB-2, PB-1; `docs/implementation/ownership.md`
//! §10.4 (the W-24/W-25 ruling for a Swift shell); ADR-0022 LC-17 (the app /
//! extension responsibility table).
//!
//! # Why this trait exists, and why it is shaped like this
//!
//! `NEPacketTunnelProvider`, `NEPacketTunnelFlow`, `NWPathMonitor` and
//! `NETunnelProviderManager` are Swift/Objective-C only. They are CB-1 (a): a
//! platform API with no stable C-callable form. Everything the core wants to do
//! with them is therefore reachable only by asking Swift to make the call.
//!
//! CB-2 then decides the *shape* of the asking. A shell may translate, marshal,
//! schedule and render; it must not hold a branch whose condition is a TwinVPN
//! domain fact. So every method here:
//!
//! - takes a **rendered programme** — plain data this crate already computed —
//!   or takes nothing at all;
//! - returns a **raw platform fact** — a snapshot, a byte count, an OS number;
//! - names **no** [`twinvpn_platform::Ruleset`], no `ConnectionState`, no
//!   `reason_code`, no policy verdict and no candidate priority.
//!
//! `ownership.md` §10.4 states the same rule from the other end: "The bridge
//! surface is **not** permitted to grow a TwinVPN domain fact. An entry that
//! takes or returns a `ConnectionState`, a `reason_code` class, a policy verdict
//! or a candidate priority is a CB-2 violation on the wrong side of the line,
//! and is a finding." [`HostStatus`] below is the mechanical consequence: Swift
//! hands back the number the OS gave it, and [`crate::oserr`] — in Rust — turns
//! that number into a registered name.
//!
//! # This is not an ABI of record
//!
//! §10.4 again: the `extern "C"` bridge in [`crate::bridge`] that binds Swift to
//! this trait "is **not** an ABI of record, is **not** `twinvpn.h`, and acquires
//! **no** compatibility obligation: both sides are compiled from one commit into
//! one artifact". This trait is the Rust-side face of that bridge, and a test
//! host ([`RecordingHost`]) implements it with no Swift at all — which is what
//! makes every layer above it *executed* rather than *written, not compiled*.

use std::sync::Mutex;

/// What a host call returned, before it becomes a [`twinvpn_platform::PlatformError`].
///
/// Deliberately three number spaces and no fourth: Swift reports what the OS
/// reported. Turning that into a TwinVPN name is [`crate::oserr`]'s, in Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// The call succeeded.
    Ok,
    /// A POSIX `errno`.
    Errno(i32),
    /// An `OSStatus` from `Security.framework`.
    OsStatus(i32),
    /// A code in `NEVPNErrorDomain`.
    NeVpnError(i32),
    /// The host is not attached — no provider is running, or the bridge has not
    /// been registered. Distinct from every OS number, because "we never asked
    /// the OS" and "the OS refused" are different facts.
    NotAttached,
}

impl HostStatus {
    /// Whether the call succeeded.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, HostStatus::Ok)
    }
}

/// One rendered `NEPacketTunnelNetworkSettings` programme, as bytes.
///
/// The encoding is [`crate::settings::TunnelSettingsProgramme`]'s canonical JSON
/// (see that module for why JSON and not protobuf). Swift decodes it and calls
/// `setTunnelNetworkSettings`; it makes no decision about the contents.
pub type SettingsProgramme<'a> = &'a str;

/// What `NWPathMonitor` most recently reported, as bytes.
///
/// The encoding is [`crate::pathmon::PathSnapshot`]'s canonical JSON. Swift
/// serialises the `NWPath` it was handed and nothing more; deciding what a change
/// *means* — a migration, a family arriving, a resolver change — is
/// [`crate::pathmon`]'s, in Rust, and above it the core's.
pub type PathSnapshotJson = String;

/// The Swift side of the seam.
///
/// Every method is a mechanism. None is a decision.
pub trait ProviderHost: Send + Sync {
    // -- the packet tunnel (PB-1's one conceded crossing) --------------------

    /// Applies a rendered settings programme via `setTunnelNetworkSettings`.
    ///
    /// This is **the whole of** address, route, DNS and MTU programming on this
    /// platform: `docs/networking.md` §5.2's iOS row is
    /// "`NEPacketTunnelNetworkSettings` only (no route API)", so there is no
    /// separate route call for Swift to get wrong.
    fn apply_settings(&self, programme: SettingsProgramme<'_>) -> HostStatus;

    /// Clears the tunnel settings (`setTunnelNetworkSettings(nil)`).
    ///
    /// Used by rollback to generation zero and by teardown. It does **not** and
    /// must not remove on-demand rules or `includeAllNetworks`: CB-6 puts those
    /// in the OS's custody so that the core going away cannot drop protection.
    fn clear_settings(&self) -> HostStatus;

    /// Reads a batch of outbound packets from `NEPacketTunnelFlow`.
    ///
    /// PB-1: "1 per batch, + 1 copy per packet — the API is Swift/Objective-C
    /// only and hands the caller `Data`; there is no fd. Unavoidable, therefore
    /// budgeted." Returns the packets, each already copied out of its `Data`.
    ///
    /// An empty vector means "no packets were ready", never an error.
    fn read_packets(&self) -> Result<Vec<Vec<u8>>, HostStatus>;

    /// Writes one batch of inbound packets to `NEPacketTunnelFlow`.
    ///
    /// `families` runs parallel to `packets`: `NEPacketTunnelFlow.writePackets`
    /// takes an `AF_INET`/`AF_INET6` protocol number per packet, and getting it
    /// from the packet's own version nibble is a decision — so this crate makes
    /// it (in [`crate::tun`]) and Swift is handed the answer.
    fn write_packets(&self, packets: &[Vec<u8>], families: &[i32]) -> HostStatus;

    // -- enforcement (there is no host firewall on this platform) ------------

    /// Installs the on-demand rule set and the `includeAllNetworks` /
    /// `excludeLocalNetworks` flags, from a rendered programme.
    ///
    /// The encoding is [`crate::enforce::EnforcementProgramme`]'s canonical JSON.
    /// ADR-0012's iOS row has no packet filter to install; this is the entire
    /// mechanism, and KS-17's atomicity is the OS's `saveToPreferences`.
    fn apply_enforcement(&self, programme: &str) -> HostStatus;

    /// Reads back what is **actually installed**, from
    /// `NETunnelProviderManager` and the running session.
    ///
    /// W-24 requires the `ProtectionAssertion` to be "a pure function of the most
    /// recent assertion, never of the agent's belief", produced by querying the
    /// enforcement layer. On a platform with no firewall to query, the OS's own
    /// configuration *is* the enforcement layer, so this reads it rather than a
    /// cache. Returns the same canonical JSON `apply_enforcement` takes, or
    /// `Ok(None)` when no configuration is installed at all.
    fn installed_enforcement(&self) -> Result<Option<String>, HostStatus>;

    // -- network path --------------------------------------------------------

    /// The most recent `NWPathMonitor` snapshot, if the monitor has fired.
    ///
    /// `docs/networking.md` §5.1: "event-driven, never polled". Swift keeps the
    /// monitor and pushes each update through [`crate::bridge`]; this accessor
    /// exists for the initial enumerate, which the trait contract requires a
    /// fresh subscriber to perform separately from subscribing.
    fn path_snapshot(&self) -> Result<Option<PathSnapshotJson>, HostStatus>;

    // -- Tier-1 custody (CB-7) ----------------------------------------------

    /// Reads a Keychain item by its already-rendered query attributes.
    ///
    /// `attributes` is [`crate::keychain::ItemQuery`]'s canonical JSON — the
    /// service, account, access group and accessibility class this crate
    /// computed. Swift builds the `CFDictionary` from it and calls
    /// `SecItemCopyMatching`; it chooses none of those values.
    fn keychain_read(&self, attributes: &str) -> Result<Option<Vec<u8>>, HostStatus>;

    /// Writes a Keychain item atomically (whole-blob replacement, CB-7).
    fn keychain_write(&self, attributes: &str, value: &[u8]) -> HostStatus;

    /// Deletes a Keychain item. Idempotent.
    fn keychain_delete(&self, attributes: &str) -> HostStatus;

    /// The App Group container path, with its file-protection class and
    /// backup-exclusion flag **already applied** (CB-7, ADR-0020 ST-6, ST-26,
    /// ST-12e).
    ///
    /// Vended, never discovered: ST-12e forbids the core deriving, probing or
    /// falling back to a path of its own, and CD-2 forbids reading it from the
    /// ambient environment.
    fn store_root(&self) -> Result<String, HostStatus>;

    /// Whether the vended root's backup exclusion was verified **at this start**.
    ///
    /// ST-26 requires re-verification at every start and says a failure "is
    /// `STORE.BACKUP_EXCLUSION_FAILED`, not a silent success". That code is not
    /// in the frozen registry (see [`crate::lib`] and the crate's README), so
    /// this is reported as a declared posture fact instead of an invented name.
    ///
    /// [`crate::lib`]: crate
    fn store_root_backup_excluded(&self) -> bool;

    // -- the Secure Enclave (CB-5) ------------------------------------------

    /// Signs `message` with the element-resident key named by `key_tag`.
    ///
    /// `key_tag` is the `kSecAttrApplicationTag` this crate computed. ES256,
    /// inside the enclave, private half never exported (CB-5 row 1, ADR-0007
    /// N-5).
    fn enclave_sign(&self, key_tag: &str, message: &[u8]) -> Result<Vec<u8>, HostStatus>;

    /// Performs an element-resident key agreement, where the enclave offers one
    /// of the requested shape.
    ///
    /// The Secure Enclave does P-256 ECDH and **not** X25519, so a caller asking
    /// for X25519 gets a refusal — which is a fact the core records, and never a
    /// licence to substitute a software key ([`crate::custody`] states this at
    /// the call site).
    fn enclave_agree(
        &self,
        key_tag: &str,
        algorithm: &str,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, HostStatus>;

    /// The public half of an element-resident key, in the element's own
    /// encoding, plus its attestation when the element produces one.
    fn enclave_public(&self, key_tag: &str) -> Result<HostIdentity, HostStatus>;

    /// Whether the private halves are genuinely enclave-resident on this device.
    ///
    /// Reported truthfully per §11.16 (l). A simulator has no SEP; `false` there
    /// is the honest answer and the core records it rather than the adapter
    /// pretending.
    fn enclave_hardware_backed(&self) -> bool;
}

/// The public identity material the element hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    /// The public key, in the element's own encoding (X9.62 uncompressed point
    /// for a SEP P-256 key).
    pub public_key: Vec<u8>,
    /// The `SecKeyCreateAttestation` blob, when the element produced one.
    pub attestation: Option<Vec<u8>>,
    /// The generation this key belongs to (ADR-0007 rotation, `T_IK_OVERLAP`).
    pub generation: u32,
}

/// A host that is not attached to anything.
///
/// Every call reports [`HostStatus::NotAttached`]. It is what the adapter holds
/// before the Swift provider registers itself, and it is what a host-side test
/// of the *assembly* binds — so that "nothing is attached" is a state with a
/// registered name rather than a null dereference.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetachedHost;

impl ProviderHost for DetachedHost {
    fn apply_settings(&self, _programme: SettingsProgramme<'_>) -> HostStatus {
        HostStatus::NotAttached
    }
    fn clear_settings(&self) -> HostStatus {
        HostStatus::NotAttached
    }
    fn read_packets(&self) -> Result<Vec<Vec<u8>>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn write_packets(&self, _packets: &[Vec<u8>], _families: &[i32]) -> HostStatus {
        HostStatus::NotAttached
    }
    fn apply_enforcement(&self, _programme: &str) -> HostStatus {
        HostStatus::NotAttached
    }
    fn installed_enforcement(&self) -> Result<Option<String>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn path_snapshot(&self) -> Result<Option<PathSnapshotJson>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn keychain_read(&self, _attributes: &str) -> Result<Option<Vec<u8>>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn keychain_write(&self, _attributes: &str, _value: &[u8]) -> HostStatus {
        HostStatus::NotAttached
    }
    fn keychain_delete(&self, _attributes: &str) -> HostStatus {
        HostStatus::NotAttached
    }
    fn store_root(&self) -> Result<String, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn store_root_backup_excluded(&self) -> bool {
        false
    }
    fn enclave_sign(&self, _key_tag: &str, _message: &[u8]) -> Result<Vec<u8>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn enclave_agree(
        &self,
        _key_tag: &str,
        _algorithm: &str,
        _peer_public: &[u8],
    ) -> Result<Vec<u8>, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn enclave_public(&self, _key_tag: &str) -> Result<HostIdentity, HostStatus> {
        Err(HostStatus::NotAttached)
    }
    fn enclave_hardware_backed(&self) -> bool {
        false
    }
}

/// A host that records what it was asked to do and replays what it was told to
/// answer.
///
/// This is what makes `ownership.md` §10.3's **executed** row reach as far as it
/// does: every trait implementation in this crate can be driven end to end on the
/// Linux build host, and the assertions are about *what programme was rendered*
/// — which is the half a device farm would not check any better.
#[derive(Default)]
pub struct RecordingHost {
    state: Mutex<RecordingState>,
}

/// What a [`RecordingHost`] saw and will say.
#[derive(Debug, Default)]
pub struct RecordingState {
    /// Every settings programme applied, in order.
    pub settings_applied: Vec<String>,
    /// How many times settings were cleared.
    pub settings_cleared: u32,
    /// Every enforcement programme applied, in order.
    pub enforcement_applied: Vec<String>,
    /// What `installed_enforcement` should report.
    pub installed_enforcement: Option<String>,
    /// What `path_snapshot` should report.
    pub path_snapshot: Option<String>,
    /// Packets the flow will hand out on the next read.
    pub inbound: Vec<Vec<u8>>,
    /// Packets written to the flow, with the family Swift was handed.
    pub outbound: Vec<(Vec<u8>, i32)>,
    /// The Keychain, keyed by the rendered query.
    pub keychain: std::collections::BTreeMap<String, Vec<u8>>,
    /// The vended root.
    pub store_root: String,
    /// Whether backup exclusion verified at this start.
    pub backup_excluded: bool,
    /// Whether the element reports hardware backing.
    pub hardware_backed: bool,
    /// A status to return from the next mutating call, then cleared.
    pub fail_next: Option<HostStatus>,
    /// A status to return from the next `apply_settings` specifically.
    ///
    /// Separate from `fail_next` because the ordering inside
    /// [`crate::netcfg::IosNetworkConfig::apply`] is load-bearing: a test that
    /// wants to prove "a settings failure leaves enforcement installed" must be
    /// able to fail the *second* call, and a single fail-next latch would always
    /// be eaten by the first.
    pub fail_settings_next: Option<HostStatus>,
    /// Whether an agreement of the requested algorithm is offered at all.
    pub agree_algorithms: Vec<String>,
}

impl RecordingHost {
    /// A host with an empty Keychain, a vended root and a hardware-backed element.
    #[must_use]
    pub fn new(store_root: impl Into<String>) -> Self {
        Self {
            state: Mutex::new(RecordingState {
                store_root: store_root.into(),
                backup_excluded: true,
                hardware_backed: true,
                // The SEP does P-256 ECDH and nothing else. Stated as data so a
                // test can model a device that offers neither.
                agree_algorithms: vec!["ecdh-p256".to_owned()],
                ..RecordingState::default()
            }),
        }
    }

    /// Inspects or edits what the host saw and will say.
    pub fn state(&self) -> std::sync::MutexGuard<'_, RecordingState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Makes the next mutating call fail with `status`.
    pub fn fail_next(&self, status: HostStatus) {
        self.state().fail_next = Some(status);
    }

    /// Makes the next `apply_settings` — and only that — fail with `status`.
    pub fn fail_settings_next(&self, status: HostStatus) {
        self.state().fail_settings_next = Some(status);
    }

    fn take_failure(&self) -> Option<HostStatus> {
        self.state().fail_next.take()
    }
}

impl ProviderHost for RecordingHost {
    fn apply_settings(&self, programme: SettingsProgramme<'_>) -> HostStatus {
        if let Some(status) = self.state().fail_settings_next.take() {
            return status;
        }
        if let Some(status) = self.take_failure() {
            return status;
        }
        self.state().settings_applied.push(programme.to_owned());
        HostStatus::Ok
    }

    fn clear_settings(&self) -> HostStatus {
        if let Some(status) = self.take_failure() {
            return status;
        }
        self.state().settings_cleared += 1;
        HostStatus::Ok
    }

    fn read_packets(&self) -> Result<Vec<Vec<u8>>, HostStatus> {
        Ok(core::mem::take(&mut self.state().inbound))
    }

    fn write_packets(&self, packets: &[Vec<u8>], families: &[i32]) -> HostStatus {
        if let Some(status) = self.take_failure() {
            return status;
        }
        let mut state = self.state();
        for (packet, family) in packets.iter().zip(families.iter()) {
            state.outbound.push((packet.clone(), *family));
        }
        HostStatus::Ok
    }

    fn apply_enforcement(&self, programme: &str) -> HostStatus {
        if let Some(status) = self.take_failure() {
            return status;
        }
        let mut state = self.state();
        state.enforcement_applied.push(programme.to_owned());
        // The OS holds it: a read-back after an apply reports what was applied,
        // which is the property W-24's query relies on.
        state.installed_enforcement = Some(programme.to_owned());
        HostStatus::Ok
    }

    fn installed_enforcement(&self) -> Result<Option<String>, HostStatus> {
        Ok(self.state().installed_enforcement.clone())
    }

    fn path_snapshot(&self) -> Result<Option<PathSnapshotJson>, HostStatus> {
        Ok(self.state().path_snapshot.clone())
    }

    fn keychain_read(&self, attributes: &str) -> Result<Option<Vec<u8>>, HostStatus> {
        Ok(self.state().keychain.get(attributes).cloned())
    }

    fn keychain_write(&self, attributes: &str, value: &[u8]) -> HostStatus {
        if let Some(status) = self.take_failure() {
            return status;
        }
        self.state()
            .keychain
            .insert(attributes.to_owned(), value.to_vec());
        HostStatus::Ok
    }

    fn keychain_delete(&self, attributes: &str) -> HostStatus {
        if let Some(status) = self.take_failure() {
            return status;
        }
        self.state().keychain.remove(attributes);
        HostStatus::Ok
    }

    fn store_root(&self) -> Result<String, HostStatus> {
        Ok(self.state().store_root.clone())
    }

    fn store_root_backup_excluded(&self) -> bool {
        self.state().backup_excluded
    }

    fn enclave_sign(&self, key_tag: &str, message: &[u8]) -> Result<Vec<u8>, HostStatus> {
        if let Some(status) = self.take_failure() {
            return Err(status);
        }
        // A deterministic NON-CRYPTOGRAPHIC tag, exactly as the seam's own mock
        // does: it must be impossible to mistake for an ES256 signature.
        let mut out = b"recording-host-not-a-signature:".to_vec();
        out.extend_from_slice(key_tag.as_bytes());
        out.push(b':');
        out.extend_from_slice(&(message.len() as u64).to_be_bytes());
        Ok(out)
    }

    fn enclave_agree(
        &self,
        _key_tag: &str,
        algorithm: &str,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, HostStatus> {
        if !self.state().agree_algorithms.iter().any(|a| a == algorithm) {
            // The enclave does not offer this shape. `errSecUnimplemented` is
            // what a real SEP returns for an unsupported algorithm, and it maps
            // to PLATFORM.OS_UNSUPPORTED — the fact, not a substitution.
            return Err(HostStatus::OsStatus(crate::oserr::ERR_SEC_UNIMPLEMENTED));
        }
        let mut out = b"recording-host-not-a-secret:".to_vec();
        out.extend_from_slice(&(peer_public.len() as u64).to_be_bytes());
        Ok(out)
    }

    fn enclave_public(&self, key_tag: &str) -> Result<HostIdentity, HostStatus> {
        Ok(HostIdentity {
            public_key: key_tag.as_bytes().to_vec(),
            attestation: self
                .state()
                .hardware_backed
                .then(|| b"attestation".to_vec()),
            generation: 0,
        })
    }

    fn enclave_hardware_backed(&self) -> bool {
        self.state().hardware_backed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_detached_host_names_the_state_rather_than_faulting() {
        let host = DetachedHost;
        assert_eq!(host.apply_settings("{}"), HostStatus::NotAttached);
        assert_eq!(host.installed_enforcement(), Err(HostStatus::NotAttached));
        assert!(!host.enclave_hardware_backed());
        // "We never asked the OS" is not an OS number, and the two must not be
        // conflated: one means the provider has not started, the other means it
        // started and the OS refused.
        assert_ne!(host.apply_settings("{}"), HostStatus::Errno(0));
    }

    #[test]
    fn the_enclave_refuses_an_agreement_it_does_not_offer() {
        let host = RecordingHost::new("/tmp/store");
        assert!(host.enclave_agree("ik", "ecdh-p256", &[1, 2, 3]).is_ok());
        // X25519 is exactly the shape ADR-0007 N-5 says the platform key APIs
        // largely do not offer, which is why TK is hardware-*wrapped* instead.
        assert_eq!(
            host.enclave_agree("tk", "x25519", &[1, 2, 3]),
            Err(HostStatus::OsStatus(crate::oserr::ERR_SEC_UNIMPLEMENTED))
        );
    }

    #[test]
    fn a_recorded_signature_cannot_be_mistaken_for_a_real_one() {
        let host = RecordingHost::new("/tmp/store");
        let sig = host.enclave_sign("ik.gen0", b"message").expect("signs");
        assert!(String::from_utf8_lossy(&sig).contains("not-a-signature"));
        assert_ne!(sig.len(), 64, "an ES256 signature is 64 raw bytes");
    }

    #[test]
    fn the_os_holds_what_was_installed_so_a_read_back_is_a_query() {
        let host = RecordingHost::new("/tmp/store");
        assert_eq!(host.installed_enforcement(), Ok(None));
        assert_eq!(host.apply_enforcement("{\"a\":1}"), HostStatus::Ok);
        assert_eq!(
            host.installed_enforcement(),
            Ok(Some("{\"a\":1}".to_owned()))
        );
    }
}
