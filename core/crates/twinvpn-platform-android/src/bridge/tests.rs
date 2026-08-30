//! The bridge's ingest entry points, driven with no JVM.
//!
//! This is what makes §10.4's prohibition **executed** rather than reviewed: the
//! five entry points are exercised here, and the last test in this file asserts
//! over the module's own source that no sixth entry has grown a TwinVPN domain
//! fact.
//!
//! [`reentrancy`] is the one case that needs a *sequence* rather than a single
//! call: the `establish()` fan-out arriving back at `on_network`, which is
//! M-19's question.

/// The `establish()` fan-out, delivered back to the process that made it.
mod reentrancy;

use std::sync::Arc;

use super::*;
use crate::builder::{Programme, VpnConfig};
use crate::hostcall::{KeystoreElement, RawFd, SecurityLevel, TunnelController};
use crate::netchange::{AndroidNetwork, TransportSet};
use crate::power::KeepalivePlan;
use crate::{AndroidAdapterParts, AndroidPlatformAdapter};
use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, SecureItemKey, SharedSecret, Signature,
};
use twinvpn_types::PerFamily;

#[derive(Debug, Default)]
struct StubController;

impl TunnelController for StubController {
    fn name(&self) -> &'static str {
        "stub"
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

#[derive(Debug, Default)]
struct StubElement;

impl KeystoreElement for StubElement {
    fn name(&self) -> &'static str {
        "stub"
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

fn bridge() -> AndroidBridge {
    AndroidBridge::new(AndroidPlatformAdapter::new(AndroidAdapterParts {
        controller: Arc::new(StubController),
        element: Arc::new(StubElement),
        store_root: std::path::PathBuf::from("/vault"),
        vpn_config: VpnConfig::default(),
    }))
}

fn network(handle: u64, transports: u32) -> AndroidNetwork {
    AndroidNetwork {
        handle,
        name: InterfaceName::new("wlan0").expect("name"),
        transports: TransportSet::from_bits(transports),
        addresses: Vec::new(),
        default_routes: PerFamily::new(true, true),
        resolvers: Vec::new(),
        mtu: 1500,
        metered: false,
        nat64: None,
        private_dns_active: false,
        is_up: true,
    }
}

#[test]
fn a_network_observation_reaches_the_snapshot() {
    let bridge = bridge();
    let payload = wire::encode_network(&network(1, TransportSet::WIFI));
    bridge.on_network(&payload).expect("ingest");
    assert_eq!(
        bridge
            .adapter()
            .interface_provider()
            .snapshot()
            .expect("snapshot")
            .networks()
            .len(),
        1
    );

    bridge.on_network_lost(1).expect("lost");
    assert!(bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot")
        .networks()
        .is_empty());
}

/// A **populated** address set survives `on_network`, link-local and all.
///
/// Every other test in this file uses [`network`], whose `addresses` is empty,
/// so the address loop in [`wire::decode_network`] had never run through
/// `on_network` at all — decoded in isolation by `wire::tests`, never on the
/// path the JNI entry actually takes. That is the gap the CI crash fell into:
/// the first two callbacks of an `onAvailable` fan-out carry no
/// `LinkProperties`, so only the third has addresses, and only the third died.
///
/// The fixture is what a real Wi-Fi interface reports — a v4 host address with
/// its host bits, a global v6, and an `fe80::/64` carrying the interface index.
#[test]
fn a_populated_address_set_reaches_the_snapshot_intact() {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    octets[15] = 1;
    let link_local = twinvpn_types::V6Addr::new(octets, twinvpn_types::ZoneIndex::new(24))
        .expect("a link-local carries its interface index");

    let mut global = [0u8; 16];
    global[0] = 0x2a;
    global[1] = 0x00;
    global[15] = 0x0a;
    let global = twinvpn_types::V6Addr::new(global, None).expect("a global v6 carries no zone");

    let mut original = network(3, TransportSet::WIFI);
    original.addresses = vec![
        twinvpn_types::InterfaceAddress::new(
            twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([192, 168, 1, 10])),
            24,
        )
        .expect("v4 host"),
        twinvpn_types::InterfaceAddress::new(twinvpn_types::IpAddr::V6(global), 64)
            .expect("global v6"),
        twinvpn_types::InterfaceAddress::new(twinvpn_types::IpAddr::V6(link_local), 64)
            .expect("link-local v6"),
    ];

    let bridge = bridge();
    bridge
        .on_network(&wire::encode_network(&original))
        .expect("a real interface's addresses cross the bridge");

    let snapshot = bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot");
    assert_eq!(snapshot.networks()[0].addresses, original.addresses);
}

#[test]
fn a_malformed_payload_is_refused_and_changes_nothing() {
    let bridge = bridge();
    let err = bridge.on_network(&[0xff, 0x00]).expect_err("malformed");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert!(bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot")
        .networks()
        .is_empty());
}

#[test]
fn the_power_posture_is_two_booleans_and_the_core_decides_what_they_mean() {
    let bridge = bridge();
    bridge.on_power(true, true).expect("posture");
    let snapshot = bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot");
    assert!(snapshot.metered());
    assert!(snapshot.low_power());
}

/// LC-40: nobody told us is `UNVERIFIED`, and `UNVERIFIED` presents as
/// unprotected. There is no probe entry, and there must not be one.
#[test]
fn the_lockdown_report_is_three_valued_and_defaults_to_unverified() {
    let bridge = bridge();
    assert_eq!(
        bridge.adapter().network().lockdown(),
        crate::posture::LockdownPosture::Unverified
    );
    bridge.on_lockdown_report(Some(true));
    assert_eq!(
        bridge.adapter().network().lockdown(),
        crate::posture::LockdownPosture::Confirmed
    );
    bridge.on_lockdown_report(Some(false));
    assert_eq!(
        bridge.adapter().network().lockdown(),
        crate::posture::LockdownPosture::Absent
    );
    bridge.on_lockdown_report(None);
    assert_eq!(
        bridge.adapter().network().lockdown(),
        crate::posture::LockdownPosture::Unverified
    );
}

/// `onRevoke()` with nothing established is a no-op, not a failure: the system
/// may revoke a tunnel we never brought up.
#[test]
fn revocation_with_no_claim_is_a_no_op() {
    let bridge = bridge();
    bridge.on_revoked().expect("no claim to drop");
    assert!(!bridge.adapter().network().enforcement_view().claim_in_force);
}

/// A second VPN arrives as an ordinary network observation classified
/// `Tunnel` — **a fact**. The verdict (`NET.CONCURRENT_VPN`, substituted) is the
/// core's, and the bridge has no entry that could carry it.
#[test]
fn a_competing_vpn_arrives_as_a_fact_and_never_as_a_verdict() {
    let bridge = bridge();
    let payload = wire::encode_network(&network(7, TransportSet::VPN | TransportSet::WIFI));
    bridge.on_network(&payload).expect("ingest");
    let snapshot = bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot");
    assert_eq!(
        crate::netchange::link_class(snapshot.networks()[0].transports),
        twinvpn_platform::iface::LinkClass::Tunnel
    );
    // And it does not count as an underlay default route.
    assert!(!snapshot.underlay_has_default(twinvpn_types::AddressFamily::V4));
}

/// **No entry point throws into the JVM.** A NEW requirement, not a repair.
///
/// Nothing in the corpus obliged `bridge::entry` to contain a refusal before
/// this, and the two rules that look like they do, do not:
///
/// * **ADR-0019 X3(5)** — *"a core fault MUST NOT abort the UI process"* —
///   records Android as discharged *"because the UI process does not load the
///   core at all, so the fault is in another process"*. That premise does not
///   hold in this tree: `AndroidManifest.xml` declares no `android:process` on
///   any component, so `MainActivity` and `TwinVpnService` are one process, and
///   the crash names it — `Process: net.twinvpn.android`.
/// * **ADR-0018 F-7** contains a **panic**. What `entry` threw was a typed
///   `PlatformError` refusal, which F-7 does not reach.
///
/// So this test is the requirement rather than a check on one. It is also the
/// only host-runnable form of it: `entry` is `#[cfg(target_os = "android")]`, so
/// `make cross-check` compiles it for `aarch64-linux-android` and nothing on any
/// host runs it. The property is a source property, and it is checked as one.
///
/// Why it must hold: JNI `ThrowNew` does not unwind the native frame, it sets a
/// pending exception that becomes a real Java exception the instant the entry
/// returns — into `CallbackHandler.handleMessage`, which has no `try`/`catch`,
/// under a `Looper` that rethrows, under a `KillApplicationHandler` that ends in
/// `Process.killProcess`. Reporting a refusal as a throw was therefore process
/// death: `FATAL EXCEPTION: ConnectivityThread` /
/// `java.lang.IllegalStateException: PLATFORM.ADAPTER_UNAVAILABLE`.
#[test]
fn no_bridge_entry_point_throws_into_the_jvm() {
    let source = include_str!("entry.rs");
    // Comment lines are stripped: the module documentation explains at length
    // why throwing here is fatal, and a scan that could not tell the rule from a
    // violation would forbid stating it.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in ["throw", "Throw", "THROWABLE", "exception_occurred"] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears in `bridge::entry`: every entry there is a \
             platform callback, and a Java exception crossing back out of one \
             is process death, not a report"
        );
    }

    // The rule is a RULE, not a special case for the entry that happened to
    // crash. Each of the five is named, because three of the other four are on
    // the same fatal threads and were only ever latent — `nativeOnNetworkLost`
    // on `ConnectivityThread`, `nativeOnPower` and `nativeOnLockdownReport` on
    // the main `Looper`. `nativeCreate` and `nativeDestroy` are absent by
    // design: our own Kotlin calls those, and they already return sentinels.
    for entry in [
        "nativeOnNetwork",
        "nativeOnNetworkLost",
        "nativeOnPower",
        "nativeOnRevoked",
        "nativeOnLockdownReport",
    ] {
        assert!(
            code.contains(&format!("guard(\"{entry}\"")),
            "`{entry}` does not route through `guard`: a platform callback that \
             can still kill the process"
        );
    }
}

/// **§10.4's prohibition, asserted over this module's own source.**
///
/// The bridge's vocabulary is Android's. If a future entry point takes or
/// returns a `ConnectionState`, a `reason_code` class, a policy verdict or a
/// candidate priority, this test fails and names it.
#[test]
fn the_bridge_speaks_android_and_never_twinvpn() {
    let source = include_str!("mod.rs");
    // Everything from `#[cfg(test)]` onward is this test file's own reference to
    // those names, so the scan stops there. Comment lines are stripped as well:
    // the module documentation QUOTES §10.4's prohibition, and a scan that
    // could not tell a rule from a violation would forbid stating the rule.
    let surface = source
        .split_once("#[cfg(test)]")
        .map_or(source, |(before, _)| before);
    let code: String = surface
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in [
        "ConnectionState",
        "ErrorClass",
        "ReasonCode",
        "PathClass",
        "TrafficDisposition",
        "HealthState",
        "SessionState",
    ] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears on the bridge surface: §10.4 forbids a \
             TwinVPN domain fact on this boundary"
        );
    }
    // Five ingest entry points, and no more. A sixth is a design change that
    // must be argued, not merged.
    let entries = code.matches("    pub fn on_").count();
    assert_eq!(
        entries, 5,
        "the bridge has {entries} ingest entry points; it should have five, \
         each an Android fact"
    );
}
