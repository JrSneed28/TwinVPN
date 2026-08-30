//! The Kotlin↔Rust bridge: **internal linkage, not an ABI of record**.
//!
//! **Authority:** `docs/implementation/ownership.md` **§10.4** (the wave-3
//! ruling, quoted below), §10.2, §8 W-24 and W-25; ADR-0018 CB-2, VR-2, §11.5's
//! Android rows, PB-1.
//!
//! # The ruling this module implements
//!
//! §10.4, in terms:
//!
//! > The missing capabilities stay **in Rust, in-process**, inside
//! > `twinvpn-platform-{ios,android}`, and the Swift/Kotlin side reaches them
//! > through a per-platform `extern "C"` bridge exported by that same adapter
//! > crate. That bridge is **not** an ABI of record, is **not** `twinvpn.h`, and
//! > acquires **no** compatibility obligation: both sides are compiled from one
//! > commit into one artifact, which is precisely the same-process scope VR-2
//! > already carves out.
//!
//! And its first consequence:
//!
//! > Sockets, the NAT ladder, interface enumeration and change events, ruleset
//! > read-back and `current_generation` are Rust on both mobile targets. Swift
//! > and Kotlin marshal; they do not decide (CB-2).
//!
//! # The rule that keeps CB-2 checkable: the bridge speaks Android, not TwinVPN
//!
//! §10.4 forbids the bridge growing "a TwinVPN domain fact — an entry that takes
//! or returns a `ConnectionState`, a `reason_code` class, a policy verdict or a
//! candidate priority". The discipline adopted here is **stronger and easier to
//! audit**: the bridge's whole vocabulary is the one Android already has.
//!
//! | Kotlin reports | Bridge entry | What Rust does with it |
//! |---|---|---|
//! | `onAvailable` / `onCapabilitiesChanged` / `onLinkPropertiesChanged` | [`AndroidBridge::on_network`] | decodes, diffs, publishes `NetworkChange` |
//! | `onLost` | [`AndroidBridge::on_network_lost`] | diffs, publishes |
//! | `PowerManager` idle / battery saver | [`AndroidBridge::on_power`] | publishes `LinkPostureChanged` |
//! | `onRevoke()` | [`AndroidBridge::on_revoked`] | drops the claim; the core names the condition |
//! | a managed-configuration read | [`AndroidBridge::on_lockdown_report`] | three-valued posture (LC-40) |
//!
//! There is no `onConnected`, no `setState`, no `reportError(code)`. Kotlin
//! cannot say a TwinVPN thing because there is no entry that accepts one, and
//! `the_bridge_speaks_android_and_never_twinvpn` asserts it over this file's own
//! source rather than over a comment.
//!
//! # What is behind `#[cfg]` and what is not
//!
//! Only `jvm` (the JNI-backed [`crate::hostcall`] implementations) and `entry`
//! (the `Java_…` symbols). Everything in this file and in [`wire`] compiles and
//! is tested on a Linux host, which is what moves the bridge's *decisions* —
//! decode, validate, reject — from `ownership.md` §9.2's **written, not
//! compiled** row into **executed**.

pub mod wire;

/// The JNI-backed [`crate::hostcall`] implementations.
///
/// `cargo check`ed against the real bionic and `jni` crates by
/// `make cross-check`; **never linked and never run** on this host.
#[cfg(all(target_os = "android", feature = "jvm-bridge"))]
pub mod jvm;

/// The `Java_net_twinvpn_android_NativeBridge_*` symbols.
///
/// # Why a feature and not `cfg(target_os)` alone
///
/// This module's symbols are `#[no_mangle]`, and they belong to exactly one
/// shared object: `libtwinvpn_platform_android.so`, which `NativeBridge`'s
/// `init` loads first. `shells/android/jni` links this crate too — for
/// [`crate::hostvtable`]'s three W-7 capabilities, and for nothing else — and
/// with an unconditional `cfg` that second link would put a **duplicate**
/// `Java_net_twinvpn_android_NativeBridge_nativeCreate` (and every sibling) into
/// `libtwinvpn_android_jni.so`, carrying its own copy of this module's registry.
/// Both `.so`s are loaded into one process (`build/ci/ci-android.sh` §1), so the
/// JVM would then bind those names by **load order** rather than by design, and
/// the adapter state Kotlin registered would sit in whichever copy happened to
/// win.
///
/// `default = ["jvm-bridge"]` keeps the shipped `.so` byte-identical; the shell
/// turns it off, and gets the capabilities without the symbols.
#[cfg(all(target_os = "android", feature = "jvm-bridge"))]
pub mod entry;

use twinvpn_platform::{PlatformError, TunnelDevice};

use crate::iface::AndroidInterfaceProvider;
use crate::netcfg::AndroidNetworkConfig;
use crate::tun::AndroidTunnelDevice;
use crate::AndroidPlatformAdapter;

/// The object the JNI layer holds, and the only thing it may call.
///
/// Deliberately **not** the adapter itself: the adapter's methods are the seam's
/// and the core's to call, and exposing them to Kotlin would be the shortest
/// path to a decision leaking across. This type exposes five ingest entry
/// points, all of them Android facts, and nothing else.
#[derive(Debug, Clone)]
pub struct AndroidBridge {
    adapter: AndroidPlatformAdapter,
}

impl AndroidBridge {
    /// Wraps an adapter.
    #[must_use]
    pub const fn new(adapter: AndroidPlatformAdapter) -> Self {
        Self { adapter }
    }

    /// The adapter, for the shell's own composition root — **not** for Kotlin.
    ///
    /// The `entry` module never calls this; it exists so the Rust-side code that
    /// builds the core can reach the adapter it is about to bind.
    #[must_use]
    pub const fn adapter(&self) -> &AndroidPlatformAdapter {
        &self.adapter
    }

    fn interfaces(&self) -> &AndroidInterfaceProvider {
        self.adapter.interface_provider()
    }

    fn network(&self) -> &AndroidNetworkConfig {
        self.adapter.network()
    }

    fn tunnel(&self) -> &AndroidTunnelDevice {
        self.adapter.tunnel_device()
    }

    /// One `Network`, as `ConnectivityManager` currently describes it.
    ///
    /// Called from `onAvailable`, `onCapabilitiesChanged` and
    /// `onLinkPropertiesChanged` — Android delivers whole current states, and
    /// [`crate::netchange::diff`] is what turns them into the seam's deltas.
    ///
    /// `payload` is **untrusted input** (§6 rule 9): every bound is checked in
    /// [`wire::decode_network`] before anything proportional to a declared
    /// length is allocated.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] on a malformed payload or a full
    /// tracked set. The JNI layer turns it into a thrown exception; it never
    /// reaches Kotlin as a `reason_code`.
    pub fn on_network(&self, payload: &[u8]) -> Result<(), PlatformError> {
        let network = wire::decode_network(payload)?;
        // **An empty transport set is "not told yet", not "no transports".**
        //
        // `NetworkCallback.onAvailable(Network)` runs before either half of the
        // network's description has been delivered, so the first observation of
        // the fan-out carries `transportBits(null) == 0`. The underlying-network
        // set is selected by `!transports.has(VPN)`
        // (`netcfg::refresh_underlying_networks`), and an observation whose
        // transports were never observed reads there as "not a VPN".
        //
        // After `Builder.establish()` that unclassified observation is OUR OWN
        // TUNNEL — the watcher removes `NET_CAPABILITY_NOT_VPN`, so the app's
        // own network fans straight back in here — and it was handed to
        // `VpnService.setUnderlyingNetworks` as one of the networks the tunnel
        // runs over. That is the platform being asked to account for a loop, and
        // `bridge::tests::reentrancy` is the reproduction.
        let classified = network.transports.bits() != 0;
        self.interfaces().ingest(network)?;
        // The underlying-network set follows every change, so a handoff does not
        // leave the system accounting against the underlay we have left
        // (`docs/networking.md` §5.4). A failure here is not fatal to the
        // ingest: the fact is recorded either way.
        //
        // Deferred, never dropped: the *fact* is in the snapshot above whatever
        // happens here, and the next callback of the same fan-out carries the
        // capabilities and recomputes the set. Holding the previous, classified
        // answer for those microseconds is the fail-safe direction — a set that
        // is briefly stale costs accounting, a set naming our own tunnel costs
        // correctness.
        if classified {
            let _ = self.network().refresh_underlying_networks();
        }
        Ok(())
    }

    /// `onLost(Network)`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the snapshot lock is poisoned.
    pub fn on_network_lost(&self, handle: u64) -> Result<(), PlatformError> {
        self.interfaces().forget(handle)?;
        let _ = self.network().refresh_underlying_networks();
        Ok(())
    }

    /// `PowerManager.isDeviceIdleMode()` / `isPowerSaveMode()`, and whether the
    /// current default link is metered.
    ///
    /// Two booleans and nothing else. **The decision they feed is the core's**:
    /// ADR-0022 LC-31 lists the responses and LC-32 closes the list of what no
    /// power pressure may ever buy, and neither is decided here.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the snapshot lock is poisoned.
    pub fn on_power(&self, metered: bool, low_power: bool) -> Result<(), PlatformError> {
        self.interfaces().set_power(metered, low_power)
    }

    /// `VpnService.onRevoke()` — another app has become the active VPN.
    ///
    /// ADR-0022's response is normative: *"Tear down our tunnel cleanly; do
    /// **not** fight for the slot; report the competing app."* Tearing down is
    /// this call; **reporting is the core's**, and the code it emits is
    /// [`crate::codes::concurrent_vpn`].
    ///
    /// Note what this entry does *not* take: which app took the slot. Kotlin
    /// reads that from `ConnectivityManager` and reports it as an ordinary
    /// network observation through [`AndroidBridge::on_network`], where it
    /// arrives as a `TRANSPORT_VPN` network and is classified
    /// [`twinvpn_platform::iface::LinkClass::Tunnel`] by
    /// [`crate::netchange::link_class`] — a fact, not a verdict.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the handle table is poisoned.
    pub fn on_revoked(&self) -> Result<(), PlatformError> {
        // The system has already closed the descriptor; this makes our own
        // bookkeeping agree with the platform's, so `claim_in_force` stops
        // reporting a claim that no longer exists. `installed_ruleset` then
        // answers `None` -- rules genuinely absent, which is the truth.
        if let Some(handle) = self.tunnel().established_handle() {
            let device = self.tunnel().clone();
            // `destroy_interface` is a `BoxFuture` that never yields before it
            // finishes: it takes a lock, removes the slot and drops the
            // descriptor. Polling it once is therefore complete, and doing so
            // avoids requiring a runtime on the JNI callback thread -- which is
            // an arbitrary Android binder thread, not one of ours.
            poll_to_completion(device.destroy_interface(handle))?;
        }
        Ok(())
    }

    /// What a DPC or managed configuration reported about always-on lockdown.
    ///
    /// `None` — no DPC, no managed configuration, or a managed configuration
    /// with no such key — is [`crate::posture::LockdownPosture::Unverified`],
    /// which **presents as unprotected** (ADR-0022 LC-40). There is no probe
    /// entry on this bridge and there must not be one: under lockdown our own
    /// sockets are the permitted ones, so a reachability test proves nothing.
    pub fn on_lockdown_report(&self, reported: Option<bool>) {
        self.network().set_lockdown_report(reported);
    }
}

/// Polls a future that is known not to yield, once.
///
/// Used only for [`AndroidBridge::on_revoked`]'s teardown, whose future takes a
/// lock and drops a descriptor with no await point that can pend. A future that
/// *did* pend would return [`PlatformError::Transient`] rather than block a
/// binder thread — which is the failure the caller can retry and the alternative
/// is an ANR.
fn poll_to_completion<T>(
    mut future: futures_core::future::BoxFuture<'_, Result<T, PlatformError>>,
) -> Result<T, PlatformError> {
    use std::task::{Context, Poll};
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(PlatformError::Transient(Some(
            crate::oserr::detail_from_code(libc::EWOULDBLOCK, "bridge.teardown"),
        ))),
    }
}

#[cfg(test)]
mod tests;
