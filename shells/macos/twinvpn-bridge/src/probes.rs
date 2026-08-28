//! The facts §11.6's start sequence asks, answered against this host.
//!
//! **Authority:** ADR-0016 §11.6, §11.2's macOS row, PS-7, PS-11, PS-17, PS-18;
//! ADR-0012 §8, KS-20; `ownership.md` §8 **W-24**, **W-43**.
//!
//! Every method is a **fact**. [`crate::start`] decides what each fact means,
//! and it is that decision — not these lookups — that the tests exercise, on a
//! host with no macOS.

use crate::config::ExtensionConfig;
use crate::start::StartProbes;

/// The probes, filled in as each thing is attempted.
// Five booleans, and each is a distinct fact §11.6 asks about on its own line:
// the clocks, the runtime's I/O driver, the enforcement read-back, the core and
// the endpoint are five different steps with five different refusals.
// Collapsing them into a bitflags type would make "which step refused" — the one
// thing a diagnostic bundle needs — invisible.
#[allow(clippy::struct_excessive_bools)]
pub struct ExtensionProbes {
    config: ExtensionConfig,
    posture: Option<twinvpn_platform_macos::AdapterPosture>,
    read_back: bool,
    core_ready: bool,
    endpoint_ready: bool,
    clocks_bind: bool,
    runtime_has_io: bool,
}

impl ExtensionProbes {
    /// Builds a probe set with nothing yet attempted.
    #[must_use]
    pub const fn new(config: ExtensionConfig) -> Self {
        Self {
            config,
            posture: None,
            read_back: false,
            core_ready: false,
            endpoint_ready: false,
            clocks_bind: false,
            runtime_has_io: false,
        }
    }

    /// Records the adapter's declared posture.
    pub fn with_posture(&mut self, posture: twinvpn_platform_macos::AdapterPosture) {
        self.posture = Some(posture);
    }

    /// Records the **read-back**, which is the only thing that may set this.
    ///
    /// Deliberately not `set_reclaimed(true)` at the point of a successful load:
    /// W-24's whole complaint is that a flag set after `Ok` is not an assertion.
    pub fn with_read_back(&mut self, assertion: &twinvpn_platform_macos::pfread::Assertion) {
        self.read_back = assertion.supports(twinvpn_platform::Ruleset::Blocked)
            || assertion.supports(twinvpn_platform::Ruleset::Protected);
    }

    /// Records that the clocks and the CSPRNG bound.
    pub fn with_clocks(&mut self, bound: bool) {
        self.clocks_bind = bound;
    }

    /// Records that the injected runtime has an I/O driver (W-43).
    pub fn with_runtime_io(&mut self, present: bool) {
        self.runtime_has_io = present;
    }

    /// Records that the core constructed.
    pub fn with_core(&mut self, ready: bool) {
        self.core_ready = ready;
    }

    /// Records that the endpoint bound.
    pub fn with_endpoint(&mut self, ready: bool) {
        self.endpoint_ready = ready;
    }
}

impl StartProbes for ExtensionProbes {
    fn boot_artifact_installed(&self) -> bool {
        self.config.boot_anchor.exists()
    }

    fn is_root(&self) -> bool {
        effective_uid() == Some(0)
    }

    fn under_supervisor(&self) -> bool {
        // A system extension is started by `systemextensionsd` and NE, never by
        // hand and never from a login item, so the supervisor is present by
        // construction here in a way it was not for a `LaunchDaemon` a developer
        // could run from a shell. PS-11's warning still exists — it is just
        // unreachable on this binding, and saying so is better than a probe that
        // looks for a `launchd` variable that a sysext does not get.
        true
    }

    fn clocks_bind(&self) -> bool {
        self.clocks_bind
    }

    fn runtime_has_io(&self) -> bool {
        self.runtime_has_io
    }

    fn enforcement_available(&self) -> bool {
        self.posture.is_some_and(|p| p.pfctl_present)
    }

    fn ks9_complete(&self) -> bool {
        self.posture.is_some_and(|p| p.ks9_complete)
    }

    fn enforcement_read_back(&self) -> bool {
        self.read_back
    }

    fn vault_ready(&self) -> bool {
        twinvpn_platform_macos::MacosSecureStore::root_is_owner_only(&self.config.store_root)
    }

    fn core_ready(&self) -> bool {
        self.core_ready
    }

    fn endpoint_ready(&self) -> bool {
        self.endpoint_ready
    }
}

/// This process's **effective** uid, without `unsafe`.
///
/// # Why not `libc::geteuid`
///
/// This crate *may* use `unsafe` (DP-4), and its budget is deliberately spent
/// where nothing else will do: the FFI entry points and
/// `getsockopt(LOCAL_PEERCRED)`. A uid is answerable through a safe API, so it
/// is — and the safe answer has a property the syscall does not: it fails if the
/// process cannot write at all, which is a fact worth having.
///
/// Returns `None` when the probe file could not be created, which the caller
/// treats as "not root" — the closed direction.
#[must_use]
pub fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let path = std::env::temp_dir().join(format!("twinvpn-uid-probe-{}", std::process::id()));
    let uid = {
        let file = std::fs::File::create(&path).ok()?;
        file.metadata().ok()?.uid()
    };
    let _ = std::fs::remove_file(&path);
    Some(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_read_back_is_the_only_thing_that_can_set_the_reclaim_probe() {
        // W-24: a flag set after a load returned `Ok` is not an assertion. The
        // only mutator here takes an `Assertion`, and an assertion that supports
        // neither posture leaves the probe false.
        let mut probes = ExtensionProbes::new(ExtensionConfig::defaults());
        assert!(!StartProbes::enforcement_read_back(&probes));
        probes.with_read_back(&twinvpn_platform_macos::pfread::Assertion {
            status: twinvpn_platform_macos::pfread::PfStatus::Disabled,
            installed: None,
        });
        assert!(
            !StartProbes::enforcement_read_back(&probes),
            "a disabled filter supports no assertion"
        );
    }

    #[test]
    fn the_extension_binding_reports_ks9_complete_once_the_adapter_is_built() {
        // The posture is the ADAPTER's answer, not a constant here. This asserts
        // the wiring: a probe that returned `true` without an adapter would be
        // claiming a predicate nobody configured.
        let mut probes = ExtensionProbes::new(ExtensionConfig::defaults());
        assert!(!StartProbes::ks9_complete(&probes), "nothing built yet");
        let adapter = crate::config::build_adapter(
            &ExtensionConfig::defaults(),
            crate::config::extension_carriers(
                std::sync::Arc::new(crate::host::NoResolver),
                String::new(),
            ),
        );
        probes.with_posture(adapter.posture());
        assert!(StartProbes::ks9_complete(&probes));
    }

    #[test]
    fn nothing_is_true_before_it_is_attempted() {
        // PS-18's shape: a probe set with nothing done must not report a host
        // that is ready. Every fact defaults to the closed direction.
        let probes = ExtensionProbes::new(ExtensionConfig::defaults());
        assert!(!StartProbes::clocks_bind(&probes));
        assert!(!StartProbes::runtime_has_io(&probes));
        assert!(!StartProbes::enforcement_available(&probes));
        assert!(!StartProbes::enforcement_read_back(&probes));
        assert!(!StartProbes::core_ready(&probes));
        assert!(!StartProbes::endpoint_ready(&probes));
    }
}
