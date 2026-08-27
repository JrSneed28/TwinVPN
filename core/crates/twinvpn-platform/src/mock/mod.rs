//! An in-memory binding of the whole seam. Feature `mock`.
//!
//! **Authority:** ADR-0018 CD-5 —
//!
//! > "The mock adapter is the payoff. Because CB-2 puts every decision in the
//! > core, binding `twinvpn-platform`'s trait to a mock exercises **100% of the
//! > decision logic** on a Linux CI runner with no VM and no device farm. The
//! > transition-coverage merge gate is affordable **because** of the split line,
//! > not despite it."
//!
//! # What this binding is, and is not
//!
//! It **is** a faithful implementation of every contract the traits state:
//! `apply` is all-or-nothing and idempotent on the generation id; `set_ruleset`
//! is an atomic swap and never leaves the rules absent; `destroy_interface` is
//! idempotent; a truncated datagram is reported; a cross-family send is refused;
//! interface changes are events. Every one of those is asserted in
//! `tests/seam.rs`, because a mock that is laxer than the contract lets the core
//! pass tests it would fail on a real adapter.
//!
//! It is **not** a cryptographic implementation. [`MockIdentity`] produces a
//! deterministic **non-cryptographic** tag and refuses to run unless the caller
//! sets [`MockIdentity::allow_insecure_stub_signer`], so a stub signature cannot
//! be mistaken for a real one — and it reports `hardware_backed: false`, truthfully,
//! per ADR-0018 §11.16 (l).
//!
//! # Fault injection
//!
//! Every capability can be made to fail on demand
//! ([`MockAdapter::fail_next_apply`], [`net::MockNetwork::blackhole`], …), so a
//! scenario can exercise the failure path without waiting for a real timeout.
//! That is what makes the hard-to-reach transitions of
//! `docs/testing-strategy.md` §2.2 — T17 `MIGRATING → RECONNECTING` with the old
//! path already dead, T33 `FAILED → DISCOVERING` — reachable at all.

pub mod net;
mod state;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub use net::{MockInterfaces, MockNetwork, MockSockets};
pub use state::{MockConfig, MockIdentity, MockStore, MockTunnel};

use crate::config::{NetworkConfig, TunnelDevice};
use crate::custody::{IdentityCustody, SecureStore};
use crate::iface::InterfaceProvider;
use crate::socket::{SocketProvider, SupportedFamilies};
use crate::PlatformAdapter;

/// A complete in-memory platform.
pub struct MockAdapter {
    sockets: MockSockets,
    tunnel: MockTunnel,
    config: MockConfig,
    interfaces: MockInterfaces,
    identity: MockIdentity,
    store: MockStore,
    shutting_down: Arc<AtomicBool>,
}

/// How to build a [`MockAdapter`].
#[derive(Debug, Clone)]
pub struct MockOptions {
    /// Which socket shapes this mock host offers.
    ///
    /// Set `v6: false` to model a v4-only host and `v4: false` to model an
    /// IPv6-only one — both first-class situations under ADR-0010 §11.7, and both
    /// reachable here without a network.
    pub supported_families: SupportedFamilies,
    /// Where the datapath runs (`KernelOffload` or `Userspace`).
    pub datapath: crate::config::Datapath,
    /// Whether the installed ruleset would survive a core crash (CB-6).
    pub enforcement_survives_core_exit: bool,
    /// Whether the record AEAD is platform-performed (CB-6a). `false` — the
    /// software-held path — is the common case on 8 of 10 real targets.
    pub platform_performs_record_aead: bool,
}

impl Default for MockOptions {
    fn default() -> Self {
        Self {
            supported_families: SupportedFamilies {
                v4: true,
                v6: true,
                dual_stack_socket: true,
            },
            datapath: crate::config::Datapath::Userspace,
            enforcement_survives_core_exit: true,
            platform_performs_record_aead: false,
        }
    }
}

impl MockAdapter {
    /// Builds a mock on its own private network.
    #[must_use]
    pub fn new(options: &MockOptions) -> Self {
        Self::on_network(&MockNetwork::new(), options)
    }

    /// Builds a mock on a shared [`MockNetwork`], so two adapters can talk.
    #[must_use]
    pub fn on_network(network: &MockNetwork, options: &MockOptions) -> Self {
        let shutting_down = Arc::new(AtomicBool::new(false));
        Self {
            sockets: MockSockets {
                network: network.clone(),
                supported: options.supported_families,
                shutting_down: Arc::clone(&shutting_down),
                opened: AtomicU64::new(0),
            },
            tunnel: MockTunnel::new(options.datapath),
            config: MockConfig::new(
                options.enforcement_survives_core_exit,
                Arc::clone(&shutting_down),
            ),
            interfaces: MockInterfaces::new(),
            identity: MockIdentity::new(),
            store: MockStore::new(options.platform_performs_record_aead),
            shutting_down,
        }
    }

    /// The socket provider, for assertions and fault injection.
    #[must_use]
    pub fn sockets_mock(&self) -> &MockSockets {
        &self.sockets
    }

    /// The interface provider, for injecting change events.
    #[must_use]
    pub fn interfaces_mock(&self) -> &MockInterfaces {
        &self.interfaces
    }

    /// The configuration surface, for asserting applied generations.
    #[must_use]
    pub fn config_mock(&self) -> &MockConfig {
        &self.config
    }

    /// The tunnel device.
    #[must_use]
    pub fn tunnel_mock(&self) -> &MockTunnel {
        &self.tunnel
    }

    /// The identity custody stub.
    #[must_use]
    pub fn identity_mock(&self) -> &MockIdentity {
        &self.identity
    }

    /// The secure store.
    #[must_use]
    pub fn store_mock(&self) -> &MockStore {
        &self.store
    }

    /// Makes the next `apply` fail, leaving the previous generation intact.
    ///
    /// The all-or-nothing contract is what a caller most needs to be able to
    /// test, and it is unreachable on a real adapter without a hostile kernel.
    pub fn fail_next_apply(&self, error: crate::PlatformError) {
        self.config.fail_next_apply(error);
    }
}

impl PlatformAdapter for MockAdapter {
    fn sockets(&self) -> &dyn SocketProvider {
        &self.sockets
    }

    fn tunnel(&self) -> &dyn TunnelDevice {
        &self.tunnel
    }

    fn network_config(&self) -> &dyn NetworkConfig {
        &self.config
    }

    fn interfaces(&self) -> &dyn InterfaceProvider {
        &self.interfaces
    }

    fn identity(&self) -> &dyn IdentityCustody {
        &self.identity
    }

    fn store(&self) -> &dyn SecureStore {
        &self.store
    }

    fn binding_name(&self) -> &'static str {
        "mock-in-memory"
    }

    fn begin_shutdown(&self) {
        // CB-6: shutting down does NOT tear down enforcement. The installed
        // ruleset stays in the OS's custody so the core going away cannot drop
        // protection — and the mock models that rather than tidying up.
        self.shutting_down.store(true, Ordering::Release);
    }
}
