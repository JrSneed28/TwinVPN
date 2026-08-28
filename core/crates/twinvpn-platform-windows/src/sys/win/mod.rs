//! The Windows syscall shim: **the only part of this crate that calls Windows**.
//!
//! **Authority:** ADR-0018 CB-1 (code belongs here "if and only if it must call
//! a platform API with no stable C-callable form"), CB-3, CD-2, DP-4;
//! `docs/implementation/ownership.md` §6.
//!
//! # Nothing in this module has ever been linked, loaded or executed
//!
//! It was written on a Linux host. `make cross-check` type-checks it against the
//! real `windows-sys` for `x86_64-pc-windows-msvc` with `-D warnings`, which is
//! a genuine compile proof and is **not** a behaviour proof. Every statement
//! below about what an API does is a statement about what its documentation says
//! it does, and several are recorded as uncertainties in this domain's report
//! rather than asserted.
//!
//! # What lives here, and what deliberately does not
//!
//! | Here | Above, and target-free |
//! |---|---|
//! | `FwpmFilterAdd0`, `FwpmFilterEnum0`, the transaction | which filters a contract implies, and what the engine's answer means |
//! | `CreateIpForwardEntry2`, `GetIpForwardTable2` | which rows a contract implies, and how a rollback inverts them |
//! | the `DnsPolicyConfig` registry writes | which NRPT rules a `DnsConfig` implies |
//! | nothing else | the whole apply/rollback/reconcile state machine |
//!
//! That split is why 220 tests run on a host that cannot execute a line of this
//! file. It is the discipline `twinvpn-platform-linux` applies to `nft.rs`.
//!
//! # The constant assertions
//!
//! [`crate::oserr`] declares every `WIN32_ERROR`, `WSAE*`, `FWP_E_*` and `NTE_*`
//! value as a **literal**, so its mapping compiles and its tests run on Linux.
//! Its module doc promises those literals are checked against `windows-sys`'s
//! own constants here — and [`constants`] is that promise kept. They are `const`
//! assertions, so a drifted value is a **compile failure under
//! `make cross-check`**, with nothing running and nobody having to notice.

pub mod addr;
pub mod constants;
pub mod ip;
pub mod nrpt;
pub mod wfp;

use crate::route::InterfaceLuid;
use crate::shutdown::ShutdownLatch;
use crate::sys::{FilterEngine, InterfaceTable, Resolver, RouteTable, SystemOps};
use twinvpn_platform::PlatformError;

/// A `String` as a null-terminated UTF-16 buffer.
///
/// Every Windows API in this shim takes one, and every one of them reads until
/// the terminator — so the terminator is appended here, once, rather than at
/// twenty call sites where one could be forgotten.
#[must_use]
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// A UTF-16 slice as a `String`, stopping at the first null.
///
/// Lossy on an unpaired surrogate rather than failing: a registry value or an
/// adapter name that Windows will render is not a value this crate should refuse
/// to read, and the alternative is a resolver read that fails because somebody
/// named a search domain with an unpaired surrogate.
#[must_use]
pub fn wide_from_utf16(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// The real system, assembled once at construction (CD-2).
///
/// One object rather than four injected separately, for the reason
/// [`SystemOps`] gives: a component that assembled its system access from
/// independently-supplied pieces could not state which system it was talking to.
pub struct WindowsSystem {
    filters: wfp::LazyEngine,
    routes: ip::IpHelper,
    resolver: nrpt::NrptResolver,
    interfaces: crate::iface::WindowsInterfaceProvider,
}

impl WindowsSystem {
    /// Binds the real system.
    ///
    /// # Why the engine is opened lazily, and why that is not a weakening
    ///
    /// `FwpmEngineOpen0` can fail — ADR-0016 §11.2 rejects `LocalService` and
    /// `NetworkService` precisely because neither can open the engine for write
    /// — and PS-18 requires that failure to be a **startup refusal** rather than
    /// a service that runs while unable to arm enforcement.
    ///
    /// This constructor is infallible because [`crate::WindowsPlatformAdapter`]
    /// is, and that file is not this domain's to change. The refusal is not
    /// lost: [`wfp::LazyEngine`] opens on first use and returns the open error
    /// from whichever call needed it, and the **first** call the service makes
    /// is `reclaim`, at step 6 of ADR-0016 §11.6's start sequence. So the
    /// failure still stops the start, one call later than it should, and the
    /// `reason_code` is the same one `FwpmEngineOpen0` produced.
    ///
    /// **The preferred fix is one line in `lib.rs`**, which this domain reports
    /// rather than makes: have `WindowsPlatformAdapter::new` return a `Result`
    /// and call [`Self::open`], which fails where PS-18 wants it to.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filters: wfp::LazyEngine::new(),
            routes: ip::IpHelper::new(),
            resolver: nrpt::NrptResolver::new(),
            // **A reported seam mismatch.** The interface provider takes the
            // adapter's shutdown latch (CD-2), and this constructor has none to
            // give it, so it gets a fresh one — which means `begin_shutdown` on
            // the adapter does not stop an in-flight enumeration. Harmless
            // today (enumeration is a bounded query with no side effect) and
            // wrong in principle; [`Self::open`] takes the latch and is the
            // constructor a corrected `lib.rs` should call.
            interfaces: crate::iface::WindowsInterfaceProvider::new(ShutdownLatch::new()),
        }
    }

    /// Opens the filter engine eagerly and binds the rest.
    ///
    /// The constructor PS-18 wants: a service that cannot open the engine finds
    /// out here, before it has reported itself as running.
    ///
    /// # Errors
    ///
    /// Whatever `FwpmEngineOpen0` refused.
    pub fn open(shutdown: ShutdownLatch) -> Result<Self, PlatformError> {
        Ok(Self {
            filters: wfp::LazyEngine::opened(wfp::WfpEngine::open()?),
            routes: ip::IpHelper::new(),
            resolver: nrpt::NrptResolver::new(),
            interfaces: crate::iface::WindowsInterfaceProvider::new(shutdown),
        })
    }

    /// The overlay's LUID, for a caller that has the concrete type.
    ///
    /// Present so a shell can pass the same identifier to the enforcement layer
    /// and the route table without re-deriving it from a name — a rename race is
    /// how a Tier-2 permit ends up authorising the wrong interface.
    #[must_use]
    pub const fn overlay_from(luid: u64) -> InterfaceLuid {
        InterfaceLuid(luid)
    }

    // ---- the engine operations, forwarded -------------------------------
    //
    // `SystemOps::filters()` is the seam's way in and is what `netcfg` uses.
    // These four exist beside it for the two callers that hold the concrete
    // type and have no reason to import a trait to reach it: the on-Windows
    // integration tests, and `twinvpn-unblock` — whose whole job is
    // `purge`, and which ADR-0012 KS-20a requires to work when the service
    // will not start, i.e. with none of the seam assembled.

    /// Installs a whole filter set in one transaction.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused, as a registered `reason_code`.
    pub fn commit(&self, set: &crate::wfp::FilterSet) -> Result<(), PlatformError> {
        FilterEngine::commit(&self.filters, set)
    }

    /// Enumerates what the engine holds — the W-24 read-back.
    ///
    /// # There is deliberately no inherent `read`
    ///
    /// `FilterEngine::read` takes no argument and `RouteTable::read` takes an
    /// interface, and `WindowsSystem` answers for both. An inherent `read` would
    /// shadow one of them, and implementing both traits on this type would make
    /// `system.read(..)` ambiguous rather than resolving by arity — Rust picks
    /// candidates by name, not by how many arguments follow.
    ///
    /// So the read-backs are reached the way the seam intends and the way
    /// `netcfg` reaches them:
    ///
    /// ```ignore
    /// let engine = system.filters().read()?;          // the WFP read-back
    /// let routes = system.routes().read(overlay)?;    // the IP Helper one
    /// ```
    ///
    /// # Errors
    ///
    /// A failed query is an error, never a remembered value.
    pub fn engine_state(&self) -> Result<crate::wfp::readback::EngineState, PlatformError> {
        FilterEngine::read(&self.filters)
    }

    /// Drains the net-event window, and says whether the engine dropped any.
    ///
    /// # Errors
    ///
    /// Whatever the enumeration refused.
    pub fn net_events(&self) -> Result<(Vec<crate::wfp::canary::NetEvent>, bool), PlatformError> {
        FilterEngine::net_events(&self.filters)
    }

    /// Removes every owner-tagged object.
    ///
    /// KS-20a's offline unblock, and PS-21 step 5. **Never** part of ordinary
    /// shutdown: CB-6 puts the ruleset in the OS's custody precisely so the core
    /// going away does not drop protection.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused.
    pub fn purge(&self) -> Result<(), PlatformError> {
        FilterEngine::purge(&self.filters)
    }
}

impl Default for WindowsSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemOps for WindowsSystem {
    fn filters(&self) -> &dyn FilterEngine {
        &self.filters
    }

    fn routes(&self) -> &dyn RouteTable {
        &self.routes
    }

    fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }

    fn interfaces(&self) -> &dyn InterfaceTable {
        &self.interfaces
    }
}
