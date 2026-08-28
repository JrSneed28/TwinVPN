//! A virtual-time `Env` and the session machine the core-decision rows drive.
//!
//! CD-5's payoff: the machine takes *declared facts* rather than asking the OS,
//! so every one of those rows runs on a plain Linux runner with no VM, no device
//! farm and no network.

use std::sync::Arc;

use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{ConsumerId, Entropy, Env, EnvError, EnvParts, Rng, RngSource, WallClockReading};
use twinvpn_session::{Context, EnforcementMode, Guards, SessionMachine, SessionState};
use twinvpn_types::SessionId;

// ---------------------------------------------------------------------------
// The session machine, on virtual time
// ---------------------------------------------------------------------------

struct CounterRng(u64);

impl Rng for CounterRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for b in dst.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = u8::try_from((self.0 >> 33) & 0xff).expect("masked");
        }
    }
}

struct TestRngSource;

impl RngSource for TestRngSource {
    fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        let seed = consumer
            .as_str()
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            });
        Ok(Box::new(CounterRng(seed)))
    }
    fn is_deterministic(&self) -> bool {
        true
    }
}

struct TestEntropy;

impl Entropy for TestEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        dst.fill(0x5a);
        Ok(())
    }
}

/// A virtual-time `Env`. No wall clock, no real timers, no network.
pub fn test_env() -> Env {
    let vt = Arc::new(VirtualTime::new(WallClockReading::Unset));
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(TestEntropy),
        rng: Arc::new(TestRngSource),
    })
}

/// Guards with everything a healthy establishment needs, and nothing more.
pub fn healthy() -> Guards {
    Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        no_l2_path_won: true,
        no_direct_path_won: true,
        new_path_committed: true,
        retry_budget_available: true,
        enforcement: Some(EnforcementMode::FailClosed),
        relay_set_nonempty: true,
        ..Guards::default()
    }
}

/// An empty transition context.
pub fn context() -> Context {
    Context::default()
}

fn session_id() -> SessionId {
    SessionId::from_array([7u8; 16])
}

/// A machine already on a validated direct path.
pub fn connected_session() -> SessionMachine {
    SessionMachine::resumed(
        test_env(),
        session_id(),
        SessionState::Steady(twinvpn_types::PathClass::WanDirect),
        None,
    )
}

/// Guards for T30: a secure path exists again and enforcement reconciles.
pub fn restored() -> Guards {
    Guards {
        secure_path_established: true,
        enforcement_reconciled: true,
        ..healthy()
    }
}

/// A machine in `BLOCKED`, carrying the code it was entered with.
pub fn blocked_session() -> SessionMachine {
    SessionMachine::resumed(
        test_env(),
        session_id(),
        SessionState::Blocked,
        Some(twinvpn_types::codes::POLICY_KILLSWITCH_ENGAGED),
    )
}

/// A machine restored from the durable journal at `state` (LC-2).
pub fn resumed_session(state: SessionState) -> SessionMachine {
    SessionMachine::resumed(test_env(), session_id(), state, None)
}

/// **CB-2's structural half.** The adapter must name no `ConnectionState`.
///
/// A grep rather than a type check, because the failure this guards against is
/// somebody *adding* one — and the moment they do, the classification the core
/// owns has a second implementation in a platform layer, which is R-31's defect
/// class.
pub fn assert_adapter_names_no_connection_state() {
    for (path, source) in ADAPTER_SOURCES {
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["ConnectionState", "SessionState", "MIGRATING", "Migrating"] {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` appears in {path}: the adapter reports facts and \
                 the core classifies them (CB-2)"
            );
        }
    }
}

/// The adapter modules that decide anything. `codes.rs` is excluded on purpose:
/// it is the substitution table, and naming a `reason_code` is its job.
const ADAPTER_SOURCES: &[(&str, &str)] = &[
    ("builder.rs", include_str!("../../src/builder.rs")),
    ("netcfg.rs", include_str!("../../src/netcfg.rs")),
    ("netchange.rs", include_str!("../../src/netchange.rs")),
    ("posture.rs", include_str!("../../src/posture.rs")),
    ("power.rs", include_str!("../../src/power.rs")),
    ("iface.rs", include_str!("../../src/iface.rs")),
    ("tun.rs", include_str!("../../src/tun.rs")),
    ("sock/mod.rs", include_str!("../../src/sock/mod.rs")),
    ("custody.rs", include_str!("../../src/custody.rs")),
    ("hostcall.rs", include_str!("../../src/hostcall.rs")),
];
