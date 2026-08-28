//! Deterministic test doubles for this crate's seams. **Never shipped.**
//!
//! Gated behind `test-support`, exactly as `twinvpn-env`'s `virtual_time` and
//! `twinvpn-platform`'s `mock` are (CD-5, `core/README.md` §3). Everything here
//! runs on [`twinvpn_env::virtual_time::VirtualTime`], so an eight-hour outage
//! scenario costs no wall time and reproduces exactly.

use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{
    ConsumerId, Entropy, Env, EnvError, EnvParts, Rng, RngSource, WallClockReading, WallMillis,
};
use twinvpn_types::ChannelBinding;

use crate::octets::ReceivedOctets;
use crate::ports::{StatementKind, StatementVerifier, VerifiedStatement, VerifyFailure};
use crate::transport::{
    ControlConnection, ControlTransport, EventStream, Rung, TransportConfig, TransportError,
};

/// A counter-based `Entropy`.
///
/// Reproducible, and **obviously** not cryptographic — the name says so at every
/// call site so it can never be mistaken for a production binding. `twinvpn-env`
/// ships no production `Entropy` for the same reason: a silent downgrade there is
/// indistinguishable from working.
#[derive(Debug, Default)]
pub struct CountingEntropy {
    next: Mutex<u64>,
}

impl CountingEntropy {
    /// A fresh counter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: Mutex::new(1),
        }
    }
}

impl Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut guard = self.next.lock().map_err(|_| EnvError::EntropyUnavailable)?;
        for byte in dst.iter_mut() {
            // A cheap full-period LCG: enough to make distinct draws distinct,
            // and deliberately not a CSPRNG.
            *guard = guard
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            #[allow(clippy::cast_possible_truncation)]
            {
                *byte = (*guard >> 33) as u8;
            }
        }
        Ok(())
    }
}

/// An `RngSource` over [`CountingEntropy`], with no CD-4 derivation.
#[derive(Debug)]
pub struct CountingRngSource {
    entropy: Arc<CountingEntropy>,
}

impl CountingRngSource {
    /// A fresh source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entropy: Arc::new(CountingEntropy::new()),
        }
    }
}

impl Default for CountingRngSource {
    fn default() -> Self {
        Self::new()
    }
}

struct CountingRng {
    entropy: Arc<CountingEntropy>,
}

impl Rng for CountingRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // The trait's `fill_bytes` is infallible, and the counter cannot fail
        // except on a poisoned lock — which in a test is a panic worth having.
        self.entropy.fill(dst).expect("counter entropy");
    }
}

impl RngSource for CountingRngSource {
    fn rng_for(&self, _consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        Ok(Box::new(CountingRng {
            entropy: Arc::clone(&self.entropy),
        }))
    }

    fn is_deterministic(&self) -> bool {
        // Reproducible, but NOT a seeded CD-4 source: TwinLab asserts
        // `is_deterministic` before declaring a BIT scenario, and this source
        // does not derive per-consumer streams, so it must not claim to.
        false
    }
}

/// A virtual-clock `Env` with a resolved wall clock.
///
/// The wall clock is `Trusted` rather than `Unset` because several checks here
/// evaluate a validity window, and CD-1a makes that unconstructible from `Unset`
/// by design.
#[must_use]
pub fn test_env() -> Env {
    let vt = VirtualTime::new(WallClockReading::Trusted {
        millis: WallMillis::from_millis(1_800_000_000_000),
    });
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(CountingEntropy::new()),
        rng: Arc::new(CountingRngSource::new()),
    })
}

/// A virtual-clock `Env` plus the driver, for scenarios that advance time.
#[must_use]
pub fn test_env_with_clock() -> (Env, VirtualTime) {
    let vt = VirtualTime::new(WallClockReading::Trusted {
        millis: WallMillis::from_millis(1_800_000_000_000),
    });
    let env = Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(CountingEntropy::new()),
        rng: Arc::new(CountingRngSource::new()),
    });
    (env, vt)
}

/// How a scripted transport should answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportScript {
    /// Fail every rung above `succeed_at`, then attach.
    SucceedAt(Rung),
    /// Fail every rung. This is a **total control-plane outage**.
    Blackhole,
    /// Refuse the mTLS handshake on the first rung tried.
    RejectHandshake,
    /// Answer with the accept limiter engaged.
    Defer(u64),
}

/// A `ControlTransport` that records which rungs were tried.
pub struct RecordingTransport {
    script: TransportScript,
    attempts: Mutex<Vec<Rung>>,
}

impl RecordingTransport {
    /// Fails every rung above `rung`, then attaches.
    #[must_use]
    pub fn failing_until(rung: Rung) -> Self {
        Self {
            script: TransportScript::SucceedAt(rung),
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Attaches on rung 1.
    #[must_use]
    pub fn healthy() -> Self {
        Self::failing_until(Rung::Quic)
    }

    /// A total outage — every rung blackholed.
    #[must_use]
    pub fn always_failing() -> Self {
        Self {
            script: TransportScript::Blackhole,
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Refuses the handshake.
    #[must_use]
    pub fn rejecting_handshake() -> Self {
        Self {
            script: TransportScript::RejectHandshake,
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Engages the accept limiter with `retry_after_ms`.
    #[must_use]
    pub fn deferring(retry_after_ms: u64) -> Self {
        Self {
            script: TransportScript::Defer(retry_after_ms),
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Which rungs were tried, in order.
    ///
    /// # Panics
    ///
    /// If the recording mutex was poisoned by a panic in another test thread —
    /// which is a failure worth surfacing rather than papering over.
    #[must_use]
    pub fn attempts(&self) -> Vec<Rung> {
        self.attempts.lock().expect("not poisoned").clone()
    }
}

impl ControlTransport for RecordingTransport {
    fn attach<'a>(
        &'a self,
        config: &'a TransportConfig,
    ) -> BoxFuture<'a, Result<Box<dyn ControlConnection>, TransportError>> {
        let rung = config.rung;
        self.attempts.lock().expect("not poisoned").push(rung);
        // Nothing may enable early data. Asserted here so a binding that ignored
        // the type would still be caught by any scenario that attaches.
        assert_eq!(
            config.early_data(),
            crate::transport::EarlyData::Prohibited,
            "ADR-0001 R8: 0-RTT is prohibited on L-CONTROL"
        );
        let script = self.script;
        Box::pin(async move {
            match script {
                TransportScript::SucceedAt(target) if rung == target => {
                    Ok(Box::new(ScriptedConnection::new(rung)) as Box<dyn ControlConnection>)
                }
                TransportScript::SucceedAt(_) | TransportScript::Blackhole => {
                    Err(TransportError::RungFailed(rung))
                }
                TransportScript::RejectHandshake => Err(TransportError::HandshakeRejected),
                TransportScript::Defer(retry_after_ms) => {
                    Err(TransportError::AdmissionDeferred { retry_after_ms })
                }
            }
        })
    }
}

/// A connection that answers from a script.
pub struct ScriptedConnection {
    rung: Rung,
    binding: [u8; 32],
    proto_version: u32,
    responses: Mutex<Vec<Vec<u8>>>,
    events: Mutex<Vec<Vec<u8>>>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl ScriptedConnection {
    /// A connection on `rung` with an empty script.
    #[must_use]
    pub fn new(rung: Rung) -> Self {
        Self {
            rung,
            binding: [0x5a; 32],
            proto_version: 1,
            responses: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Queues one C1 response body.
    ///
    /// # Panics
    ///
    /// If the script mutex was poisoned.
    pub fn push_response(&self, body: Vec<u8>) {
        self.responses.lock().expect("not poisoned").push(body);
    }

    /// Queues one C2 event body.
    ///
    /// # Panics
    ///
    /// If the script mutex was poisoned.
    pub fn push_event(&self, body: Vec<u8>) {
        self.events.lock().expect("not poisoned").push(body);
    }

    /// The request bodies this connection was asked to send.
    ///
    /// # Panics
    ///
    /// If the recording mutex was poisoned.
    #[must_use]
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("not poisoned").clone()
    }

    /// The exporter value this connection reports.
    #[must_use]
    pub fn binding_bytes(&self) -> [u8; 32] {
        self.binding
    }
}

impl ControlConnection for ScriptedConnection {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::from_array(self.binding)
    }

    fn rung(&self) -> Rung {
        self.rung
    }

    fn proto_version(&self) -> u32 {
        self.proto_version
    }

    fn request<'a>(
        &'a self,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<ReceivedOctets, TransportError>> {
        self.requests
            .lock()
            .expect("not poisoned")
            .push(body.to_vec());
        Box::pin(async move {
            let mut queue = self.responses.lock().expect("not poisoned");
            if queue.is_empty() {
                Err(TransportError::Closed)
            } else {
                Ok(ReceivedOctets::from_wire_owned(queue.remove(0)))
            }
        })
    }

    fn subscribe(
        &self,
        _from_net_seq: u64,
    ) -> BoxFuture<'_, Result<Box<dyn EventStream>, TransportError>> {
        let queued = self.events.lock().expect("not poisoned").clone();
        Box::pin(async move { Ok(Box::new(ScriptedStream { queued }) as Box<dyn EventStream>) })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

struct ScriptedStream {
    queued: Vec<Vec<u8>>,
}

impl EventStream for ScriptedStream {
    fn next(&mut self) -> BoxFuture<'_, Option<Result<ReceivedOctets, TransportError>>> {
        Box::pin(async move {
            if self.queued.is_empty() {
                None
            } else {
                Some(Ok(ReceivedOctets::from_wire_owned(self.queued.remove(0))))
            }
        })
    }
}

/// A verifier that accepts or refuses on command.
///
/// It performs **no cryptography** — CD-I2 forbids this crate a cryptographic
/// dependency, dev-dependencies included. It exists to test that this crate
/// *asks*, and that it refuses when the answer is no.
pub struct ScriptedVerifier {
    verdict: Result<SigningVerdict, VerifyFailure>,
}

/// What a [`ScriptedVerifier`] should claim about a statement.
#[derive(Debug, Clone, Copy)]
pub struct SigningVerdict {
    /// The type the payload claims, after verification.
    pub kind: StatementKind,
}

impl ScriptedVerifier {
    /// Accepts every statement as `kind`, chained to its required authority.
    #[must_use]
    pub const fn accepting(kind: StatementKind) -> Self {
        Self {
            verdict: Ok(SigningVerdict { kind }),
        }
    }

    /// Refuses every statement with `failure`.
    #[must_use]
    pub const fn refusing(failure: VerifyFailure) -> Self {
        Self {
            verdict: Err(failure),
        }
    }
}

impl StatementVerifier for ScriptedVerifier {
    fn verify(
        &self,
        octets: &ReceivedOctets,
        expected: StatementKind,
    ) -> Result<VerifiedStatement, VerifyFailure> {
        let verdict = self.verdict?;
        if verdict.kind != expected {
            return Err(VerifyFailure::TypeMismatch);
        }
        Ok(VerifiedStatement {
            kind: verdict.kind,
            authority: verdict.kind.required_authority(),
            // The verified payload is the octets that arrived, unchanged. A
            // verifier that returned re-encoded bytes here would be the CF-2
            // defect this crate exists to avoid.
            payload: octets.clone(),
            window: twinvpn_env::ValidityWindow::default(),
        })
    }
}
