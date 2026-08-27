//! The composed control-plane client.
//!
//! **Authority:** ADR-0002 §11 (the whole decision), `docs/architecture.md` §4.2
//! and §4.4, ADR-0018 CD-2 (`Env` at construction).
//!
//! # What this type is, and what it deliberately is not
//!
//! It is the state machine that walks the ladder, holds the cursor, admits
//! events, and mints envelopes. It is **not** a session manager, a path manager,
//! or anything that knows a `Tunnel` exists: CD-I5 forbids this crate from
//! naming a data-plane crate, and `architecture.md` §4.2 forbids the data plane
//! from holding a reference to any control-plane client. Everything this client
//! learns leaves through [`crate::ports::ControlPlaneStore`] and nowhere else.
//!
//! That is not merely a policy — it is ADR-0002 §11.8 step 1's structural
//! argument for I5: *"every message defined here terminates at the control-plane
//! client, which writes only to the store."*

use core::time::Duration;
use std::sync::Arc;

use twinvpn_env::Env;
use twinvpn_types::TwinnetId;

use crate::cursor::{plan_resume, Cursor, ResumeOutcome};
use crate::error::{CpError, CpResult};
use crate::events::{admit, Admitted};
use crate::freshness::{next_backoff, Drain, FreshnessTracker, InfrastructureBackoff};
use crate::health::ChannelHealth;
use crate::metadata::MetadataFactory;
use crate::transport::{
    AttachFamilies, ControlConnection, ControlTransport, Rung, TransportConfig, TransportError,
};

/// Everything the client needs at construction. CD-2: no global, no ambient
/// default, no partial constructor.
pub struct ClientParts {
    /// The injected environment — the only source of time, timers and randomness.
    pub env: Env,
    /// The L-CONTROL binding.
    pub transport: Arc<dyn ControlTransport>,
    /// The `TwinNet` this client is scoped to. Every message is `TwinNet`-scoped.
    pub twinnet_id: TwinnetId,
    /// This device's `"twd1…"` text form, for `MessageMetadata.sender_id`.
    pub sender_id: String,
    /// Where to reach the control plane, as names.
    pub coordination_endpoints: Vec<String>,
    /// Which address families the host has.
    pub families: AttachFamilies,
    /// The durable cursor, restored from the store before construction.
    pub cursor: Cursor,
    /// Whether the process is in mobile background.
    pub mobile_background: bool,
}

/// The control-plane client.
pub struct ControlPlaneClient {
    env: Env,
    transport: Arc<dyn ControlTransport>,
    twinnet_id: TwinnetId,
    sender_id: String,
    coordination_endpoints: Vec<String>,
    families: AttachFamilies,
    mobile_background: bool,
    cursor: Cursor,
    health: ChannelHealth,
    backoff: InfrastructureBackoff,
    freshness: FreshnessTracker,
}

impl ControlPlaneClient {
    /// Binds a client. Every capability arrives here (CD-2).
    #[must_use]
    pub fn new(parts: ClientParts) -> Self {
        Self {
            env: parts.env,
            transport: parts.transport,
            twinnet_id: parts.twinnet_id,
            sender_id: parts.sender_id,
            coordination_endpoints: parts.coordination_endpoints,
            families: parts.families,
            mobile_background: parts.mobile_background,
            cursor: parts.cursor,
            health: ChannelHealth::Detached,
            backoff: InfrastructureBackoff::new(),
            freshness: FreshnessTracker::new(),
        }
    }

    /// The current channel health.
    #[must_use]
    pub const fn health(&self) -> ChannelHealth {
        self.health
    }

    /// The durable cursor.
    #[must_use]
    pub const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// How the stream should be opened for the current cursor.
    #[must_use]
    pub const fn resume_plan(&self) -> ResumeOutcome {
        plan_resume(self.cursor)
    }

    /// Walks the ADR-0002 §11.2 ladder, rung by rung, in order.
    ///
    /// Each rung that is entered below rung 1 emits its own code, so a fall-through
    /// is **individually observable** (RQ-2). Exhausting the ladder yields
    /// `CONTROL.UNREACHABLE` — "the control plane, entirely, and **nothing
    /// else**".
    ///
    /// # Errors
    ///
    /// [`CpError::Unreachable`] once every rung is exhausted,
    /// [`CpError::HandshakeRejected`] on an mTLS refusal (which does **not** fall
    /// through: a rejected key is rejected on every rung, and retrying three more
    /// times only makes the ladder look flaky), and
    /// [`CpError::AdmissionDeferred`] carrying the server's `retry_after_ms`.
    pub async fn attach(&mut self) -> CpResult<Box<dyn ControlConnection>> {
        let mut rung = Some(Rung::Quic);
        let mut degraded_codes = Vec::new();
        while let Some(current) = rung {
            let config = TransportConfig::new(
                self.coordination_endpoints.clone(),
                self.families,
                current,
                self.mobile_background,
            );
            if config.admissible().is_err() {
                rung = current.next();
                continue;
            }
            if let Some(code) = current.entry_code() {
                degraded_codes.push(code);
                tracing::info!(
                    reason_code = code.as_str(),
                    rung = current.number(),
                    "control channel entering a degraded rung"
                );
            }
            match self.transport.attach(&config).await {
                Ok(connection) => {
                    self.health = ChannelHealth::Attached {
                        rung: connection.rung(),
                    };
                    self.backoff.reset();
                    tracing::info!(
                        rung = connection.rung().number(),
                        proto_version = connection.proto_version(),
                        "control channel attached"
                    );
                    return Ok(connection);
                }
                // A rejected identity is rejected on every rung. Falling through
                // would turn one legible AUTH failure into four transport ones.
                Err(TransportError::HandshakeRejected) => {
                    self.health = ChannelHealth::Unreachable;
                    return Err(CpError::HandshakeRejected);
                }
                // The server named a number; honour it rather than choosing one.
                Err(TransportError::AdmissionDeferred { retry_after_ms }) => {
                    return Err(CpError::AdmissionDeferred { retry_after_ms })
                }
                Err(TransportError::Draining { drain_deadline_ms }) => {
                    self.health = ChannelHealth::Draining;
                    return Err(CpError::AdmissionDeferred {
                        retry_after_ms: Drain::from_millis(drain_deadline_ms)
                            .deadline
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                    });
                }
                Err(TransportError::Superseded) => return Err(CpError::SupersededByNewAttach),
                Err(TransportError::RungFailed(_) | TransportError::Closed) => {
                    rung = current.next();
                }
            }
        }
        self.health = ChannelHealth::Unreachable;
        tracing::warn!(
            reason_code = "CONTROL.UNREACHABLE",
            rungs_tried = Rung::LADDER.len(),
            "every ladder rung exhausted; established sessions are unaffected"
        );
        Err(CpError::Unreachable)
    }

    /// Waits the decorrelated-jitter interval before the next attach.
    ///
    /// Runs on [`twinvpn_env::Timer`] and the suspend-exclusive monotonic clock,
    /// so a laptop closed for eight hours does not wake up and fire an accrued
    /// backlog of reattach timers.
    ///
    /// # Errors
    ///
    /// [`CpError::Env`] if the jitter stream cannot be opened.
    pub async fn wait_before_reattach(&mut self) -> CpResult<Duration> {
        let delay = next_backoff(&self.env, &mut self.backoff)?;
        self.env.timer().sleep(delay).await;
        Ok(delay)
    }

    /// A metadata factory bound to one connection's fixed `proto_version`.
    #[must_use]
    pub fn metadata_factory(&self, proto_version: u32) -> MetadataFactory {
        MetadataFactory::new(
            self.env.clone(),
            proto_version,
            self.twinnet_id.clone(),
            self.sender_id.clone(),
        )
    }

    /// Admits one decoded C2 event against the current cursor.
    ///
    /// Does **not** advance the cursor: ADR-0009 R-9 requires the durable
    /// high-water write to land before the event's effect is acted on, so the
    /// caller applies the effect, persists, and then calls
    /// [`ControlPlaneClient::commit_cursor`].
    ///
    /// # Errors
    ///
    /// Everything [`crate::events::admit`] can return, including
    /// [`CpError::EventWrongPublisher`] — which must be handled as a security
    /// event and not as a stream hiccup.
    pub fn admit_event(&self, event: &twinvpn_schema::v1::ControlEvent) -> CpResult<Admitted> {
        let admitted = admit(event, self.cursor.from_net_seq());
        if let Err(ref err) = admitted {
            if err.is_security_event() {
                tracing::error!(
                    reason_code = err.reason_code().as_str(),
                    security_event = true,
                    "rejected a C2 event as a security event"
                );
            }
        }
        admitted
    }

    /// Moves the cursor after the durable write succeeded.
    pub const fn commit_cursor(&mut self, net_seq: u64) {
        self.cursor.commit(net_seq);
    }

    /// Records a `LogHead` whose signature verified and whose window is open.
    pub fn record_freshness_proof(&mut self) {
        self.freshness.record_valid(self.env.now_monotonic());
    }

    /// The freshness diagnostic, if three intervals have passed.
    ///
    /// **Never a trust input.** A missing proof means cached documents approach
    /// expiry; it never admits anything and never withdraws baseline
    /// reachability.
    #[must_use]
    pub fn freshness_diagnostic(&self) -> Option<CpError> {
        self.freshness.overdue(self.env.now_monotonic())
    }

    /// Marks the channel unreachable without walking the ladder again.
    ///
    /// Used when a live connection drops and the caller is going to back off
    /// rather than retry immediately.
    pub const fn mark_unreachable(&mut self) {
        self.health = ChannelHealth::Unreachable;
    }

    /// Begins graceful shutdown of this client's use of the environment.
    ///
    /// `ownership.md` §6 rule 7. The injected runtime refuses new spawns and lets
    /// running work finish; a refused spawn is reported, never dropped.
    pub fn begin_shutdown(&self) {
        self.env.begin_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::{ChannelHealth, ClientParts, ControlPlaneClient};
    use crate::cursor::{Cursor, ResumeOutcome};
    use crate::testing::{test_env, RecordingTransport};
    use crate::transport::{AttachFamilies, Rung, TransportError};
    use std::sync::Arc;
    use twinvpn_types::TwinnetId;

    /// `Box<dyn ControlConnection>` is not `Debug` — deliberately, a connection
    /// handle is not a thing to render — so `expect`/`expect_err` are unavailable
    /// and these two helpers stand in for them.
    fn ok(
        outcome: crate::CpResult<Box<dyn crate::transport::ControlConnection>>,
    ) -> Box<dyn crate::transport::ControlConnection> {
        match outcome {
            Ok(connection) => connection,
            Err(err) => panic!("expected an attach, got {err:?}"),
        }
    }

    fn err_of(
        outcome: crate::CpResult<Box<dyn crate::transport::ControlConnection>>,
    ) -> crate::CpError {
        match outcome {
            Ok(_) => panic!("expected a refusal, got an attached connection"),
            Err(err) => err,
        }
    }

    /// Every test shares ONE `Env` with the client it drives. Two envs means two
    /// virtual clocks, and a timer armed on one is never advanced by the other —
    /// which presents as a hang rather than as a mistake.
    fn client(
        env: &twinvpn_env::Env,
        transport: Arc<RecordingTransport>,
        cursor: Cursor,
    ) -> ControlPlaneClient {
        ControlPlaneClient::new(ClientParts {
            env: env.clone(),
            transport,
            twinnet_id: TwinnetId::new("tn-alpha").expect("valid"),
            sender_id: "twd1abc".to_owned(),
            coordination_endpoints: vec!["cp.example".to_owned()],
            families: AttachFamilies {
                v4: true,
                v6: true,
                nat64: false,
            },
            cursor,
            mobile_background: false,
        })
    }

    fn block_on<F>(env: &twinvpn_env::Env, fut: F) -> F::Output
    where
        F: core::future::Future + Send,
        F::Output: Send,
    {
        let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = std::sync::Arc::clone(&cell);
        env.runtime().block_on(Box::pin(async move {
            let out = fut.await;
            *sink.lock().expect("not poisoned") = Some(out);
        }));
        let mut guard = cell.lock().expect("not poisoned");
        guard.take().expect("the future completed")
    }

    #[test]
    fn health_never_withdraws_the_data_planes_ability_to_reconnect() {
        for state in [
            ChannelHealth::Detached,
            ChannelHealth::Attached { rung: Rung::Quic },
            ChannelHealth::Unreachable,
            ChannelHealth::Draining,
        ] {
            assert!(
                state.permits_data_plane_reconnect(),
                "I5: {state:?} may not stop a data-plane reconnect"
            );
        }
    }

    #[test]
    fn rung_one_is_silent_and_lower_rungs_are_named() {
        assert!(ChannelHealth::Attached { rung: Rung::Quic }
            .diagnostic()
            .is_none());
        let degraded = ChannelHealth::Attached {
            rung: Rung::Http2Tcp,
        }
        .diagnostic()
        .expect("named");
        assert_eq!(
            degraded.reason_code().as_str(),
            "CONTROL.TRANSPORT_DEGRADED_TCP"
        );
        let out = ChannelHealth::Unreachable.diagnostic().expect("named");
        assert_eq!(out.reason_code().as_str(), "CONTROL.UNREACHABLE");
        assert!(!out.reason_code().terminal(), "an outage is not terminal");
    }

    #[test]
    fn the_ladder_falls_through_to_the_last_rung() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::failing_until(Rung::Proxy));
        let mut c = client(&env, Arc::clone(&transport), Cursor::COLD_START);
        let attached = ok(block_on(&env, c.attach()));
        assert_eq!(attached.rung(), Rung::Proxy);
        assert_eq!(
            transport.attempts(),
            vec![Rung::Quic, Rung::Http2Tcp, Rung::Http1LongPoll, Rung::Proxy]
        );
        assert_eq!(c.health(), ChannelHealth::Attached { rung: Rung::Proxy });
    }

    #[test]
    fn an_exhausted_ladder_is_unreachable_and_nothing_more() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::always_failing());
        let mut c = client(&env, Arc::clone(&transport), Cursor::restored(500));
        let err = err_of(block_on(&env, c.attach()));
        assert_eq!(err.reason_code().as_str(), "CONTROL.UNREACHABLE");
        assert!(
            err.permits_offline_reconnect(),
            "a total outage never withdraws baseline reachability"
        );
        assert_eq!(c.health(), ChannelHealth::Unreachable);
        // And the cursor survives, so the next attach RESUMES rather than reloads.
        assert_eq!(c.resume_plan(), ResumeOutcome::Resume { from_net_seq: 500 });
    }

    #[test]
    fn a_rejected_handshake_does_not_pretend_to_be_a_transport_problem() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::rejecting_handshake());
        let mut c = client(&env, Arc::clone(&transport), Cursor::COLD_START);
        let err = err_of(block_on(&env, c.attach()));
        assert_eq!(err.reason_code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
        assert_eq!(
            transport.attempts(),
            vec![Rung::Quic],
            "a rejected key is rejected on every rung; falling through hides it"
        );
    }

    #[test]
    fn admission_deferral_carries_the_servers_own_number() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::deferring(1_750));
        let mut c = client(&env, transport, Cursor::COLD_START);
        let err = err_of(block_on(&env, c.attach()));
        match err {
            crate::CpError::AdmissionDeferred { retry_after_ms } => {
                assert_eq!(retry_after_ms, 1_750);
            }
            other => panic!("expected a deferral, got {other:?}"),
        }
    }

    #[test]
    fn a_mobile_background_device_skips_rung_three() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::failing_until(Rung::Proxy));
        let mut c = ControlPlaneClient::new(ClientParts {
            env: env.clone(),
            transport: Arc::clone(&transport) as Arc<dyn crate::transport::ControlTransport>,
            twinnet_id: TwinnetId::new("tn-alpha").expect("valid"),
            sender_id: "twd1abc".to_owned(),
            coordination_endpoints: vec!["cp.example".to_owned()],
            families: AttachFamilies {
                v4: false,
                v6: true,
                nat64: true,
            },
            cursor: Cursor::COLD_START,
            mobile_background: true,
        });
        let attached = ok(block_on(&env, c.attach()));
        assert_eq!(attached.rung(), Rung::Proxy);
        assert_eq!(
            transport.attempts(),
            vec![Rung::Quic, Rung::Http2Tcp, Rung::Proxy],
            "rung 3 is prohibited as a background binding on mobile"
        );
    }

    #[test]
    fn reattach_waits_a_bounded_jittered_interval() {
        let env = test_env();
        let transport = Arc::new(RecordingTransport::always_failing());
        let mut c = client(&env, transport, Cursor::COLD_START);
        let delay = block_on(&env, c.wait_before_reattach()).expect("jitter");
        assert!(delay >= core::time::Duration::from_millis(500));
        assert!(delay <= core::time::Duration::from_secs(30));
    }

    #[test]
    fn transport_errors_map_onto_registered_codes() {
        assert_eq!(
            crate::CpError::from(TransportError::Closed)
                .reason_code()
                .as_str(),
            "CONTROL.UNREACHABLE"
        );
        assert_eq!(
            crate::CpError::from(TransportError::Superseded)
                .reason_code()
                .as_str(),
            "CONTROL.SUPERSEDED_BY_NEW_ATTACH"
        );
    }
}
