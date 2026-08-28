//! The relay engine — the glue that owns the tables, the limits and the drain.
//!
//! Everything here is **in memory** (S-29) and everything decides from parameters
//! rather than from a clock, so a decision is reproducible from its inputs
//! (architecture §5.2 R-DET-1) and every boundary is testable without sleeping.
//!
//! The engine is deliberately **not** `async`. Admission, binding, forwarding and
//! drain scheduling are pure state transitions; only [`crate::net`] awaits, and
//! it awaits a socket. That split is I5 made structural: a component that never
//! `.await`s cannot acquire a network dependency without a visible signature
//! change (see `token::verify`'s note).

use std::net::SocketAddr;
use std::time::Instant;

use crate::condition::Condition;
use crate::config::{AdminState, RelayConfig};
use crate::crypto::{LegKey, RelayCrypto};
use crate::drain::DrainPlan;
use crate::epoch::EpochFloor;
use crate::flow::{BindOutcome, FlowId, PairTable, PairTag};
use crate::forward::{ForwardRefusal, Forwarded, Forwarder};
use crate::frame::RelayFrame;
use crate::issuer::IssuerKeySet;
use crate::replay::ReplayCache;
use crate::resource::{Ceilings, CookieGate, Limiter};
use crate::token::{verify, PresentedToken, VerifiedToken, VerifyContext};

/// What a `BIND` produced.
#[derive(Debug, PartialEq, Eq)]
pub enum BindResult {
    /// A pending slot exists; the partner has 30 s to arrive.
    Pending(FlowId),
    /// Both peers may now be sent `BOUND{flow_id}`.
    Bound {
        /// The arriving half-flow's handle.
        flow_id: FlowId,
        /// The waiting half-flow's handle.
        peer_flow_id: FlowId,
    },
    /// Refused, with a condition that maps to a registered reason code.
    Refused(Condition),
}

/// The relay's whole runtime state.
pub struct RelayEngine {
    config: RelayConfig,
    issuers: IssuerKeySet,
    floor: EpochFloor,
    table: PairTable,
    limiter: Limiter,
    cookies: CookieGate,
    replay: ReplayCache,
    drain: Option<DrainPlan>,
    /// The monotonic base the millisecond-valued packet path is measured from.
    /// Set once, on first use, so a rate decision is a pure function of the
    /// caller's `now_ms` thereafter.
    bucket_epoch: Option<Instant>,
}

impl std::fmt::Debug for RelayEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayEngine")
            .field("relay_id", &self.config.relay_id_hex)
            .field("region", &self.config.region_id)
            .field("issuers", &self.issuers.len())
            .field("epoch_floor", &self.floor.current())
            .field("bound", &self.table.bound_count())
            .field("pending", &self.table.pending_count())
            .field("draining", &self.drain.is_some())
            .finish()
    }
}

impl RelayEngine {
    /// Builds an engine from validated configuration and a loaded key set.
    #[must_use]
    pub fn new(config: RelayConfig, issuers: IssuerKeySet, starting_epoch: u64) -> Self {
        let ceilings = Ceilings {
            max_flows_per_subject: config.max_flows_per_subject,
            rate_per_subject_mbps: config.rate_per_subject_mbps,
            rate_per_flow_mbps: config.rate_per_flow_mbps,
            quota_bytes_per_hour: config.quota_bytes_per_hour,
            bind_per_minute_per_subject: config.bind_per_minute_per_subject,
        };
        let max_subjects = config
            .max_total_flows
            .checked_div(usize::try_from(config.max_flows_per_subject.max(1)).unwrap_or(1))
            .unwrap_or(1)
            .max(1)
            // A subject may hold one flow, so the subject table must be able to
            // hold as many subjects as there are flows.
            .max(config.max_total_flows);
        Self {
            table: PairTable::new(
                config.pending_slot_ttl_ms,
                config.idle_flow_timeout_ms,
                config.max_total_flows,
            ),
            limiter: Limiter::new(ceilings, max_subjects),
            cookies: CookieGate::new(config.cookie_threshold_handshakes_per_s, 65_536),
            replay: ReplayCache::frozen_default(),
            floor: EpochFloor::starting_at(starting_epoch),
            issuers,
            drain: None,
            bucket_epoch: None,
            config,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// The held issuer key set.
    #[must_use]
    pub const fn issuers(&self) -> &IssuerKeySet {
        &self.issuers
    }

    /// The trust-epoch floor, mutably, for a piggybacked advance.
    pub const fn floor_mut(&mut self) -> &mut EpochFloor {
        &mut self.floor
    }

    /// The flow table.
    #[must_use]
    pub const fn table(&self) -> &PairTable {
        &self.table
    }

    /// Whether a handshake from `peer` may proceed without a cookie challenge.
    pub fn allows_handshake(&mut self, peer: SocketAddr, now: Instant) -> bool {
        self.cookies.allows_handshake(peer.ip(), now)
    }

    /// Verifies a presented token, offline.
    ///
    /// # Errors
    ///
    /// The [`Condition`] that refused it.
    pub fn admit(
        &mut self,
        presented: &PresentedToken,
        presented_leg_key: &[u8],
        crypto: &dyn RelayCrypto,
        now_ms: u64,
    ) -> Result<VerifiedToken, Condition> {
        let ctx = VerifyContext {
            operator_group_id: &self.config.operator_group_id,
            issuers: &self.issuers,
            floor: &self.floor,
            presented_leg_key,
            now_ms,
            clock_skew_ms: self.config.token_clock_skew_ms,
        };
        verify(presented, &ctx, crypto, &mut self.replay)
    }

    /// Handles a `BIND` from an admitted device.
    pub fn bind(
        &mut self,
        tag: PairTag,
        peer: SocketAddr,
        token: &VerifiedToken,
        now: Instant,
        now_ms: u64,
    ) -> BindResult {
        // A draining or retired relay accepts no new binds, but keeps carrying
        // what it already has until the deadline it announced (ADR-0005 §8).
        if self.drain.is_some() || self.config.admin_state != AdminState::Active {
            return BindResult::Refused(Condition::Draining);
        }
        if let Err(c) = self.limiter.admit_bind(token.subject(), token.quota(), now) {
            return BindResult::Refused(c);
        }
        match self.table.bind(tag, peer, token.subject(), now_ms) {
            BindOutcome::Pending { flow_id } => BindResult::Pending(flow_id),
            BindOutcome::Bound {
                flow_id,
                peer_flow_id,
            } => BindResult::Bound {
                flow_id,
                peer_flow_id,
            },
            BindOutcome::Collision => {
                self.limiter.release_flow(token.subject());
                BindResult::Refused(Condition::PairCollision)
            }
            BindOutcome::RelayFull => {
                self.limiter.release_flow(token.subject());
                BindResult::Refused(Condition::Overloaded)
            }
        }
    }

    /// Forwards a `DATA` frame, metering the egress subject's quota.
    ///
    /// # Errors
    ///
    /// [`ForwardRefusal`] — every variant a silent drop.
    pub fn forward(
        &mut self,
        frame: &RelayFrame,
        ingress_key: &LegKey,
        egress_key: &LegKey,
        crypto: &dyn RelayCrypto,
        now_ms: u64,
    ) -> Result<Forwarded, ForwardRefusal> {
        let out = Forwarder::new(crypto).forward(
            frame,
            &mut self.table,
            ingress_key,
            egress_key,
            now_ms,
        )?;
        // Quota is charged after a successful forward. A refused frame costs the
        // subject nothing, so an off-path injector cannot exhaust a victim's
        // hourly budget with frames that never arrive.
        //
        // A spent hourly budget is NOT a silent drop: §11.5 requires a
        // RELAY_STATUS on the affected flow, so it is surfaced as a distinct
        // refusal for `pump` to answer rather than swallowed here.
        if self
            .limiter
            .charge_bytes(out.egress_subject, out.payload_len as u64, now_ms)
            .is_err()
        {
            return Err(ForwardRefusal::QuotaExceeded);
        }
        Ok(out)
    }

    /// Whether `subject` may send now, or must be throttled.
    ///
    /// ADR-0005 §11.5 says **throttle, not drop**, so a `Deferred` result is a
    /// queueing instruction plus a `RELAY_STATUS`, never a discard. `pump` acts
    /// on both halves.
    pub fn admit_bytes(
        &mut self,
        subject: crate::subject::RelaySub,
        now_ms: u64,
    ) -> twinvpn_service_common::transport::Admission {
        // The token bucket takes an `Instant`; the pump has milliseconds. A
        // monotonic base plus the offset keeps the decision reproducible from its
        // inputs (architecture §5.2 R-DET-1) without reading a clock here.
        let base = *self.bucket_epoch.get_or_insert_with(Instant::now);
        self.limiter
            .admit_bytes(subject, base + std::time::Duration::from_millis(now_ms))
    }

    /// Expires pending slots and idle flows. Returns `(unmatched, idle)`.
    pub fn collect(&mut self, now_ms: u64) -> (usize, usize) {
        self.table.collect(now_ms)
    }

    /// Begins a herd-safe drain and returns the flows to announce it to.
    ///
    /// Idempotent: a second call returns the same plan and no new flows, because
    /// a device that receives two deadlines has been given two draws.
    pub fn begin_drain(&mut self, now_ms: u64, deadline_ms: u64) -> (DrainPlan, Vec<FlowId>) {
        if let Some(existing) = &self.drain {
            return (existing.clone(), Vec::new());
        }
        let mut plan = DrainPlan::new(now_ms, deadline_ms);
        let flows = self.table.bound_flow_ids();
        for f in &flows {
            plan.announce_to(*f);
        }
        self.drain = Some(plan.clone());
        (plan, flows)
    }

    /// Whether the relay is draining.
    #[must_use]
    pub const fn is_draining(&self) -> bool {
        self.drain.is_some()
    }

    /// Whether the relay must still carry traffic — its half of herd safety.
    #[must_use]
    pub fn still_carrying(&self, now_ms: u64) -> bool {
        self.drain.as_ref().is_none_or(|p| p.still_carrying(now_ms))
    }

    /// Drops every flow, as a restart does. Nothing was ever written anywhere.
    pub fn simulate_restart(&mut self) -> usize {
        self.table.drop_everything()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::TokenClaims;
    use crate::crypto::FailClosed;
    use crate::token::testkit::{claims, good_envelope, Doubles};
    use twinvpn_service_common::config::MapEnv;

    /// The engine's tests exercise binding, drain and metering, not signature
    /// arithmetic, so they share `token::testkit`'s double. `provider.rs` tests
    /// the real `twinvpn-crypto` binding separately.
    fn always_ok() -> Doubles {
        let mut c = claims();
        c.epoch = 3;
        c.not_before_ms = 0;
        c.not_after_ms = 86_400_000;
        Doubles::new(c)
    }

    fn always_ok_with(edit: impl FnOnce(&mut TokenClaims)) -> Doubles {
        let mut c = claims();
        c.epoch = 3;
        c.not_before_ms = 0;
        c.not_after_ms = 86_400_000;
        edit(&mut c);
        Doubles::new(c)
    }

    fn config() -> RelayConfig {
        RelayConfig::load(
            &MapEnv::new()
                .with("TWINVPN_RELAY_ID", "0000000000000a01")
                .with("TWINVPN_RELAY_REGION", "local-1")
                .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
                .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
                .with(
                    "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                )
                .with(
                    "TWINVPN_RELAY_STATIC_KEY_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                ),
        )
        .expect("loads")
    }

    fn issuers(populated: bool) -> IssuerKeySet {
        let raw = if populated {
            r#"{"operator_group_id":"local-operator","issuers":[{"key_id":"k1","alg":"Ed25519","cose_key_hex":"0102"}]}"#
        } else {
            r#"{"operator_group_id":"local-operator","issuers":[]}"#
        };
        IssuerKeySet::parse(raw, "local-operator", "x").expect("parses")
    }

    fn token() -> PresentedToken {
        PresentedToken::new("k1".into(), good_envelope())
    }

    /// The leg key `token::testkit::claims()` binds `cnf` to.
    const LEG: &[u8] = b"RLK-cose-key";

    fn engine(populated: bool) -> RelayEngine {
        RelayEngine::new(config(), issuers(populated), 3)
    }

    fn tag(n: u8) -> PairTag {
        PairTag::from_wire(&[n; 16]).expect("16")
    }

    fn addr(port: u16) -> SocketAddr {
        format!("[::1]:{port}").parse().expect("addr")
    }

    #[test]
    fn an_empty_issuer_set_admits_no_one() {
        let mut e = engine(false);
        assert_eq!(
            e.admit(&token(), LEG, &always_ok(), 1_000).unwrap_err(),
            Condition::IssuerUnknown
        );
    }

    #[test]
    fn the_fail_closed_crypto_provider_admits_no_one() {
        let mut e = engine(true);
        assert_eq!(
            e.admit(&token(), LEG, &FailClosed, 1_000).unwrap_err(),
            Condition::TokenInvalid
        );
    }

    #[test]
    fn an_admitted_device_binds_and_a_second_completes_the_pair() {
        let mut e = engine(true);
        let now = Instant::now();
        let v1 = e
            .admit(&token(), LEG, &always_ok(), 1_000)
            .expect("admitted");
        assert!(matches!(
            e.bind(tag(1), addr(1), &v1, now, 1_000),
            BindResult::Pending(_)
        ));
        let second = always_ok_with(|c| {
            c.jti = [2; 16];
            c.subject = [8; 16];
        });
        let v2 = e.admit(&token(), LEG, &second, 1_000).expect("admitted");
        assert!(matches!(
            e.bind(tag(1), addr(2), &v2, now, 1_000),
            BindResult::Bound { .. }
        ));
    }

    #[test]
    fn a_draining_relay_refuses_new_binds_but_keeps_carrying() {
        let mut e = engine(true);
        let now = Instant::now();
        let v = e
            .admit(&token(), LEG, &always_ok(), 1_000)
            .expect("admitted");
        let _ = e.bind(tag(1), addr(1), &v, now, 1_000);

        let (plan, flows) = e.begin_drain(1_000, 120_000);
        assert_eq!(plan.deadline_ms(), 120_000);
        assert!(flows.is_empty(), "only BOUND flows are announced to");

        let second = always_ok_with(|c| c.jti = [2; 16]);
        let v2 = e.admit(&token(), LEG, &second, 1_000).expect("admitted");
        assert_eq!(
            e.bind(tag(2), addr(2), &v2, now, 1_000),
            BindResult::Refused(Condition::Draining)
        );
        assert!(
            e.still_carrying(120_999),
            "the relay honours the deadline it announced"
        );
        assert!(!e.still_carrying(121_000));
    }

    #[test]
    fn drain_is_idempotent_so_no_device_gets_two_draws() {
        let mut e = engine(true);
        let now = Instant::now();
        let v = e
            .admit(&token(), LEG, &always_ok(), 1_000)
            .expect("admitted");
        let _ = e.bind(tag(1), addr(1), &v, now, 1_000);
        let second = always_ok_with(|c| {
            c.jti = [2; 16];
            c.subject = [8; 16];
        });
        let v2 = e.admit(&token(), LEG, &second, 1_000).expect("admitted");
        let _ = e.bind(tag(1), addr(2), &v2, now, 1_000);

        let (_, first) = e.begin_drain(1_000, 120_000);
        assert_eq!(first.len(), 2, "both half-flows of the bound pair");
        let (_, second) = e.begin_drain(1_000, 120_000);
        assert!(second.is_empty());
    }

    #[test]
    fn a_restart_kills_every_flow_and_the_engine_survives() {
        let mut e = engine(true);
        let now = Instant::now();
        let v = e
            .admit(&token(), LEG, &always_ok(), 1_000)
            .expect("admitted");
        let _ = e.bind(tag(1), addr(1), &v, now, 1_000);
        assert_eq!(e.simulate_restart(), 1);
        assert_eq!(e.table().half_flow_count(), 0);
    }

    #[test]
    fn a_pending_slot_expires_and_the_engine_reports_it() {
        let mut e = engine(true);
        let now = Instant::now();
        let v = e
            .admit(&token(), LEG, &always_ok(), 1_000)
            .expect("admitted");
        let _ = e.bind(tag(1), addr(1), &v, now, 1_000);
        assert_eq!(e.collect(1_000 + 30_000), (1, 0));
    }

    #[test]
    fn the_engine_never_awaits() {
        // I5, structurally: none of admit, bind, forward or collect is async, so
        // none of them can hold a network dependency. Changing that changes the
        // signature and every caller, which is the point.
        type Admit = fn(
            &mut RelayEngine,
            &PresentedToken,
            &[u8],
            &dyn RelayCrypto,
            u64,
        ) -> Result<VerifiedToken, Condition>;
        let f: Admit = RelayEngine::admit;
        let _ = f;
    }
}
