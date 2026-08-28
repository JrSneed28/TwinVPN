//! The client and gateway run loops.
//!
//! **Authority:** ADR-0005 §11.1(3) (two half-flows meet on one `pair_tag`),
//! §11.1(4) (a third `BIND` on a bound tag is refused), ADR-0006 §11.15(b) (a
//! gateway needs a raised `max_binds_per_min`, or a ~15-peer listening ceiling
//! stands), ADR-0013 (a gateway fronts many peers over one tunnel).
//!
//! # What a "simulated client" is, and what it is not
//!
//! It is a **real relay peer**: a real `Noise_IK` leg carrying a real
//! COSE_Sign1 token, real `BIND`s under real `pair_tag`s, real MACed `DATA`
//! frames over a real socket. Everything the relay sees from it is what it
//! would see from a device.
//!
//! It is **not a TwinVPN client**. It runs no L-DATA tunnel, holds no device
//! identity, completes no pairing ceremony and speaks to no control plane. The
//! composition root that would give it those — the QUIC binding for L-CONTROL —
//! does not exist in `core/`, by design: `twinvpn-cp-client`'s transport is a
//! trait because ADR-0018 CB-1 puts the socket at the platform seam, and the
//! crate's own documentation lists binding it as an outstanding integration
//! item. A simulator cannot invent that binding without inventing the product's
//! composition root, so it does not pretend to.
//!
//! The consequence is stated plainly here and in `infra/README.md`: this
//! environment exercises the **data plane's relay path end to end** and the
//! control plane's **health, readiness, storage and observability** surfaces.
//! It does not yet drive a control-plane ceremony from a device.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::admin::SimState;
use crate::device::{BindOutcome, LegOutcome, SimDevice};
use crate::issuer::{DevIssuer, TokenSpec};
use crate::map::RelayEntry;
use crate::pairing::{current_bucket, now_ms, pair_tag_for};

/// The trust epoch the local environment issues at. ADR-0005 §11.3 compares a
/// token's `epoch` against the relay's floor, so this must equal every relay's
/// configured floor or nothing binds.
pub const DEV_EPOCH: u64 = 1;

/// How often a running simulator sends a `DATA` frame.
///
/// Slow on purpose. The relay's quota accounting is per-subject bitrate, and a
/// simulator that saturated it would make every scenario a shed test. Load
/// generation is a *scenario's* job (`twinlab-scenarios`), not the idle
/// behaviour of a background container.
pub const DATA_INTERVAL: Duration = Duration::from_secs(2);

/// How long to wait before re-attempting a leg the relay refused or ignored.
///
/// ADR-0002 §11.7's reconnect discipline is the control plane's; this is the
/// simulator's own backoff and is deliberately flat rather than exponential:
/// a background container that backed off to minutes would look healthy while
/// having stopped exercising anything.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Everything one simulated peer needs.
pub struct PeerConfig {
    /// Which relay to bind.
    pub relay: RelayEntry,
    /// The local address to bind the UDP socket to. `[::]:0` or `0.0.0.0:0`
    /// decides the family the leg runs on, which is what makes the v4-only and
    /// v6-only compose profiles exercise different code.
    pub local: SocketAddr,
    /// The seed for this peer's `RLK` and subject.
    pub seed: String,
    /// The shared secret both halves of a pair derive their `pair_tag` from.
    pub pair_secret: String,
    /// How many `BIND`s this peer drives. One for a client; one per fronted
    /// peer for a gateway.
    pub pairs: u32,
    /// `max_binds_per_min` in the minted token.
    pub max_binds_per_min: u32,
}

/// Runs one simulated peer until the process is stopped.
///
/// The loop is: establish a leg, bind every pair, then send `DATA` and drain
/// inbound frames forever, re-establishing whenever the leg is lost. Readiness
/// tracks the loop's actual state rather than its progress through it.
///
/// # Errors
///
/// A socket that cannot be bound, or a relay map entry that does not parse.
/// A *refusal* is never an error: the loop records it, stays unready, and
/// retries, because a simulator that exited on refusal would take its own
/// metrics down with it at exactly the moment they became interesting.
// 102 lines against clippy's 100. `run_peer` is one peer's whole life — bind,
// leg, token, data, teardown — and the parts read as a sequence because they
// happen in one. Splitting it to satisfy a line count would put five halves of
// one story in five places.
//
// NOTE (test-engineering, twinnet wave): this crate was reformatted by a
// workspace-wide `cargo fmt --all` run from the neighbouring `twinnet` work, and
// this function may have crossed the threshold then. It is flagged here rather
// than silently reflowed, because it is another wave's file.
#[allow(clippy::too_many_lines)]
pub async fn run_peer(
    config: PeerConfig,
    issuer: Arc<DevIssuer>,
    state: Arc<SimState>,
) -> anyhow::Result<()> {
    let relay_addr = config.relay.socket_addr()?;
    let relay_static = config.relay.static_public()?;
    let relay_id = config.relay.relay_id_bytes()?;
    let socket = UdpSocket::bind(config.local).await?;
    socket.connect(relay_addr).await?;
    tracing::info!(
        local = %socket.local_addr()?,
        relay = %relay_addr,
        relay_id = %config.relay.relay_id,
        pairs = config.pairs,
        "simulated peer starting"
    );

    let mut device = SimDevice::new(config.seed.as_bytes())?;
    // Which bucket this peer's tags are currently bound for.
    //
    // A tag is bound ONCE per bucket, not once per loop. ADR-0005 §11.1(4)
    // refuses "a third `BIND` on a bound tag" with `RELAY_STATUS`, so a loop
    // that re-bound every cycle spent the flow's first `BIND` correctly and
    // then generated a refusal every two seconds afterwards — an offered load
    // of pure protocol violations, and a `RELAY_STATUS` count that looked like
    // relay overload. Observed, and this is the fix.
    let mut bound_for: Option<u64> = None;

    loop {
        if !device.has_leg() {
            state.set_ready(false);
            bound_for = None;
            match establish(
                &mut device,
                &socket,
                relay_addr,
                &relay_static,
                &issuer,
                &config,
                &state,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "leg attempt failed");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    device = SimDevice::new(config.seed.as_bytes())?;
                    continue;
                }
            }
        }

        // The bucket rotates every 10 minutes and every tag rotates with it, so
        // this is also the re-`BIND` schedule: a peer that never re-bound would
        // lose its flow at the next rotation and never notice.
        let bucket = current_bucket()?;
        if bound_for != Some(bucket) {
            let mut admitted = false;
            let mut refused_backoff = false;
            for i in 0..config.pairs {
                let tag = pair_tag_for(&config.pair_secret, i, &relay_id, bucket)?;
                match device.bind(&socket, relay_addr, tag, bucket).await? {
                    BindOutcome::Bound => {
                        state.binds_bound.fetch_add(1, Ordering::Relaxed);
                        admitted = true;
                    }
                    BindOutcome::Pending { ttl_ms } => {
                        state.binds_pending.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(ttl_ms, pair = i, "pending: the partner has not arrived");
                        admitted = true;
                    }
                    BindOutcome::Status => {
                        // Backed off, not retried immediately. RELAY_STATUS is
                        // the relay saying "not now" (§11.5 / §11.1(4)), and a
                        // peer that answered it by binding again on the next
                        // tick would turn one refusal into a refusal storm --
                        // adding load to a relay that just said it had too
                        // much. Observed against a relay still holding the tag
                        // from a previous run: six refusals in twelve seconds.
                        state.binds_status.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(pair = i, "RELAY_STATUS: shedding, draining or overloaded");
                        refused_backoff = true;
                    }
                    BindOutcome::Unauthenticated => {
                        // Never folded into loss. An unauthenticated reply is a
                        // relay that stopped signing or a source-address spoof,
                        // and both are findings rather than weather.
                        state.binds_unauthenticated.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(pair = i, "a BIND reply did not verify under K_leg");
                    }
                    BindOutcome::Silent => {}
                }
            }
            if admitted {
                bound_for = Some(bucket);
            }
            // READY means "the relay admitted this peer and gave it a flow",
            // which includes PENDING. A peer whose partner has not arrived yet
            // is doing exactly what it was started to do; requiring BOUND would
            // make the FIRST of a pair to start permanently unready and hold
            // `docker compose up --wait` until the second one raced it.
            state.set_ready(admitted);
            if !admitted && refused_backoff {
                tokio::time::sleep(RETRY_INTERVAL).await;
                continue;
            }
        }

        // One DATA frame per interval, then drain whatever the peer sent back.
        if device.flow_id().is_some() {
            let payload = payload_for(&config.seed, state.data_sent.load(Ordering::Relaxed));
            if let Err(e) = device.send_data(&socket, relay_addr, &payload).await {
                tracing::warn!(error = %e, "DATA send failed");
            } else {
                state.data_sent.fetch_add(1, Ordering::Relaxed);
                state
                    .bytes_sent
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            while let Ok(Some((kind, _))) = device.recv_verified(&socket).await {
                if kind == crate::wire::FrameType::Data {
                    state.data_received.fetch_add(1, Ordering::Relaxed);
                } else {
                    tracing::debug!(frame = kind.name(), "control frame from the relay");
                    break;
                }
            }
        }

        tokio::time::sleep(DATA_INTERVAL).await;
    }
}

/// One leg attempt, recorded by outcome.
async fn establish(
    device: &mut SimDevice,
    socket: &UdpSocket,
    relay_addr: SocketAddr,
    relay_static: &[u8; 32],
    issuer: &DevIssuer,
    config: &PeerConfig,
    state: &SimState,
) -> anyhow::Result<bool> {
    let subject = subject_of(&config.seed);
    let jti = jti_of(&config.seed, now_ms()?);
    let spec = TokenSpec::admitting(*device.rlk_public(), subject, jti, now_ms()?, DEV_EPOCH)
        .as_gateway(config.max_binds_per_min);

    let outcome = device
        .establish(socket, relay_addr, relay_static, issuer, &spec)
        .await?;
    match outcome {
        LegOutcome::Established => {
            state.legs_established.fetch_add(1, Ordering::Relaxed);
        }
        LegOutcome::EstablishedAfterCookie => {
            state.legs_after_cookie.fetch_add(1, Ordering::Relaxed);
        }
        LegOutcome::Refused => {
            state.legs_refused.fetch_add(1, Ordering::Relaxed);
        }
        LegOutcome::Silent => {
            state.legs_silent.fetch_add(1, Ordering::Relaxed);
        }
    }
    tracing::info!(outcome = outcome.name(), "leg attempt");
    Ok(outcome.is_established())
}

/// The `relay_sub` pseudonym. ADR-0005 §11.3 makes it per-operator and
/// per-day, and explicitly **never** a `device_id`.
fn subject_of(seed: &str) -> [u8; 16] {
    let day = now_ms().unwrap_or(0) / 86_400_000;
    let d = twinvpn_crypto::sha256(format!("{seed}|sub|{day}").as_bytes());
    let mut out = [0_u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// 16 bytes for the relay's bounded replay cache. Fresh per attempt: reusing a
/// `jti` is how a token gets refused as a replay, and a simulator that reused
/// one would report a relay bug that is its own.
fn jti_of(seed: &str, now_ms: u64) -> [u8; 16] {
    let d = twinvpn_crypto::sha256(format!("{seed}|jti|{now_ms}").as_bytes());
    let mut out = [0_u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// A payload chosen to be hostile to a forwarder that peeks.
///
/// The relay must forward bytes it cannot interpret (I1), and
/// `twinvpn_service_common::Verbatim::from_opaque` is what lets it. The first
/// octets here decode as a protobuf record with an **unknown field number** —
/// the shape that a forwarder running a parser refuses and a forwarder that
/// does not, carries. Sending only random bytes would never catch that.
fn payload_for(seed: &str, n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // field 15000, wire type 2, length 4 — a well-formed record no schema in
    // this repository declares.
    out.extend_from_slice(&[0xC2, 0xEA, 0x07, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&twinvpn_crypto::sha256(seed.as_bytes()));
    out.resize(256, 0x5A);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_is_protobuf_shaped_with_an_unknown_field() {
        let p = payload_for("s", 0);
        assert_eq!(p.len(), 256);
        // A parser-based forwarder refuses this; an opaque one carries it.
        assert_eq!(&p[..3], &[0xC2, 0xEA, 0x07]);
    }

    #[test]
    fn two_sends_differ_so_a_forwarder_cannot_be_caching() {
        assert_ne!(payload_for("s", 0), payload_for("s", 1));
    }

    #[test]
    fn a_subject_is_sixteen_bytes_and_is_not_the_seed() {
        let s = subject_of("device-a");
        assert_eq!(s.len(), 16);
        assert_ne!(&s[..8], &b"device-a"[..]);
        // Two devices must not share a subject: the relay's per-subject quota
        // would then be shared, and every quota scenario would be wrong.
        assert_ne!(subject_of("device-a"), subject_of("device-b"));
    }

    #[test]
    fn a_jti_is_fresh_per_attempt() {
        // A reused jti is refused as a replay. If this ever held equal, every
        // reconnect after the first would look like a relay bug.
        assert_ne!(jti_of("s", 1_000), jti_of("s", 1_001));
    }
}
