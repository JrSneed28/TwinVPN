//! The socket half: the thin driver that gives a leg something to speak on.
//!
//! **Authority:** ADR-0018 CB-1 (the join between a decision and a mechanism is
//! the core's), CB-2 (with every shell deleted and a mock bound, the core must
//! still make every decision), §11.6 (the seam), CD-1 (every deadline on the
//! injected monotonic clock); `twinvpn_platform::socket`'s own contract —
//! *"the adapter imposes no timeout of its own. A caller composes one from
//! `twinvpn_env::Timer`, so every deadline in the system runs on the injected
//! monotonic clock rather than on a timeout the platform chose."*
//!
//! # Why this is separate from [`super::leg`]
//!
//! Everything in [`super::leg`] is a pure step function over octets: given a
//! datagram, what does it mean, and what datagram goes back. That is what makes
//! the leg testable with no runtime, no socket and no fabric — and it is the
//! shape `services/relay/src/pump.rs` uses on the other end for the same
//! reason. This module is the only place that awaits anything, and it decides
//! nothing.
//!
//! # The receive buffer is sized once, from a constant
//!
//! ADR-0005 §9.1's header plus §9.2's derived payload ceiling is the largest
//! datagram a conforming relay can send on this leg, and
//! [`MAX_RELAY_DATAGRAM_BYTES`] is that sum. Nothing here ever sizes a buffer
//! from a length a peer declared (`ownership.md` §6 rules 9 and 10), and a
//! datagram that did not fit is **reported, never silently truncated** —
//! `Datagram::truncated` exists precisely because "a silently truncated
//! datagram is a message that fails authentication for a reason nobody can
//! see."

use twinvpn_env::{Env, MonotonicInstant};
use twinvpn_platform::error::PlatformError;
use twinvpn_platform::socket::UdpSocket;
use twinvpn_relay_client::frame::{HEADER_LEN, MAX_DATA_PAYLOAD_BYTES};
use twinvpn_types::PairTag;

use super::leg::{LegParams, LegStep, PendingLeg, RelayLeg};
use super::legsetup::is_leg_setup;
use super::outcome::{BindOutcome, Inbound, RelayReject};
use super::sealed::Sealed;

/// The largest datagram a conforming relay can put on this leg.
///
/// Derived, not borrowed: ADR-0005 §9.1's 16-byte header plus §9.2's derived
/// 1 456-byte payload ceiling. Every other carriage and family is smaller.
pub const MAX_RELAY_DATAGRAM_BYTES: usize = HEADER_LEN + MAX_DATA_PAYLOAD_BYTES;

/// Why a leg operation did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LegError {
    /// The relay, or its datagram, was refused. Carries the registered code.
    #[error("relay leg refused: {0}")]
    Rejected(#[from] RelayReject),
    /// The platform refused the send or the receive.
    ///
    /// A **fact about the host**, reported so the caller can decide, never a
    /// reason to substitute another family or another socket.
    #[error("platform refused the relay leg: {0}")]
    Platform(PlatformError),
    /// The caller's deadline passed with no usable answer.
    ///
    /// The deadline is the caller's, on the injected monotonic clock. The
    /// adapter contributed none.
    #[error("no answer from the relay before the deadline")]
    Deadline,
    /// A datagram did not fit [`MAX_RELAY_DATAGRAM_BYTES`].
    ///
    /// Reported rather than truncated: a truncated datagram fails its MAC, and
    /// a MAC failure with no explanation is indistinguishable from an attack.
    #[error("relay datagram exceeded {MAX_RELAY_DATAGRAM_BYTES} B and was not truncated")]
    Oversized,
}

impl LegError {
    /// The registered `reason_code`, where this refusal has one of its own.
    ///
    /// `None` for a platform refusal and for a deadline, because both are
    /// already carried as typed values by the layer that owns them — a
    /// `PlatformError` has its own code, and a deadline is the caller's own
    /// policy rather than a condition the relay reported.
    #[must_use]
    pub const fn reason_code(&self) -> Option<twinvpn_types::ReasonCode> {
        match self {
            LegError::Rejected(r) => Some(r.reason_code()),
            LegError::Oversized => Some(twinvpn_types::codes::PROTO_SIZE_EXCEEDED),
            LegError::Platform(_) | LegError::Deadline => None,
        }
    }
}

/// Opens a leg to one relay: `HANDSHAKE_INIT`, the cookie round trip if the
/// relay demands one, then `HANDSHAKE_RESP` and `K_leg`.
///
/// One code path for both address families (ADR-0010 R1). The family is the
/// endpoint's, the socket is the caller's, and nothing below branches on which
/// of the two it is.
///
/// # The deadline, and what it does not cover
///
/// `deadline` is checked on the injected monotonic clock before each receive,
/// so a relay that answers with a stream of frames this leg cannot use will not
/// hold the caller past it. It does **not** interrupt a receive already in
/// flight: the adapter imposes no timeout and this module adds none, so a
/// caller that must survive a relay which answers *nothing at all* races this
/// future against `env.timer()`. That is the seam's rule, not an omission —
/// composing the timeout at the caller is what keeps every deadline in the
/// system on one clock.
///
/// # Errors
///
/// [`LegError`].
pub async fn open_leg(
    env: &Env,
    socket: &dyn UdpSocket,
    params: LegParams<'_>,
    deadline: MonotonicInstant,
) -> Result<RelayLeg, LegError> {
    let endpoint = params.endpoint;
    let (mut pending, mut datagram) = PendingLeg::begin(env, params)?;
    loop {
        socket
            .send_to(&datagram, &endpoint)
            .await
            .map_err(LegError::Platform)?;

        let received = recv_one(env, socket, deadline).await?;
        // A datagram that is not one of the three leg-setup types cannot be
        // acted on before `K_leg` exists, and is dropped in silence rather than
        // answered — ADR-0005 §11.5's rule, owed to the relay in the same way
        // the relay owes it to us.
        if !is_leg_setup(&received) {
            continue;
        }
        match pending.on_datagram(&received)? {
            LegStep::Established(leg) => return Ok(leg),
            LegStep::Challenged {
                pending: next,
                datagram: retry,
            } => {
                pending = *next;
                datagram = retry;
            }
        }
    }
}

/// Sends a `BIND` and waits for the relay's answer.
///
/// The answer is `BOUND` — pending or bound — or a `RELAY_STATUS` carrying one
/// of the refusals in [`super::Refusal`]. It is never silence: ADR-0005 §11.5,
/// *"a relay that drops without a status frame is a defect."*
///
/// # Errors
///
/// [`LegError`].
pub async fn bind(
    env: &Env,
    socket: &dyn UdpSocket,
    leg: &mut RelayLeg,
    pair_tag: PairTag,
    bucket: u64,
    deadline: MonotonicInstant,
) -> Result<BindOutcome, LegError> {
    let endpoint = leg.endpoint();
    let datagram = leg.bind_datagram(pair_tag, bucket);
    socket
        .send_to(&datagram, &endpoint)
        .await
        .map_err(LegError::Platform)?;

    loop {
        let received = recv_one(env, socket, deadline).await?;
        // Anything the leg refuses is a silent drop, and a `DATA` or `PING`
        // arriving while a `BIND` is outstanding is neither an error nor an
        // answer — the leg may already be carrying another half-flow.
        match leg.on_datagram(&received) {
            Ok(Inbound::Bound(outcome)) => return Ok(outcome),
            Ok(Inbound::Status(refusal)) => return Ok(BindOutcome::Refused(refusal)),
            Ok(_) | Err(_) => {}
        }
    }
}

/// Sends one sealed payload on a bound leg.
///
/// # Errors
///
/// [`LegError`].
pub async fn send_sealed(
    socket: &dyn UdpSocket,
    leg: &mut RelayLeg,
    sealed: &Sealed,
) -> Result<(), LegError> {
    let endpoint = leg.endpoint();
    let datagram = leg.data_datagram(sealed)?;
    socket
        .send_to(&datagram, &endpoint)
        .await
        .map_err(LegError::Platform)?;
    Ok(())
}

/// Receives one datagram and tells the leg what it was.
///
/// # Errors
///
/// [`LegError`].
pub async fn receive(
    env: &Env,
    socket: &dyn UdpSocket,
    leg: &mut RelayLeg,
    deadline: MonotonicInstant,
) -> Result<Inbound, LegError> {
    let received = recv_one(env, socket, deadline).await?;
    Ok(leg.on_datagram(&received)?)
}

/// One bounded receive, with the caller's deadline checked on the injected
/// clock first.
async fn recv_one(
    env: &Env,
    socket: &dyn UdpSocket,
    deadline: MonotonicInstant,
) -> Result<Vec<u8>, LegError> {
    if env.now_monotonic().reached(deadline) {
        return Err(LegError::Deadline);
    }
    // Sized from a constant, once, every time. Never from a declared length.
    let mut buf = vec![0_u8; MAX_RELAY_DATAGRAM_BYTES];
    let meta = socket
        .recv_from(&mut buf)
        .await
        .map_err(LegError::Platform)?;
    if meta.truncated {
        return Err(LegError::Oversized);
    }
    buf.truncate(meta.len);
    Ok(buf)
}
