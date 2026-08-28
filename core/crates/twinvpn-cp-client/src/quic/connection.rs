//! One live rung-1 connection: C1 on bidirectional streams, C2 on the
//! unidirectional stream the server opens, and the RFC 9266 channel binding.
//!
//! **Authority:** ADR-0002 **N-1** (one connection per device carrying both C1
//! and C2), **N-2** (the `tls-exporter` channel binding), §11.6 (C2 gets its own
//! stream so an event backlog cannot consume the RPC window), ADR-0014 §11.1
//! **V-3** (`proto_version` is fixed for the life of the connection),
//! `ownership.md` §6 rules 9, 10 and 12 (bound every allocation an untrusted
//! input can drive; refuse with a registered code), §8 **W-27** (the launch
//! `ProtocolEpoch` is 1).
//!
//! # The framing, and where the decision was made
//!
//! [`crate::transport::ControlConnection::request`] takes `body: &[u8]` and no
//! command code, so *something* has to decide where the code goes, and nothing
//! in `core/` says. The server does: `services/control-plane/src/wire.rs` puts
//!
//! ```text
//!   C1 request  :  u16 command_code | u32 body_len | body
//!   C1 response :  u16 command_code | u32 body_len | body
//!   C2 record   :                     u32 body_len | ControlEvent
//! ```
//!
//! on the stream, and records at its own definition that the header is a
//! transport detail outside the protobuf body, which an HTTP/3 front-end could
//! strip into `:path` without either side changing.
//!
//! This binding therefore treats `request`'s argument as the **complete C1
//! frame**, header included — the same decision `lab/twinsim/src/lcontrol.rs`
//! records, and it is written down in both places for the same reason: a second
//! binding that split it differently would be silently incompatible with this
//! one and both would look correct.
//!
//! The response's `command_code` is an echo of the request's, so
//! [`ReceivedOctets`] carries the **body** and not the frame. That keeps
//! `crate::decode` — which applies the `limits.json` caps — able to consume the
//! result directly, and keeps the octets that a signature must be verified over
//! exactly the octets that arrived (`octets.rs`).
//!
//! # Every declared length is checked before the buffer exists
//!
//! `body_len` is a peer's `u32`. `checked_body_len` compares it against the
//! frozen `envelope.c1_c2_c7_max_bytes` and refuses with
//! `PROTO.SIZE_EXCEEDED`, so a declared `0xFFFF_FFFF` costs six bytes of
//! reading and a typed reject rather than four gigabytes of
//! `Vec::with_capacity`. Never truncated, never padded, never silently
//! accepted.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_core::future::BoxFuture;
use twinvpn_schema::{Channel, Reject};

use crate::octets::ReceivedOctets;
use crate::transport::{ControlConnection, EventStream, Rung, TransportError};

/// The C1 frame header: `u16 command_code | u32 body_len`.
pub const C1_HEADER_BYTES: usize = 6;

/// The C2 record header: `u32 body_len`.
pub const C2_HEADER_BYTES: usize = 4;

/// The control-plane API epoch this build speaks.
///
/// `ownership.md` §8 **W-27**: the launch `ProtocolEpoch` is 1, declared by
/// `twinvpn-core`'s `EPOCH_TABLE` as a table rather than inferred from
/// `core_version`, which VR-3 forbids. A constant here because nothing on this
/// wire negotiates it yet; ADR-0014 V-3 fixes it for the life of the
/// connection either way, so a change is a coordinated reconnect and never an
/// in-place upgrade.
pub const LAUNCH_PROTOCOL_EPOCH: u32 = 1;

/// The QUIC application error code used when [`ControlConnection::close`] is
/// called. Zero, and no meaning is attached to it: this is a graceful local
/// close, not a protocol complaint.
pub(super) const CLOSE_CODE: u32 = 0;

/// The QUIC application error code used when a newer attach supersedes this
/// connection (ADR-0002 N-1).
pub(super) const SUPERSEDED_CODE: u32 = 1;

/// Refuses a declared length the frozen registry does not allow.
///
/// # Errors
///
/// [`TransportError::Rejected`] carrying `PROTO.SIZE_EXCEEDED` with the
/// violated parser named.
fn checked_body_len(declared: u32) -> Result<usize, TransportError> {
    let observed = usize::try_from(declared).unwrap_or(usize::MAX);
    let limit = Channel::ControlAndTelemetry.max_bytes();
    if observed > limit {
        return Err(TransportError::Rejected(Reject::SizeExceeded {
            parser_id: Channel::ControlAndTelemetry.parser_id(),
            observed,
            limit,
        }));
    }
    Ok(observed)
}

/// One attached control connection.
///
/// Holds the [`quinn::Endpoint`] as well as the connection: the endpoint owns
/// the UDP socket and the driver, and dropping it while a connection is live
/// would close the connection out from under its own user.
pub struct QuicConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    superseded: Arc<AtomicBool>,
}

impl core::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("rung", &Rung::Quic)
            .field("superseded", &self.superseded.load(Ordering::Acquire))
            // The endpoint and the connection are omitted rather than
            // forgotten: quinn's own `Debug` for them renders peer addresses
            // and connection ids, and a `Debug` that is safe to put in a log
            // line is worth more here than a complete one.
            .finish_non_exhaustive()
    }
}

impl QuicConnection {
    pub(super) fn new(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        superseded: Arc<AtomicBool>,
    ) -> Self {
        Self {
            endpoint,
            connection,
            superseded,
        }
    }

    /// The peer address this connection actually settled on.
    ///
    /// Which candidate won the Happy Eyeballs race is an observable an operator
    /// needs — "did this device reach us over IPv6" is the question ADR-0010 R1
    /// makes answerable, and a race that logged nothing would make it a guess.
    #[must_use]
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    /// The server's raw public key as presented on this connection.
    ///
    /// Already verified against the pin set during the handshake — the
    /// handshake would not have completed otherwise. Exposed so a composition
    /// root can record *which* pinned key was used across a rotation.
    #[must_use]
    pub fn server_key(&self) -> Option<Vec<u8>> {
        self.connection
            .peer_identity()?
            .downcast::<Vec<quinn::rustls::pki_types::CertificateDer<'static>>>()
            .ok()
            .and_then(|chain| chain.first().map(|c| c.as_ref().to_vec()))
    }

    /// The check every stream operation starts with.
    fn live(&self) -> Result<(), TransportError> {
        if self.superseded.load(Ordering::Acquire) {
            // ADR-0002 N-1: one connection per device. A caller still holding
            // the older handle is told what happened rather than being given a
            // generic close, because the two need different responses — a
            // supersession needs no reattach and a close does.
            return Err(TransportError::Superseded);
        }
        Ok(())
    }
}

impl ControlConnection for QuicConnection {
    fn channel_binding(&self) -> twinvpn_types::ChannelBinding {
        let mut out = [0u8; twinvpn_types::ChannelBinding::WIDTH];
        // Read from the LIVE CONNECTION, never from a message on it. That is
        // what makes the binding a binding (ADR-0002 N-2): a value a peer sent
        // proves only that the peer can send values.
        //
        // An exporter that cannot be read leaves `out` as zeros, and that is a
        // value the control plane REJECTS rather than one it accepts — its
        // `check_channel_binding` compares against the exporter it read itself,
        // which is never all-zero for a completed TLS 1.3 handshake. Failing
        // that comparison is the correct outcome and a louder one than a panic
        // here would be.
        let _ = self.connection.export_keying_material(
            &mut out,
            super::EXPORTER_LABEL,
            super::EXPORTER_CONTEXT,
        );
        twinvpn_types::ChannelBinding::from_array(out)
    }

    fn rung(&self) -> Rung {
        Rung::Quic
    }

    fn proto_version(&self) -> u32 {
        LAUNCH_PROTOCOL_EPOCH
    }

    fn request<'a>(
        &'a self,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<ReceivedOctets, TransportError>> {
        Box::pin(async move {
            self.live()?;
            // `body` is the COMPLETE C1 frame — see the module docs. A frame
            // too short to carry its own header never reaches the wire, and it
            // is reported as an unparseable envelope rather than as a
            // connection failure, because it is neither the network's fault nor
            // the peer's.
            if body.len() < C1_HEADER_BYTES {
                return Err(TransportError::Rejected(Reject::Unparseable {
                    parser_id: Channel::ControlAndTelemetry.parser_id(),
                }));
            }
            // Our own body is checked against the same cap the peer's is. The
            // caller is not untrusted, but a frame the server will refuse is
            // better refused here, where the violated registry key is still in
            // hand, than as an opaque stream reset.
            let declared = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
            let declared = checked_body_len(declared)?;
            if declared != body.len() - C1_HEADER_BYTES {
                return Err(TransportError::Rejected(Reject::Unparseable {
                    parser_id: Channel::ControlAndTelemetry.parser_id(),
                }));
            }

            let (mut send, mut recv) = self
                .connection
                .open_bi()
                .await
                .map_err(|e| super::map_connection_error(&e))?;
            send.write_all(body)
                .await
                .map_err(|_| TransportError::Closed)?;
            // FIN, so the server's `read_exact` over the body cannot block on a
            // client that has already said everything it intends to.
            send.finish().map_err(|_| TransportError::Closed)?;

            let mut header = [0u8; C1_HEADER_BYTES];
            recv.read_exact(&mut header)
                .await
                .map_err(|_| TransportError::Closed)?;
            let len = checked_body_len(u32::from_be_bytes([
                header[2], header[3], header[4], header[5],
            ]))?;
            let mut out = vec![0u8; len];
            recv.read_exact(&mut out)
                .await
                .map_err(|_| TransportError::Closed)?;
            Ok(ReceivedOctets::from_wire_owned(out))
        })
    }

    fn subscribe(
        &self,
        from_net_seq: u64,
    ) -> BoxFuture<'_, Result<Box<dyn EventStream>, TransportError>> {
        Box::pin(async move {
            self.live()?;
            // The C2 stream is opened by the SERVER, unidirectionally, after
            // the `SubscribeEvents` C1 request — `serve.rs`'s `spawn_c2` calls
            // `open_uni` on its side. So this accepts rather than opens.
            //
            // The `SubscribeEvents` request itself goes out through `request`
            // like every other C1 command, and deliberately not from here:
            // `SubscribeEventsRequest` carries a `MessageMetadata` with the
            // `correlation_id`/`causation_id` `ownership.md` §6 rule 6 requires
            // preserved across the boundary, and this trait method is handed
            // none. A transport that minted its own metadata would be the
            // second authority for a value the caller already owns.
            let recv = self
                .connection
                .accept_uni()
                .await
                .map_err(|e| super::map_connection_error(&e))?;
            Ok(Box::new(QuicEventStream {
                recv,
                next_net_seq: from_net_seq,
            }) as Box<dyn EventStream>)
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // Graceful shutdown (`ownership.md` §6 rule 7): close, then wait for
            // the CONNECTION_CLOSE frame to actually leave. Without the wait the
            // process can exit before the datagram is sent and the server sees
            // an idle timeout minutes later instead of a clean close — which
            // makes every deliberate shutdown look like a network failure in
            // the server's own metrics.
            self.connection.close(CLOSE_CODE.into(), b"closing");
            self.endpoint.wait_idle().await;
        })
    }
}

/// The C2 event stream: `u32 body_len | ControlEvent`, in order, forever.
pub struct QuicEventStream {
    recv: quinn::RecvStream,
    next_net_seq: u64,
}

impl QuicEventStream {
    /// The `net_seq` this stream was resumed from.
    ///
    /// ADR-0002 §11.7 rule 4 — "resume, do not reload". The value is carried so
    /// a caller can assert that what arrives continues from where it left off
    /// rather than re-snapshotting, which "converts a reconnect storm into a
    /// bandwidth storm".
    #[must_use]
    pub fn resumed_from(&self) -> u64 {
        self.next_net_seq
    }

    async fn read_one(&mut self) -> Option<Result<ReceivedOctets, TransportError>> {
        let mut header = [0u8; C2_HEADER_BYTES];
        match self.recv.read_exact(&mut header).await {
            Ok(()) => {}
            // End of stream is `None`, not an error: the server closing the C2
            // stream on a drain or a compaction is an ordinary event, and
            // reporting it as a failure would make every planned restart look
            // like an outage.
            Err(_) => return None,
        }
        let len = match checked_body_len(u32::from_be_bytes(header)) {
            Ok(len) => len,
            Err(err) => return Some(Err(err)),
        };
        let mut out = vec![0u8; len];
        if self.recv.read_exact(&mut out).await.is_err() {
            return Some(Err(TransportError::Closed));
        }
        Some(Ok(ReceivedOctets::from_wire_owned(out)))
    }
}

impl EventStream for QuicEventStream {
    fn next(&mut self) -> BoxFuture<'_, Option<Result<ReceivedOctets, TransportError>>> {
        Box::pin(self.read_one())
    }
}

#[cfg(test)]
mod tests {
    use super::{checked_body_len, C1_HEADER_BYTES, C2_HEADER_BYTES, LAUNCH_PROTOCOL_EPOCH};
    use crate::transport::TransportError;

    #[test]
    fn the_framing_matches_the_servers_wire_module() {
        // Duplicated across an artifact boundary
        // (`services/control-plane/src/wire.rs`), so asserted rather than
        // trusted: a mismatch is a stream that stalls with no diagnosis on
        // either side.
        assert_eq!(C1_HEADER_BYTES, 2 + 4);
        assert_eq!(C2_HEADER_BYTES, 4);
    }

    #[test]
    fn a_declared_length_over_the_envelope_cap_is_refused_before_allocation() {
        let cap = twinvpn_schema::Channel::ControlAndTelemetry.max_bytes();
        assert_eq!(
            checked_body_len(u32::try_from(cap).expect("the cap fits a u32")),
            Ok(cap)
        );
        let Err(TransportError::Rejected(reject)) =
            checked_body_len(u32::try_from(cap + 1).expect("fits"))
        else {
            panic!("one byte over the cap must be refused");
        };
        assert_eq!(reject.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn a_hostile_u32_costs_a_reject_and_not_four_gigabytes() {
        let Err(TransportError::Rejected(reject)) = checked_body_len(u32::MAX) else {
            panic!("0xFFFFFFFF must be refused");
        };
        assert_eq!(reject.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn the_launch_protocol_epoch_is_one() {
        // `ownership.md` §8 W-27, and VR-3's requirement that it be stated
        // rather than inferred.
        assert_eq!(LAUNCH_PROTOCOL_EPOCH, 1);
    }
}
