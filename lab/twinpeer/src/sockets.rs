//! Two thin wrappers over the one real UDP socket the peer holds.
//!
//! The peer has exactly one socket, and three things want to read it at
//! different moments: the listen phase, `twinvpn_core::lab::drive` while it
//! answers an initiation, and the pump. Two sockets would be two ports and the
//! guest would send its initiation to only one of them, so the socket is shared
//! and the *reader* is what changes.
//!
//! | Wrapper | Whose | What it changes |
//! |---|---|---|
//! | [`Replay`] | `drive`, as Responder | its first receive answers the initiation the supervisor already took off the wire |
//! | [`Guard`] | the pump | drops probes, and captures a NEW initiation instead of feeding it to the pump |
//!
//! [`Guard`] is the one that carries a decision. `drive` requires
//! `peer_endpoint` **before** it receives, so the initiation's source address has
//! to be known before the handshake starts — which means the initiation has to
//! be read by something that is not `drive`, and then replayed to it. And once a
//! pump is running it owns the socket, so a re-handshake after the guest
//! restarts would be invisible: the pump would see a datagram with a type octet
//! of `1`, reject it as a malformed frame, and carry on pumping into a tunnel
//! whose keys the guest has thrown away. [`Guard`] therefore trips the pump's
//! [`Cancel`] and holds the initiation for the supervisor.

use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_core::lab::{Cancel, PROBE, TYPE_HANDSHAKE_INITIATION};
use twinvpn_platform::error::PlatformError;
use twinvpn_platform::socket::{Datagram, MulticastOptions, SocketFamily, UdpSocket};
use twinvpn_types::Endpoint;

/// One datagram and where it came from.
pub type Captured = (Vec<u8>, Endpoint);

/// What a datagram is, decided by its first octet alone.
///
/// The bodies are parsed by [`twinvpn_core::lab::drive`] and by the pump, where
/// the bounds and the refusals already live. Nothing here validates anything: it
/// only decides which of the three readers a datagram belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `TwinVPN/probe/v1`. Nothing answers one.
    Probe,
    /// A handshake initiation, type `1`.
    Initiation,
    /// Anything else — transport data, a response, or noise the pump will
    /// refuse.
    Carry,
}

/// Classifies one datagram.
#[must_use]
pub fn classify(datagram: &[u8]) -> Kind {
    if datagram == PROBE {
        Kind::Probe
    } else if datagram.first() == Some(&TYPE_HANDSHAKE_INITIATION) {
        Kind::Initiation
    } else {
        Kind::Carry
    }
}

fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

fn put<T>(slot: &Mutex<Option<T>>, value: T) {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value);
}

/// Copies a captured datagram back out as though it had just arrived.
fn deliver(captured: &Captured, buf: &mut [u8]) -> Datagram {
    let (bytes, source) = captured;
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    Datagram {
        len,
        source: *source,
        destination: None,
        interface: None,
        // Reported, never silent — the same rule the real adapter follows. A
        // handshake message that did not fit is refused by `drive` rather than
        // failing to authenticate for a reason nobody can see.
        truncated: len < bytes.len(),
    }
}

/// The socket `drive` sees while it answers one initiation.
pub struct Replay {
    inner: Arc<dyn UdpSocket>,
    first: Mutex<Option<Captured>>,
}

impl Replay {
    /// Wraps the socket so that the next receive answers `first`.
    #[must_use]
    pub fn new(inner: Arc<dyn UdpSocket>, first: Captured) -> Self {
        Self {
            inner,
            first: Mutex::new(Some(first)),
        }
    }
}

impl UdpSocket for Replay {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        self.inner.local_endpoint()
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        self.inner.send_to(buf, destination)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            if let Some(captured) = take(&self.first) {
                return Ok(deliver(&captured, buf));
            }
            self.inner.recv_from(buf).await
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.inner.join_multicast(options)
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.inner.leave_multicast(options)
    }

    fn family(&self) -> SocketFamily {
        self.inner.family()
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        // **Not closed.** The socket outlives the handshake: the pump and the
        // next handshake are on the same port, and closing it here would drop
        // the guest's binding.
        Box::pin(async { Ok(()) })
    }
}

/// The socket the pump sees.
pub struct Guard {
    inner: Arc<dyn UdpSocket>,
    cancel: Cancel,
    captured: Mutex<Option<Captured>>,
}

impl Guard {
    /// Wraps the socket, tripping `cancel` when a new initiation arrives.
    #[must_use]
    pub fn new(inner: Arc<dyn UdpSocket>, cancel: Cancel) -> Self {
        Self {
            inner,
            cancel,
            captured: Mutex::new(None),
        }
    }

    /// **Takes** the initiation that stopped the pump, if that is why it
    /// stopped.
    ///
    /// A take rather than a read: one initiation drives one handshake. A second
    /// arriving before the first is claimed replaces it, for the reason
    /// `Pump::take_resume` gives — the newer offer is the one that can still
    /// complete, and an unbounded queue here is a memory sink an off-path
    /// sender fills for free.
    #[must_use]
    pub fn take_initiation(&self) -> Option<Captured> {
        take(&self.captured)
    }
}

impl UdpSocket for Guard {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        self.inner.local_endpoint()
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        self.inner.send_to(buf, destination)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            loop {
                let arrival = self.inner.recv_from(&mut *buf).await?;
                match classify(&buf[..arrival.len]) {
                    Kind::Carry => return Ok(arrival),
                    Kind::Probe => {
                        tracing::debug!(source = ?arrival.source, "discarded a reachability probe");
                    }
                    Kind::Initiation => {
                        tracing::info!(
                            source = ?arrival.source,
                            "an initiation arrived while pumping; stopping to re-handshake"
                        );
                        put(&self.captured, (buf[..arrival.len].to_vec(), arrival.source));
                        self.cancel.cancel();
                        // The pump's own receive is raced against this token, so
                        // it stops rather than waiting for this loop to return.
                        // Continuing keeps the socket drained until it does.
                    }
                }
            }
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.inner.join_multicast(options)
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.inner.leave_multicast(options)
    }

    fn family(&self) -> SocketFamily {
        self.inner.family()
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        // Same reason as `Replay::close`: the port outlives one pump.
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_core::lab::{encode_initiation, ReceiverIndex, TYPE_TRANSPORT_DATA};

    #[test]
    fn a_probe_is_not_mistaken_for_a_handshake() {
        assert_eq!(classify(PROBE), Kind::Probe);
    }

    #[test]
    fn an_initiation_is_recognised_by_its_type_octet() {
        let datagram = encode_initiation(ReceiverIndex(7), &[0u8; 96]);
        assert_eq!(classify(&datagram), Kind::Initiation);
    }

    #[test]
    fn transport_data_is_carried_rather_than_captured() {
        let mut datagram = vec![TYPE_TRANSPORT_DATA];
        datagram.extend_from_slice(&[0u8; 15]);
        assert_eq!(classify(&datagram), Kind::Carry);
    }

    #[test]
    fn an_empty_datagram_is_carried_and_refused_downstream() {
        // Never classified as a handshake: `first()` is `None`. The pump refuses
        // it as a short frame, which is where that refusal belongs.
        assert_eq!(classify(&[]), Kind::Carry);
    }
}
