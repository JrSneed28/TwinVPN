//! The mock's in-memory network fabric, sockets and interfaces.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_core::future::BoxFuture;
use futures_core::Stream;
use twinvpn_types::{Endpoint, IpAddr, Port, V4Addr, V6Addr};

use crate::error::PlatformError;
use crate::iface::{InterfaceFacts, InterfaceIndex, InterfaceProvider, NetworkChange};
use crate::socket::{
    Datagram, MulticastOptions, SocketFamily, SocketProvider, SupportedFamilies, UdpBindSpec,
    UdpSocket,
};

/// A deterministic in-memory network several mock adapters share.
///
/// Datagrams are delivered by endpoint, so two `MockAdapter`s bound to one
/// `MockNetwork` can complete a real handshake with no kernel involved — which is
/// what makes CD-5's "100% of the decision logic on a Linux CI runner" true for
/// the path-establishment logic and not only for the state machine.
#[derive(Clone, Default)]
pub struct MockNetwork {
    inner: Arc<Mutex<Fabric>>,
}

#[derive(Default)]
struct Fabric {
    /// Bound sockets, by endpoint.
    inboxes: HashMap<Endpoint, Arc<Mutex<Inbox>>>,
    /// Multicast group membership.
    groups: HashMap<(IpAddr, u32), Vec<Endpoint>>,
    next_ephemeral: u16,
    /// Endpoints whose traffic is silently dropped, for fault injection.
    blackholed: Vec<Endpoint>,
    delivered: u64,
    dropped: u64,
}

#[derive(Default)]
struct Inbox {
    queue: VecDeque<(Vec<u8>, Endpoint)>,
    waker: Option<Waker>,
    closed: bool,
}

impl MockNetwork {
    /// A fresh, empty network.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Fabric {
                next_ephemeral: 49_152,
                ..Fabric::default()
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Fabric> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drops every datagram to or from `endpoint`, so a scenario can express a
    /// blocked path as a fact rather than by waiting for a timeout.
    pub fn blackhole(&self, endpoint: Endpoint) {
        self.lock().blackholed.push(endpoint);
    }

    /// Stops blackholing `endpoint`.
    pub fn unblackhole(&self, endpoint: &Endpoint) {
        self.lock().blackholed.retain(|e| e != endpoint);
    }

    /// How many datagrams were delivered and how many dropped. A cheap `BIT`
    /// assertion for a scenario.
    #[must_use]
    pub fn counters(&self) -> (u64, u64) {
        let f = self.lock();
        (f.delivered, f.dropped)
    }

    fn bind(
        &self,
        requested: Option<Endpoint>,
        family: SocketFamily,
    ) -> Result<(Endpoint, Arc<Mutex<Inbox>>), PlatformError> {
        let mut fabric = self.lock();
        let endpoint = if let Some(e) = requested {
            e
        } else {
            {
                let port = fabric.next_ephemeral;
                fabric.next_ephemeral = fabric.next_ephemeral.wrapping_add(1).max(49_152);
                let address = match family {
                    SocketFamily::V4 => IpAddr::V4(V4Addr::UNSPECIFIED),
                    SocketFamily::V6Only | SocketFamily::V6DualStack => {
                        IpAddr::V6(V6Addr::UNSPECIFIED)
                    }
                };
                Endpoint::new(
                    address,
                    Port::new(port).map_err(|_| PlatformError::AdapterUnavailable(None))?,
                )
            }
        };
        if fabric.inboxes.contains_key(&endpoint) {
            // Address already in use. Reported, not silently rebound: a silent
            // rebind is how two sockets come to believe they own one port.
            return Err(PlatformError::NotPermitted(None));
        }
        let inbox = Arc::new(Mutex::new(Inbox::default()));
        fabric.inboxes.insert(endpoint, Arc::clone(&inbox));
        Ok((endpoint, inbox))
    }

    fn deliver(&self, from: Endpoint, to: &Endpoint, payload: &[u8]) {
        let mut fabric = self.lock();
        if fabric.blackholed.contains(&from) || fabric.blackholed.contains(to) {
            fabric.dropped += 1;
            return;
        }
        // A multicast destination fans out to every joined member.
        let members: Vec<Endpoint> = fabric
            .groups
            .get(&(to.address, u32::from(to.port.get())))
            .cloned()
            .unwrap_or_default();
        let targets = if members.is_empty() {
            fabric
                .inboxes
                .get(to)
                .map(|_| vec![*to])
                .unwrap_or_default()
        } else {
            members
        };
        if targets.is_empty() {
            fabric.dropped += 1;
            return;
        }
        for target in targets {
            if let Some(inbox) = fabric.inboxes.get(&target).cloned() {
                let mut i = inbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                i.queue.push_back((payload.to_vec(), from));
                if let Some(w) = i.waker.take() {
                    w.wake();
                }
                fabric.delivered += 1;
            }
        }
    }

    fn unbind(&self, endpoint: &Endpoint) {
        let mut fabric = self.lock();
        if let Some(inbox) = fabric.inboxes.remove(endpoint) {
            let mut i = inbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            i.closed = true;
            if let Some(w) = i.waker.take() {
                w.wake();
            }
        }
        for members in fabric.groups.values_mut() {
            members.retain(|m| m != endpoint);
        }
    }

    /// Group membership is keyed by `(group address, the member's own port)`,
    /// which is how multicast actually works: a datagram to `(group, port)`
    /// reaches every member listening on that port, and a member bound to a
    /// different port does not receive it. Keying by interface index instead
    /// would make every join match every port, which is laxer than the contract.
    fn join(&self, options: &MulticastOptions, member: Endpoint) {
        let key = (options.group, u32::from(member.port.get()));
        self.lock().groups.entry(key).or_default().push(member);
    }

    fn leave(&self, options: &MulticastOptions, member: &Endpoint) {
        let key = (options.group, u32::from(member.port.get()));
        if let Some(members) = self.lock().groups.get_mut(&key) {
            members.retain(|m| m != member);
        }
    }
}

/// An in-memory UDP socket on a [`MockNetwork`].
pub struct MockSocket {
    network: MockNetwork,
    endpoint: Endpoint,
    family: SocketFamily,
    inbox: Arc<Mutex<Inbox>>,
    closed: Arc<AtomicBool>,
}

impl UdpSocket for MockSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(PlatformError::AdapterUnavailable(None));
        }
        Ok(self.endpoint)
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            // A cross-family send is refused rather than coerced: coercing is how
            // a v6-only socket comes to look like it reached a v4 peer.
            if destination.family() != self.family.primary_family()
                && self.family != SocketFamily::V6DualStack
            {
                return Err(PlatformError::NoRoute(None));
            }
            self.network.deliver(self.endpoint, destination, buf);
            Ok(buf.len())
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(Recv {
            inbox: Arc::clone(&self.inbox),
            buf: Some(buf),
            local: self.endpoint,
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.network.join(options, self.endpoint);
        Ok(())
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.network.leave(options, &self.endpoint);
        Ok(())
    }

    fn family(&self) -> SocketFamily {
        self.family
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Idempotent, per the adapter contract.
            if !self.closed.swap(true, Ordering::AcqRel) {
                self.network.unbind(&self.endpoint);
            }
            Ok(())
        })
    }
}

struct Recv<'a> {
    inbox: Arc<Mutex<Inbox>>,
    buf: Option<&'a mut [u8]>,
    local: Endpoint,
}

impl std::future::Future for Recv<'_> {
    type Output = Result<Datagram, PlatformError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inbox = this
            .inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((payload, source)) = inbox.queue.pop_front() {
            let buf = this.buf.take().expect("polled after completion");
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            return Poll::Ready(Ok(Datagram {
                len: n,
                source,
                destination: Some(this.local.address),
                interface: None,
                // Reported, never silent.
                truncated: n < payload.len(),
            }));
        }
        if inbox.closed {
            return Poll::Ready(Err(PlatformError::ShuttingDown));
        }
        inbox.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// The mock's socket provider.
pub struct MockSockets {
    pub(super) network: MockNetwork,
    pub(super) supported: SupportedFamilies,
    pub(super) shutting_down: Arc<AtomicBool>,
    pub(super) opened: AtomicU64,
}

impl MockSockets {
    /// How many sockets have been opened. Lets a test assert that gathering
    /// opened a v4 socket and a v6 socket, which is ADR-0010 R1 at the mechanism
    /// level.
    #[must_use]
    pub fn opened(&self) -> u64 {
        self.opened.load(Ordering::Relaxed)
    }
}

impl SocketProvider for MockSockets {
    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            if self.shutting_down.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            let available = match spec.family {
                SocketFamily::V4 => self.supported.v4,
                SocketFamily::V6Only => self.supported.v6,
                SocketFamily::V6DualStack => self.supported.dual_stack_socket,
            };
            if !available {
                // A fact about the host, reported so the core can decide. Never
                // substituted with another family.
                return Err(PlatformError::OsUnsupported(None));
            }
            let (endpoint, inbox) = self.network.bind(spec.local, spec.family)?;
            self.opened.fetch_add(1, Ordering::Relaxed);
            let socket = MockSocket {
                network: self.network.clone(),
                endpoint,
                family: spec.family,
                inbox,
                closed: Arc::new(AtomicBool::new(false)),
            };
            if let Some(mc) = spec.options.multicast.as_ref() {
                socket.join_multicast(mc)?;
            }
            Ok(Box::new(socket) as Box<dyn UdpSocket>)
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move { Ok(self.supported) })
    }
}

/// The mock's interface provider, with an injectable change stream.
#[derive(Clone, Default)]
pub struct MockInterfaces {
    state: Arc<Mutex<InterfaceState>>,
}

#[derive(Default)]
struct InterfaceState {
    interfaces: Vec<InterfaceFacts>,
    subscribers: Vec<Arc<Mutex<ChangeQueue>>>,
}

#[derive(Default)]
struct ChangeQueue {
    queue: VecDeque<NetworkChange>,
    waker: Option<Waker>,
}

impl MockInterfaces {
    /// An empty interface table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InterfaceState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replaces the interface table.
    pub fn set_interfaces(&self, interfaces: Vec<InterfaceFacts>) {
        self.lock().interfaces = interfaces;
    }

    /// Emits a change to every subscriber.
    pub fn emit(&self, change: &NetworkChange) {
        let subscribers = self.lock().subscribers.clone();
        for s in subscribers {
            let mut q = s.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            q.queue.push_back(change.clone());
            if let Some(w) = q.waker.take() {
                w.wake();
            }
        }
    }

    /// Removes an interface and emits the corresponding event, so a test does
    /// not have to keep the two in step by hand.
    pub fn remove_interface(&self, index: InterfaceIndex) {
        self.lock().interfaces.retain(|i| i.index != index);
        self.emit(&NetworkChange::InterfaceRemoved(index));
    }
}

impl InterfaceProvider for MockInterfaces {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move { Ok(self.lock().interfaces.clone()) })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        let queue = Arc::new(Mutex::new(ChangeQueue::default()));
        self.lock().subscribers.push(Arc::clone(&queue));
        Ok(Box::pin(ChangeStream { queue }))
    }
}

struct ChangeStream {
    queue: Arc<Mutex<ChangeQueue>>,
}

impl Stream for ChangeStream {
    type Item = NetworkChange;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<NetworkChange>> {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(change) = q.queue.pop_front() {
            return Poll::Ready(Some(change));
        }
        q.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
