//! [`InterfaceProvider`]: enumeration, and the change stream `NWPathMonitor`
//! feeds.
//!
//! **Authority:** `docs/networking.md` §5.1 ("event-driven, never polled") and
//! §5.2's iOS change-events column; §5.4's iOS row (every wake is a
//! network-change event); ADR-0018 §11.6 ("a dropped event is itself recorded"),
//! §11.16 (h); ADR-0022 LC-23b.
//!
//! # The subscription is inbound, and that is the platform's shape too
//!
//! ADR-0018 §11.16 (h) records that at the C ABI the subscription is satisfied by
//! "an inbound command submission rather than a literal outbound function
//! pointer". `NWPathMonitor` has exactly that shape: Swift sets
//! `pathUpdateHandler`, the OS calls it, and Swift pushes the snapshot into
//! [`IosInterfaceProvider::push_snapshot`]. Nothing in this crate polls, and
//! there is no timer here to poll with.
//!
//! Why it matters is not efficiency. `docs/networking.md` §5.1: "a poll interval
//! is a window in which the host has moved networks and the core still believes
//! it has not", and every roaming deadline in `docs/reliability.md` §5 "is
//! measured from the moment the change is *known*, so a poll interval is added
//! directly to `T_FAILOVER_TARGET`."
//!
//! # A slow consumer loses events, and is told
//!
//! Each subscriber has a bounded queue. When it fills, the change is dropped and
//! [`NetworkChange::EventsLost`] is delivered in its place — ADR-0018 §11.6: "an
//! adapter that silently coalesces leaves the core believing it has a complete
//! picture; an adapter that reports the gap lets the core re-enumerate and
//! recover." An unbounded queue would trade that for a jetsam kill inside a
//! 12 MB provider, which is the same loss with no notification.
//!
//! **The loss notice cannot itself be lost.** A first attempt at this sent
//! `EventsLost` down the same queue, and its own test caught the obvious
//! consequence: the queue that just refused a change refuses the notice about it
//! too, so the subscriber that fell behind is the one subscriber never told. The
//! count therefore lives in an [`AtomicU64`] beside the queue, and
//! `ChangeStream::poll_next` reports it **before** it reports any queued
//! change — so the gap arrives the instant the consumer drains, ahead of the
//! events that survived it.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use futures_core::future::BoxFuture;
use futures_core::Stream;
use tokio::sync::mpsc;

use twinvpn_platform::{InterfaceFacts, InterfaceProvider, NetworkChange, PlatformError};

use crate::host::ProviderHost;
use crate::netcfg::status_error;
use crate::oserr::{self, Context};
use crate::pathmon::{self, ObservedPath, PathSnapshot};
use crate::shutdown::ShutdownLatch;

/// How many changes one subscriber may fall behind before the gap is reported.
///
/// Bounded because `ownership.md` §6 rule 10 bounds every allocation an
/// untrusted input can drive, and because an unbounded queue in a provider with
/// ADR-0022 LC-17's 12 MB budget is a jetsam kill waiting for a flapping network.
pub const SUBSCRIBER_QUEUE_DEPTH: usize = 64;

/// Interface enumeration and change notification.
pub struct IosInterfaceProvider {
    host: Arc<dyn ProviderHost>,
    shutdown: ShutdownLatch,
    /// The one observation both this provider and `crate::netcfg` read, so
    /// `enumerate` and `query_link_facts` describe the same instant.
    observed: ObservedPath,
    state: Mutex<ProviderState>,
}

#[derive(Default)]
struct ProviderState {
    subscribers: Vec<Subscriber>,
    /// How many changes were dropped because a subscriber was not draining.
    dropped: u64,
}

/// One subscriber's queue, and the gap it has not been told about yet.
struct Subscriber {
    tx: mpsc::Sender<NetworkChange>,
    /// Incremented when this subscriber's queue refused a change.
    ///
    /// Lives beside the queue rather than in it, because the queue that just
    /// refused a change would refuse the notice about it too — see the module
    /// header.
    lost: Arc<AtomicU64>,
}

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl IosInterfaceProvider {
    /// Builds the provider.
    #[must_use]
    pub fn new(
        host: Arc<dyn ProviderHost>,
        shutdown: ShutdownLatch,
        observed: ObservedPath,
    ) -> Self {
        Self {
            host,
            shutdown,
            observed,
            state: Mutex::new(ProviderState::default()),
        }
    }

    /// Delivers one `NWPathMonitor` update.
    ///
    /// Called by [`crate::bridge`] from Swift's `pathUpdateHandler`. Returns how
    /// many changes were derived, which is a number a shell can log; it is not a
    /// verdict about what they mean.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the snapshot is malformed or
    /// exceeds a declared bound.
    pub fn push_snapshot(&self, json: &str) -> Result<usize, PlatformError> {
        self.deliver(json, false)
    }

    /// Delivers the first `NWPathMonitor` update after `NEProvider.wake()`.
    ///
    /// `docs/networking.md` §5.4: "treat every wake as a network-change event"
    /// and "re-validate every path rather than assuming continuity". The
    /// difference from [`Self::push_snapshot`] is that this **always** leads with
    /// [`NetworkChange::EventsLost`], even when the snapshot is byte-identical to
    /// the last one — because the monitor was not running, so "identical" is not
    /// evidence that nothing happened.
    ///
    /// # Errors
    ///
    /// As [`Self::push_snapshot`].
    pub fn push_snapshot_after_wake(&self, json: &str) -> Result<usize, PlatformError> {
        self.deliver(json, true)
    }

    fn deliver(&self, json: &str, across_wake: bool) -> Result<usize, PlatformError> {
        let snapshot = PathSnapshot::parse(json)?;
        // Replace first: a malformed snapshot never reaches here, so the cell
        // only ever holds an observation this build could read.
        let previous = self.observed.replace(snapshot.clone());
        let changes = match (previous, across_wake) {
            (Some(previous), true) => pathmon::changes_across_wake(&previous, &snapshot),
            (Some(previous), false) => pathmon::diff(&previous, &snapshot),
            // The first snapshot is not a diff. A caller that has just
            // subscribed also enumerates, and "an adapter that replayed the
            // initial state as a burst of `Added` events would make 'we just
            // started' and 'the network just changed' indistinguishable."
            // After a wake with no previous snapshot the loss is still
            // reported, because the gap is real either way.
            (None, true) => vec![NetworkChange::EventsLost { count: None }],
            (None, false) => Vec::new(),
        };

        for change in &changes {
            self.broadcast(change);
        }
        Ok(changes.len())
    }

    fn broadcast(&self, change: &NetworkChange) {
        let mut state = guard(&self.state);
        let mut any_lost = false;
        state.subscribers.retain(|subscriber| {
            match subscriber.tx.try_send(change.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Counted beside the queue, so the notice survives the
                    // condition it describes.
                    subscriber.lost.fetch_add(1, Ordering::SeqCst);
                    any_lost = true;
                    true
                }
                // The subscriber is gone. Dropping the receiver is not an event.
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
        if any_lost {
            state.dropped += 1;
        }
    }

    /// How many changes were dropped because a subscriber was not draining.
    #[must_use]
    pub fn dropped_changes(&self) -> u64 {
        guard(&self.state).dropped
    }

    /// The snapshot most recently delivered, if any.
    #[must_use]
    pub fn last_snapshot(&self) -> Option<PathSnapshot> {
        self.observed.get()
    }

    fn fetch_snapshot(&self) -> Result<PathSnapshot, PlatformError> {
        match self.host.path_snapshot() {
            Ok(Some(json)) => PathSnapshot::parse(&json),
            // The monitor has not fired. Reporting an empty interface list would
            // say "this device has no network", which is a far stronger claim
            // than "we have not been told yet".
            Ok(None) => Err(PlatformError::AdapterUnavailable(Some(
                oserr::detail_from_code(0, "NWPathMonitor.currentPath"),
            ))),
            Err(status) => Err(status_error(
                status,
                "NWPathMonitor.currentPath",
                Context::Interfaces,
            )),
        }
    }
}

/// The change stream one subscriber holds.
struct ChangeStream {
    rx: mpsc::Receiver<NetworkChange>,
    lost: Arc<AtomicU64>,
}

impl Stream for ChangeStream {
    type Item = NetworkChange;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        // The gap first, ahead of the events that survived it. A core reading
        // `EventsLost` re-enumerates, and it must do so knowing the queued
        // events it is about to see are an incomplete account.
        let lost = self.lost.swap(0, Ordering::SeqCst);
        if lost > 0 {
            return Poll::Ready(Some(NetworkChange::EventsLost { count: Some(lost) }));
        }
        self.rx.poll_recv(cx)
    }
}

impl InterfaceProvider for IosInterfaceProvider {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // Prefer the snapshot already delivered: it is what the core's most
            // recent events described, and re-fetching could return a newer path
            // whose changes have not been delivered yet — which would make the
            // enumerate and the stream disagree about the same instant.
            if let Some(snapshot) = self.last_snapshot() {
                return snapshot.interface_facts();
            }
            self.fetch_snapshot()?.interface_facts()
        })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.shutdown.guard()?;
        let (tx, rx) = mpsc::channel(SUBSCRIBER_QUEUE_DEPTH);
        let lost = Arc::new(AtomicU64::new(0));
        guard(&self.state).subscribers.push(Subscriber {
            tx,
            lost: lost.clone(),
        });
        // The stream carries changes and NOT the initial state, per the trait's
        // contract: a subscriber that also wants the current picture calls
        // `enumerate`, and the two are deliberately separate calls.
        Ok(Box::pin(ChangeStream { rx, lost }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::RecordingHost;
    use twinvpn_platform::InterfaceIndex;

    const WIFI: &str = r#"{"interfaces":[{"index":1,"name":"en0","interface_type":"wifi",
        "is_up":true,"mtu":1500}],"supports_v4":true,"supports_v6":false,
        "supports_dns":true,"metered":false,"constrained":false}"#;

    const CELLULAR: &str = r#"{"interfaces":[{"index":2,"name":"pdp_ip0",
        "interface_type":"cellular","is_up":true,"mtu":1428}],"supports_v4":true,
        "supports_v6":true,"supports_dns":true,"metered":true,"constrained":false}"#;

    fn build() -> (Arc<RecordingHost>, IosInterfaceProvider) {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let provider =
            IosInterfaceProvider::new(host.clone(), ShutdownLatch::new(), ObservedPath::default());
        (host, provider)
    }

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn drain(stream: &mut Pin<Box<dyn Stream<Item = NetworkChange> + Send>>) -> Vec<NetworkChange> {
        let mut out = Vec::new();
        let waker = futures_noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        while let Poll::Ready(Some(change)) = stream.as_mut().poll_next(&mut cx) {
            out.push(change);
        }
        out
    }

    /// A no-op waker, so a test can drain without a runtime.
    fn futures_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: every function in VTABLE ignores its data pointer, so the null
        // pointer is never dereferenced; clone returns an equally inert waker.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn the_first_snapshot_is_not_replayed_as_a_burst_of_added_events() {
        // "an adapter that replayed the initial state as a burst of `Added`
        // events would make 'we just started' and 'the network just changed'
        // indistinguishable."
        let (_host, provider) = build();
        let mut stream = provider.subscribe().expect("subscribes");
        assert_eq!(provider.push_snapshot(WIFI).expect("delivers"), 0);
        assert!(drain(&mut stream).is_empty());
        // But `enumerate` sees it, which is why they are separate calls.
        let facts = block_on(provider.enumerate()).expect("enumerates");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].index, InterfaceIndex(1));
    }

    #[test]
    fn a_roam_is_delivered_as_events_and_the_core_decides_what_they_mean() {
        let (_host, provider) = build();
        provider.push_snapshot(WIFI).expect("delivers");
        let mut stream = provider.subscribe().expect("subscribes");
        provider.push_snapshot(CELLULAR).expect("delivers");

        let changes = drain(&mut stream);
        assert!(changes.contains(&NetworkChange::InterfaceAdded(InterfaceIndex(2))));
        assert!(changes.contains(&NetworkChange::InterfaceRemoved(InterfaceIndex(1))));
        assert!(changes.iter().any(|c| matches!(
            c,
            NetworkChange::DefaultRouteChanged {
                family: twinvpn_types::AddressFamily::V6,
                present: true
            }
        )));
    }

    #[test]
    fn a_wake_leads_with_events_lost_even_when_nothing_changed() {
        // networking.md §5.4's iOS row. The monitor was not running, so an
        // identical snapshot is not evidence that nothing happened.
        let (_host, provider) = build();
        provider.push_snapshot(WIFI).expect("delivers");
        let mut stream = provider.subscribe().expect("subscribes");
        provider.push_snapshot_after_wake(WIFI).expect("delivers");

        let changes = drain(&mut stream);
        assert_eq!(changes, vec![NetworkChange::EventsLost { count: None }]);
    }

    #[test]
    fn a_wake_with_no_previous_snapshot_still_reports_the_gap() {
        let (_host, provider) = build();
        let mut stream = provider.subscribe().expect("subscribes");
        provider.push_snapshot_after_wake(WIFI).expect("delivers");
        assert_eq!(
            drain(&mut stream),
            vec![NetworkChange::EventsLost { count: None }]
        );
    }

    #[test]
    fn a_subscriber_that_falls_behind_is_told_rather_than_silently_coalesced() {
        // ADR-0018 §11.6: "a dropped event is itself recorded".
        let (_host, provider) = build();
        let mut stream = provider.subscribe().expect("subscribes");
        provider.push_snapshot(WIFI).expect("delivers");

        // Flood past the queue depth without draining. Each push alternates the
        // v6 default so every one yields exactly one change.
        for i in 0..(SUBSCRIBER_QUEUE_DEPTH + 8) {
            let v6 = if i % 2 == 0 { "true" } else { "false" };
            let json = format!(
                r#"{{"interfaces":[{{"index":1,"name":"en0","interface_type":"wifi",
                "is_up":true,"mtu":1500}}],"supports_v4":true,"supports_v6":{v6},
                "supports_dns":true,"metered":false,"constrained":false}}"#
            );
            provider.push_snapshot(&json).expect("delivers");
        }
        assert!(provider.dropped_changes() > 0);
        let changes = drain(&mut stream);
        // The notice arrives FIRST, ahead of the events that survived the gap:
        // a core reading it must know the queued events are an incomplete
        // account before it processes them.
        assert!(
            matches!(changes.first(), Some(NetworkChange::EventsLost { count: Some(n) }) if *n > 0),
            "the gap is reported with a count so the core can re-enumerate, and \
             it is reported ahead of the survivors; got {:?}",
            changes.first()
        );
        // And it is not lost by the very queue that refused the change it
        // describes — the defect this test was written to catch.
        assert!(changes.len() > 1);
    }

    #[test]
    fn a_dropped_subscriber_is_forgotten_and_is_not_an_event() {
        let (_host, provider) = build();
        let stream = provider.subscribe().expect("subscribes");
        provider.push_snapshot(WIFI).expect("delivers");
        drop(stream);
        provider.push_snapshot(CELLULAR).expect("delivers");
        assert_eq!(
            provider.dropped_changes(),
            0,
            "a gone subscriber is not a lost event"
        );
        assert!(guard(&provider.state).subscribers.is_empty());
    }

    #[test]
    fn two_subscribers_both_see_every_change() {
        let (_host, provider) = build();
        provider.push_snapshot(WIFI).expect("delivers");
        let mut a = provider.subscribe().expect("subscribes");
        let mut b = provider.subscribe().expect("subscribes");
        provider.push_snapshot(CELLULAR).expect("delivers");
        assert_eq!(drain(&mut a), drain(&mut b));
    }

    #[test]
    fn enumerate_before_the_monitor_fires_is_refused_and_not_reported_as_offline() {
        // An empty interface list says "this device has no network", which is a
        // far stronger claim than "we have not been told yet".
        let (_host, provider) = build();
        let err = block_on(provider.enumerate()).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }

    #[test]
    fn enumerate_falls_back_to_the_hosts_current_path_when_nothing_was_pushed() {
        let (host, provider) = build();
        host.state().path_snapshot = Some(WIFI.to_owned());
        let facts = block_on(provider.enumerate()).expect("enumerates");
        assert_eq!(facts.len(), 1);
    }

    #[test]
    fn a_malformed_snapshot_is_refused_and_does_not_replace_the_last_good_one() {
        let (_host, provider) = build();
        provider.push_snapshot(WIFI).expect("delivers");
        provider.push_snapshot("not json").expect_err("refuses");
        // The last good snapshot survives, so `enumerate` does not start
        // reporting an empty network because one callback was garbled.
        assert_eq!(block_on(provider.enumerate()).expect("enumerates").len(), 1);
    }

    #[test]
    fn after_shutdown_subscribing_refuses_by_name() {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let shutdown = ShutdownLatch::new();
        let provider = IosInterfaceProvider::new(host, shutdown.clone(), ObservedPath::default());
        shutdown.begin();
        assert_eq!(
            provider.subscribe().err(),
            Some(PlatformError::ShuttingDown)
        );
        assert_eq!(
            block_on(provider.enumerate()),
            Err(PlatformError::ShuttingDown)
        );
    }
}
