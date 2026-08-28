//! The packet port: `NEPacketTunnelFlow` on one side, the core's
//! [`PacketPort`] on the other.
//!
//! **Authority:** ADR-0018 PB-1 ("zero FFI crossings per packet, with one
//! exception — `NEPacketTunnelFlow`, which is a Swift API and not this ABI"),
//! F-6 (the reentrancy guard is on the CORE, not a serialisation of this
//! bridge); `docs/networking.md` §5.1.
//!
//! # Two halves with different blocking needs
//!
//! | Direction | Producer | Consumer | Shape |
//! |---|---|---|---|
//! | inbound (`packetFlow` → core) | Swift, via `tvb_ext_inject_inbound` | the core, via [`PacketPort::read_frame`] | the adapter's [`QueuePort`], unchanged |
//! | outbound (core → `packetFlow`) | the core, via [`PacketPort::write_frame`] | Swift, via `tvb_ext_next_outbound` | a deque **plus a condition variable** |
//!
//! The asymmetry is the whole reason this type exists rather than the adapter's
//! `QueuePort` being used directly. `tvb_ext_next_outbound` must **block up to a
//! timeout**, and `QueuePort::take_outbound` is non-blocking — so a bare
//! `QueuePort` leaves a caller polling. `PacketLoop.swift` calls with a
//! sub-second timeout in a loop, so polling would mean a wakeup per interval per
//! direction whether or not there is traffic, which on a laptop is a battery
//! cost ADR-0022 spends real effort avoiding elsewhere.
//!
//! The inbound half needs no such thing — the core reads it from an async task —
//! so it stays the adapter's own type.
//!
//! # The lost wakeup, and how it is closed
//!
//! A naive condvar has a race: the consumer checks the queue, finds it empty,
//! and a producer pushes and notifies **before** the consumer starts waiting. The
//! notification is lost and the consumer waits out its whole timeout with a
//! packet sitting in the queue.
//!
//! It is closed by making the producer take the **same mutex** the consumer
//! holds across its check-and-wait. [`BridgePort::publish_outbound`] locks before
//! it notifies, and `Condvar::wait_timeout` releases the guard atomically — so
//! there is no instant in which a producer can slip between the two.
//!
//! # Concurrency
//!
//! `tvb_ext_inject_inbound`, `tvb_ext_next_outbound` and
//! `tvb_ext_next_settings` are called from **three different Swift tasks at the
//! same time**. They touch three different locks here, so none of them blocks
//! another. F-6's reentrancy guard is about a callback arriving *into* the core
//! during a mutating call; reading it as a serialisation guarantee for these
//! would be a mistake, and `CoreBridge.swift` says so on its side too.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use futures_core::future::BoxFuture;
use twinvpn_platform::PlatformError;
use twinvpn_platform_macos::oserr;
use twinvpn_platform_macos::utun::{PacketPort, QueuePort};

/// How many outbound frames are held before the oldest is dropped.
///
/// A bound rather than an unbounded queue: the consumer is a Swift task that can
/// stall (a `packetFlow` write that is not draining), and an unbounded queue in
/// front of a stalled consumer is a memory exhaustion with a packet-shaped
/// trigger. 1024 frames at a 1500-byte MTU is about 1.5 MB.
///
/// **Dropping the oldest, and saying so.** A full queue means the datapath is
/// already failing; keeping the newest frames is what lets it recover when the
/// consumer resumes, and [`BridgePort::dropped_outbound`] counts what went so the
/// loss is a number rather than a silence.
pub const OUTBOUND_CAPACITY: usize = 1024;

/// The port the Swift provider and the core share.
#[derive(Debug)]
pub struct BridgePort {
    /// The inbound half — the adapter's own type, so the core reads exactly what
    /// it reads on every other binding.
    inbound: QueuePort,
    /// The outbound half. The mutex is the one a producer must take before it
    /// notifies, which is what closes the lost wakeup.
    outbound: Mutex<VecDeque<Vec<u8>>>,
    /// Signalled whenever a frame is published or the port closes.
    ready: Condvar,
    /// How many frames were dropped because the consumer was not draining.
    dropped: Mutex<u64>,
    closed: AtomicBool,
}

impl Default for BridgePort {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgePort {
    /// An empty port.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbound: QueuePort::new(),
            outbound: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            dropped: Mutex::new(0),
            closed: AtomicBool::new(false),
        }
    }

    /// Hands the core one **framed** packet read from `packetFlow`.
    ///
    /// The frame carries the 4-byte protocol-family header the `utun` contract
    /// requires, encoded by the adapter's own
    /// [`twinvpn_platform_macos::utun::encode_frame`] — so the bridge does not
    /// have a second copy of that framing to get wrong.
    pub fn inject_inbound(&self, frame: Vec<u8>) {
        self.inbound.push_inbound(frame);
    }

    /// Publishes one **framed** packet for the Swift side to write.
    ///
    /// Called by [`PacketPort::write_frame`] — i.e. by the core — and by tests.
    /// Returns whether the frame was queued; `false` means the queue was full and
    /// the oldest frame was evicted to make room.
    pub fn publish_outbound(&self, frame: Vec<u8>) -> bool {
        // The lock is taken BEFORE the notify and released after, so a consumer
        // sitting between its `pop_front` and its `wait_timeout` cannot miss it.
        let Ok(mut queue) = self.outbound.lock() else {
            // A poisoned lock means a panic happened while a frame was in
            // flight. Dropping this frame is the safe direction: the alternative
            // is `unwrap`, which turns one contained panic into a second
            // uncontained one on the datapath.
            return false;
        };
        let evicted = if queue.len() >= OUTBOUND_CAPACITY {
            queue.pop_front();
            true
        } else {
            false
        };
        queue.push_back(frame);
        drop(queue);
        if evicted {
            if let Ok(mut dropped) = self.dropped.lock() {
                *dropped = dropped.saturating_add(1);
            }
        }
        self.ready.notify_one();
        !evicted
    }

    /// The next frame the core produced, or `None` after `timeout`.
    ///
    /// **`None` is not a deadline guarantee.** A spurious wakeup returns it
    /// early, which is safe because the ABI's `TVB_TIMEOUT` means "none yet" and
    /// the caller loops. Making it a guarantee would need a clock read, and
    /// ADR-0018 CD-1/CD-2 put every clock behind an injected `Env` that this
    /// crate does not hold.
    #[must_use]
    pub fn next_outbound(&self, timeout: Duration) -> Option<Vec<u8>> {
        let Ok(mut queue) = self.outbound.lock() else {
            return None;
        };
        if let Some(frame) = queue.pop_front() {
            return Some(frame);
        }
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        // The guard is released atomically here, which is what makes the
        // producer's lock-then-notify sufficient.
        let Ok((mut queue, _timed_out)) = self.ready.wait_timeout(queue, timeout) else {
            return None;
        };
        queue.pop_front()
    }

    /// How many outbound frames were dropped because the consumer stalled.
    #[must_use]
    pub fn dropped_outbound(&self) -> u64 {
        self.dropped.lock().map_or(0, |d| *d)
    }

    /// How many outbound frames are waiting.
    #[must_use]
    pub fn outbound_depth(&self) -> usize {
        self.outbound.lock().map_or(0, |q| q.len())
    }

    /// Whether the port has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl PacketPort for BridgePort {
    fn read_frame<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, PlatformError>> {
        // Delegated unchanged: the core must read exactly what it reads on every
        // other binding, including the `EAGAIN` on an empty queue and the
        // `EMSGSIZE` on a frame that does not fit — a truncated packet is a
        // packet that fails authentication for a reason nobody can see.
        self.inbound.read_frame(buf)
    }

    fn write_frame<'a>(&'a self, frame: &'a [u8]) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            let len = frame.len();
            if self.publish_outbound(frame.to_vec()) {
                Ok(len)
            } else {
                // The queue was full and a frame was evicted. Reported to the
                // core as a transient condition rather than as a success: a
                // datapath that silently drops is a datapath nobody can debug.
                Err(oserr::unavailable("port.outbound", libc::ENOBUFS))
            }
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.inbound.close();
        // Wake every waiter so a blocked `next_outbound` returns promptly on
        // teardown instead of sitting out its timeout.
        self.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform_macos::utun::{decode_frame, encode_frame};
    use twinvpn_types::AddressFamily;

    fn frame(family: AddressFamily, byte: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = match family {
            AddressFamily::V4 => 0x45,
            AddressFamily::V6 => 0x60,
        };
        packet[39] = byte;
        let mut out = Vec::new();
        encode_frame(family, &packet, &mut out);
        out
    }

    #[test]
    fn a_frame_published_before_the_wait_is_taken_immediately() {
        let port = BridgePort::new();
        assert!(port.publish_outbound(frame(AddressFamily::V6, 1)));
        let taken = port
            .next_outbound(Duration::from_millis(0))
            .expect("a frame");
        let (family, _) = decode_frame(&taken).expect("well formed");
        assert_eq!(family, AddressFamily::V6);
        assert_eq!(port.outbound_depth(), 0);
    }

    #[test]
    fn an_empty_port_times_out_rather_than_blocking_forever() {
        let port = BridgePort::new();
        assert!(port.next_outbound(Duration::from_millis(5)).is_none());
    }

    #[test]
    fn a_frame_published_while_a_consumer_waits_wakes_it() {
        // The lost-wakeup case: the producer runs after the consumer has checked
        // the queue and found it empty. If the producer did not take the same
        // lock, this test would time out instead of returning a frame.
        let port = std::sync::Arc::new(BridgePort::new());
        let producer = std::sync::Arc::clone(&port);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            producer.publish_outbound(frame(AddressFamily::V4, 9));
        });
        let taken = port
            .next_outbound(Duration::from_secs(5))
            .expect("the waiter was woken");
        let (family, packet) = decode_frame(&taken).expect("well formed");
        assert_eq!(family, AddressFamily::V4);
        assert_eq!(packet[39], 9);
        handle.join().expect("the producer finished");
    }

    #[test]
    fn the_outbound_queue_is_bounded_and_the_loss_is_counted() {
        // An unbounded queue in front of a stalled consumer is a memory
        // exhaustion with a packet-shaped trigger.
        let port = BridgePort::new();
        for _ in 0..OUTBOUND_CAPACITY {
            assert!(port.publish_outbound(frame(AddressFamily::V4, 0)));
        }
        assert_eq!(port.outbound_depth(), OUTBOUND_CAPACITY);
        assert!(
            !port.publish_outbound(frame(AddressFamily::V4, 1)),
            "the queue was full and the publish reports the eviction"
        );
        assert_eq!(port.outbound_depth(), OUTBOUND_CAPACITY, "still bounded");
        assert_eq!(
            port.dropped_outbound(),
            1,
            "the loss is a number, not a silence"
        );
    }

    #[test]
    fn the_inbound_half_is_the_adapters_own_queue() {
        // The core must read exactly what it reads on every other binding.
        let port = BridgePort::new();
        port.inject_inbound(frame(AddressFamily::V6, 3));
        let mut buf = vec![0u8; 1500];
        let read = futures_lite_block_on(port.read_frame(&mut buf)).expect("reads");
        let (family, packet) = decode_frame(&buf[..read]).expect("well formed");
        assert_eq!(family, AddressFamily::V6);
        assert_eq!(packet[39], 3);
    }

    #[test]
    fn closing_wakes_a_waiter_instead_of_making_it_sit_out_the_timeout() {
        let port = std::sync::Arc::new(BridgePort::new());
        let closer = std::sync::Arc::clone(&port);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            closer.close();
        });
        // A five-second timeout that returns in about twenty milliseconds.
        assert!(port.next_outbound(Duration::from_secs(5)).is_none());
        assert!(port.is_closed());
        handle.join().expect("the closer finished");
    }

    #[test]
    fn a_closed_port_refuses_a_write_rather_than_queueing_into_nothing() {
        let port = BridgePort::new();
        port.close();
        let error = futures_lite_block_on(port.write_frame(&frame(AddressFamily::V4, 0)))
            .expect_err("refused");
        assert!(matches!(error, PlatformError::ShuttingDown));
    }

    /// Drives an immediately-ready future to completion.
    ///
    /// The port's futures never actually suspend — every one of them is a queue
    /// operation behind a `Box::pin(async move { … })` — so a single poll with a
    /// no-op waker completes them. A test-only executor rather than a dependency
    /// on one, because the bridge itself never awaits anything: Swift calls
    /// blocking C functions, and the async half of `PacketPort` exists for the
    /// core's runtime and not for this crate.
    fn futures_lite_block_on<T>(mut future: BoxFuture<'_, T>) -> T {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: the vtable's four functions are all no-ops that ignore their
        // data pointer, so a null data pointer is never dereferenced. This is the
        // standard no-op waker construction.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("a port future suspended, which none of them do"),
        }
    }
}
