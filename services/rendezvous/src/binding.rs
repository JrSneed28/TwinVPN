//! Binding a claimed `device_id` to the authenticated channel identity.
//!
//! # The hole this closes
//!
//! Before TLS, `ATTACH` was an unauthenticated **claim**: anyone who could open
//! a socket could say "I am `device_id` D" and receive D's `CALL`s. The bodies
//! stay Rule-B signed and opaque, so that was a delivery-redirection and
//! impersonation hole rather than a confidentiality one — but a hole.
//!
//! [`crate::tls`] now proves that the peer holds the private half of the key it
//! presented. This module is the other half: it makes the claimed `device_id`
//! answerable to that key.
//!
//! # The invariant, stated exactly
//!
//! **A `device_id` belongs to at most one channel identity, and a channel
//! identity speaks for at most one `device_id`, for the life of the binding.**
//!
//! - the first `ATTACH(D)` on a channel holding key `K` records `K ↔ D`;
//! - `ATTACH(D')` on that same channel with `D' ≠ D` is **refused**;
//! - `ATTACH(D)` from any channel holding `K' ≠ K` is **refused** while `K ↔ D`
//!   is live.
//!
//! Refusal is `CONTROL.CHANNEL_BINDING_MISMATCH` — FATAL, CRITICAL, and
//! `trust-boundaries.md` §4's words for it are "**a security event, never a
//! parse error**". That is the right classification here for the same reason it
//! is there: a mismatch is a message being lifted onto a channel that is not
//! entitled to it.
//!
//! # What this is, and what it is not — stated plainly
//!
//! This is **channel-pinned** binding. It is not a derivation. It closes
//! impersonation of a device that is attached, or that has attached within
//! [`BindingLimits::ttl`], which is every device in normal operation and is the
//! attack the integration lead named. It does **not** close first-contact
//! impersonation: an attacker who attaches as D *before* the real D ever does
//! holds the binding until it lapses.
//!
//! Closing that needs the server to compute D from the presented key, and
//! `identifiers.md` §2 fixes exactly how:
//!
//! ```text
//! identity_id = SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)))
//! device_id   = identity_id of generation 0
//! ```
//!
//! That derivation is implemented, tested and owned — in
//! `core/crates/twinvpn-trust`'s `derive_device_id`, which a service artifact
//! may not link (`services/Cargo.toml`: the only permitted edge into `/core` is
//! `twinvpn-schema`). **Re-deriving it here is precisely finding W-23's mistake**
//! — "a specified derivation is not ours to improve" — and would be worse than
//! the gap, because a wrong `device_id` derivation names the wrong device.
//!
//! So the seam is a trait. [`ChannelPinned`] is what ships; [`Binding`]'s other
//! implementor is a one-file change once the derivation is reachable, and
//! nothing above this module needs to move. `README.md` §8 carries the ask.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use crate::frame::DeviceId;
use crate::tls::ChannelIdentity;

/// Why a claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This channel already speaks for a different device.
    ChannelSpeaksForAnotherDevice,
    /// Another live channel already speaks for this device.
    DeviceHeldByAnotherChannel,
}

/// The outcome of checking a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The claim is consistent with the channel identity.
    Accepted,
    /// Refused. `CONTROL.CHANNEL_BINDING_MISMATCH`.
    Refused(Refusal),
}

/// How a claimed `device_id` is made answerable to a channel identity.
///
/// One method, so an implementation cannot answer differently in two places.
pub trait Binding: std::fmt::Debug + Send + Sync {
    /// Decides whether `channel` may speak for `device_id`, recording the
    /// binding when it may.
    fn claim(&mut self, channel: &ChannelIdentity, device_id: DeviceId, now: Instant) -> Claim;

    /// Releases a binding when its connection closes.
    fn release(&mut self, channel: &ChannelIdentity, now: Instant);

    /// Drops bindings past their TTL.
    fn sweep(&mut self, now: Instant);

    /// How many bindings are held. For metrics and tests.
    fn len(&self) -> usize;

    /// Whether none are held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bounds on the binding table.
#[derive(Debug, Clone, Copy)]
pub struct BindingLimits {
    /// How long a binding outlives its connection.
    ///
    /// Longer than the S-25 attachment TTL on purpose: a device that drops and
    /// reconnects must find its own binding still there, and an attacker racing
    /// a reconnect must find it *taken*. Shorter than for ever, because a device
    /// that legitimately rotates its identity key must eventually be able to
    /// attach — and because an unbounded table is an unbounded table.
    pub ttl: Duration,
    /// The ceiling on concurrently held bindings.
    pub max_bindings: usize,
}

impl Default for BindingLimits {
    fn default() -> Self {
        Self {
            // Ten minutes: comfortably past a mobile radio transition and a
            // process restart, well short of a key-rotation window.
            ttl: Duration::from_millis(600_000),
            max_bindings: 16_384,
        }
    }
}

#[derive(Debug)]
struct Entry {
    channel: ChannelIdentity,
    expires_at: Instant,
    /// Live connections currently holding this binding. A binding with a live
    /// holder is never evicted for capacity: evicting it would hand an
    /// attacker the very mailbox the binding exists to protect.
    holders: u32,
    arrival: u64,
}

/// The shipped [`Binding`]: first claim wins, and wins exclusively.
#[derive(Debug)]
pub struct ChannelPinned {
    limits: BindingLimits,
    by_device: HashMap<DeviceId, Entry>,
    /// `arrival → device`, so the oldest unheld binding is evictable without a
    /// scan.
    order: BTreeMap<u64, DeviceId>,
    next_arrival: u64,
    refusals: u64,
}

impl ChannelPinned {
    /// A table bounded by `limits`.
    #[must_use]
    pub fn new(limits: BindingLimits) -> Self {
        Self {
            limits,
            by_device: HashMap::new(),
            order: BTreeMap::new(),
            next_arrival: 0,
            refusals: 0,
        }
    }

    /// How many claims have been refused since start.
    #[must_use]
    pub const fn refusals(&self) -> u64 {
        self.refusals
    }

    /// Evicts the oldest binding that no live connection holds.
    fn evict_oldest_unheld(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .find(|(_, d)| self.by_device.get(*d).is_some_and(|e| e.holders == 0))
            .map(|(seq, d)| (*seq, *d));
        match victim {
            Some((seq, device)) => {
                self.order.remove(&seq);
                self.by_device.remove(&device);
                true
            }
            None => false,
        }
    }
}

impl Default for ChannelPinned {
    fn default() -> Self {
        Self::new(BindingLimits::default())
    }
}

impl Binding for ChannelPinned {
    fn claim(&mut self, channel: &ChannelIdentity, device_id: DeviceId, now: Instant) -> Claim {
        self.sweep(now);

        // Does this channel already speak for someone else? Checked first,
        // because it is the cheaper half of the invariant and because a channel
        // that changes its mind is a stronger signal than a contested device.
        if let Some((held, _)) = self
            .by_device
            .iter()
            .find(|(_, e)| e.channel == *channel && e.holders > 0)
        {
            if *held != device_id {
                self.refusals += 1;
                return Claim::Refused(Refusal::ChannelSpeaksForAnotherDevice);
            }
        }

        match self.by_device.get_mut(&device_id) {
            Some(entry) if entry.channel == *channel => {
                entry.expires_at = now + self.limits.ttl;
                entry.holders = entry.holders.saturating_add(1);
                Claim::Accepted
            }
            Some(_) => {
                self.refusals += 1;
                Claim::Refused(Refusal::DeviceHeldByAnotherChannel)
            }
            None => {
                if self.by_device.len() >= self.limits.max_bindings && !self.evict_oldest_unheld() {
                    // Every binding is held by a live connection. Refusing is
                    // the safe direction: admitting would mean forgetting a
                    // binding that is actively protecting a mailbox.
                    self.refusals += 1;
                    return Claim::Refused(Refusal::DeviceHeldByAnotherChannel);
                }
                let arrival = self.next_arrival;
                self.next_arrival += 1;
                self.order.insert(arrival, device_id);
                self.by_device.insert(
                    device_id,
                    Entry {
                        channel: channel.clone(),
                        expires_at: now + self.limits.ttl,
                        holders: 1,
                        arrival,
                    },
                );
                Claim::Accepted
            }
        }
    }

    fn release(&mut self, channel: &ChannelIdentity, now: Instant) {
        for entry in self.by_device.values_mut() {
            if entry.channel == *channel {
                entry.holders = entry.holders.saturating_sub(1);
                if entry.holders == 0 {
                    // The binding OUTLIVES the connection. This is the whole
                    // point: a device that drops and reconnects finds its own
                    // binding, and an attacker racing that reconnect finds it
                    // taken.
                    entry.expires_at = now + self.limits.ttl;
                }
            }
        }
    }

    fn sweep(&mut self, now: Instant) {
        let gone: Vec<DeviceId> = self
            .by_device
            .iter()
            .filter(|(_, e)| e.holders == 0 && e.expires_at <= now)
            .map(|(d, _)| *d)
            .collect();
        for d in gone {
            if let Some(e) = self.by_device.remove(&d) {
                self.order.remove(&e.arrival);
            }
        }
    }

    fn len(&self) -> usize {
        self.by_device.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> ChannelIdentity {
        ChannelIdentity::new(&[n; 64])
    }

    #[test]
    fn a_first_claim_is_accepted() {
        let mut b = ChannelPinned::default();
        assert_eq!(b.claim(&key(1), [1u8; 32], Instant::now()), Claim::Accepted);
    }

    #[test]
    fn a_second_key_cannot_take_an_attached_devices_mailbox() {
        // The attack the integration lead named, refused.
        let mut b = ChannelPinned::default();
        let now = Instant::now();
        assert_eq!(b.claim(&key(1), [7u8; 32], now), Claim::Accepted);
        assert_eq!(
            b.claim(&key(2), [7u8; 32], now),
            Claim::Refused(Refusal::DeviceHeldByAnotherChannel)
        );
        assert_eq!(b.refusals(), 1);
    }

    #[test]
    fn a_channel_cannot_speak_for_a_second_device() {
        let mut b = ChannelPinned::default();
        let now = Instant::now();
        assert_eq!(b.claim(&key(1), [1u8; 32], now), Claim::Accepted);
        assert_eq!(
            b.claim(&key(1), [2u8; 32], now),
            Claim::Refused(Refusal::ChannelSpeaksForAnotherDevice)
        );
    }

    #[test]
    fn the_same_key_may_reattach_freely() {
        let mut b = ChannelPinned::default();
        let now = Instant::now();
        assert_eq!(b.claim(&key(1), [3u8; 32], now), Claim::Accepted);
        b.release(&key(1), now);
        assert_eq!(b.claim(&key(1), [3u8; 32], now), Claim::Accepted);
    }

    #[test]
    fn a_binding_outlives_the_connection_so_a_reconnect_race_is_lost_by_the_attacker() {
        let mut b = ChannelPinned::default();
        let t0 = Instant::now();
        b.claim(&key(1), [4u8; 32], t0);
        b.release(&key(1), t0);
        // The victim's connection is gone; the attacker tries immediately.
        assert_eq!(
            b.claim(&key(9), [4u8; 32], t0 + Duration::from_millis(1)),
            Claim::Refused(Refusal::DeviceHeldByAnotherChannel)
        );
    }

    #[test]
    fn a_binding_does_lapse_so_a_rotated_key_is_not_locked_out_for_ever() {
        let mut b = ChannelPinned::default();
        let t0 = Instant::now();
        b.claim(&key(1), [5u8; 32], t0);
        b.release(&key(1), t0);
        let later = t0 + Duration::from_millis(600_001);
        assert_eq!(b.claim(&key(2), [5u8; 32], later), Claim::Accepted);
    }

    #[test]
    fn a_held_binding_is_never_evicted_for_capacity() {
        let mut b = ChannelPinned::new(BindingLimits {
            max_bindings: 2,
            ..BindingLimits::default()
        });
        let now = Instant::now();
        b.claim(&key(1), [1u8; 32], now);
        b.claim(&key(2), [2u8; 32], now);
        // Both are held; a third must be refused rather than evicting a live
        // binding and handing away the mailbox it protects.
        assert_eq!(
            b.claim(&key(3), [3u8; 32], now),
            Claim::Refused(Refusal::DeviceHeldByAnotherChannel)
        );
        assert!(b.len() <= 2);
    }

    #[test]
    fn an_unheld_binding_is_evictable_so_the_table_stays_bounded() {
        let mut b = ChannelPinned::new(BindingLimits {
            max_bindings: 4,
            ..BindingLimits::default()
        });
        let now = Instant::now();
        for i in 0..1000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            let k = ChannelIdentity::new(&i.to_be_bytes());
            b.claim(&k, id, now);
            b.release(&k, now);
        }
        assert!(b.len() <= 4, "held {}", b.len());
    }
}
