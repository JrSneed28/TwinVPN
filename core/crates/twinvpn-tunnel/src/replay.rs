//! The anti-replay window and the send counter.
//!
//! **Authority:** ADR-0001 §7.1 ("64-bit nonce counter + **8192-bit** sliding
//! receive window (**RFC 6479 style**)"), §7.2 (the counter nonce and the
//! `REJECT_AFTER_MESSAGES` bound), §7.6, §8 ("the `Session`, its keys, its
//! counters, and its replay window all persist" across a transport change);
//! `docs/implementation/ownership.md` §6 ("L-DATA is **unmodified WireGuard**");
//! `docs/reliability.md` §6.5.
//!
//! # The counter starts at zero, and the window starts empty
//!
//! This is the seam defect D-1 lived in, so it is stated rather than implied.
//! There are two origins and they have to agree:
//!
//! | Origin | Value | Why |
//! |---|---|---|
//! | [`SendCounter`]'s first counter | **0** | `ownership.md` §6 requires *unmodified* WireGuard, whose first transport nonce is 0. `REJECT_AFTER_MESSAGES` is a **count of messages**, so with a 0-based counter the last legal value is `REJECT_AFTER_MESSAGES − 1`. |
//! | [`ReplayWindow`]'s initial bitmap | **all clear** | RFC 6479 keeps "seen" in the **bitmap**, never in the window's upper bound. `highest` is a *bound*, not an assertion that the bound was received. |
//!
//! An earlier version of this module treated `highest` as implicitly seen —
//! `bit(0)` returned `true` unconditionally — which made the very first record
//! of every tunnel a replay, classed `FATAL`.
//!
//! **The receiver was the half that was wrong, and that is what decided the
//! fix.** A conforming peer sends counter 0 first, so a receiver that refuses
//! counter 0 is broken against every correct implementation regardless of what
//! its own sender does. Moving [`SendCounter`] to 1 would have made two TwinVPN
//! devices agree with each other and left them both wrong against WireGuard —
//! and `ownership.md` §6 does not permit a modified L-DATA.
//!
//! # Bit `i` means counter `highest − i`
//!
//! Bit 0 is `highest` itself and is set **explicitly** when `highest` is
//! accepted. That is RFC 6479's ring, and it is what makes "nothing has been
//! received yet" and "counter 0 has been received" two distinguishable states —
//! [`ReplayWindow::has_accepted_any`] is the distinction.
//!
//! # A sliding-window bitmap, and why the size is stated
//!
//! The window is **8192** counters, per ADR-0001 §7.1 and ADR-0013 §11.5's
//! per-peer state table (which sizes a peer's fixed memory against an
//! "8192-entry replay bitmap"). The size is a *reordering tolerance*: a packet
//! more than 8192 behind the highest accepted counter is refused, because
//! keeping an unbounded window is an unbounded allocation an attacker drives.
//!
//! # Replay detection is `FATAL`
//!
//! The registry classifies `CRYPTO.REPLAY_DETECTED` `FATAL`/`CRITICAL`. A
//! duplicate under a valid key is either an attack or a defect, and neither is
//! something to retry.

/// The window size, in counters. ADR-0001 §7.1's 8192.
pub const WINDOW_BITS: u64 = 8192;

/// Words in the bitmap.
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize;

/// The anti-replay window for one key generation.
///
/// **Survives a transport change** (§8) and a path migration (§6.5), and is
/// **lost** on a rekey, a process restart, and a suspend past the rekey window —
/// which is exactly §6.5's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    /// The highest counter **accepted** so far. A bound, not an assertion that
    /// it was received — `bit(0)` answers that.
    highest: u64,
    /// Bit `i` represents counter `highest - i`. Bit 0 is `highest` itself.
    bitmap: Vec<u64>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window. **Nothing has been received**, counter 0 included.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: vec![0u64; WINDOW_WORDS],
        }
    }

    /// The highest counter accepted so far.
    ///
    /// Zero both before anything arrives and after counter 0 arrives; the two
    /// are told apart by [`ReplayWindow::has_accepted_any`], because the bitmap
    /// is where "seen" lives.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
    }

    /// Whether any counter has been accepted at all.
    ///
    /// Exists so `highest == 0` is never read as "counter 0 was seen" — the
    /// conflation that made the first packet of every tunnel a replay.
    #[must_use]
    pub fn has_accepted_any(&self) -> bool {
        self.bit(0)
    }

    /// Whether `counter` would be accepted, without recording it.
    #[must_use]
    pub fn would_accept(&self, counter: u64) -> bool {
        if counter >= crate::rekey::REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter > self.highest {
            return true;
        }
        let behind = self.highest - counter;
        if behind >= WINDOW_BITS {
            // Too old to distinguish from a replay, so refused. A bigger window
            // would be an unbounded allocation an attacker drives.
            return false;
        }
        !self.bit(behind)
    }

    /// Accepts `counter`, returning `false` if it is a replay.
    ///
    /// A `false` is `CRYPTO.REPLAY_DETECTED`, which is `FATAL`.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.would_accept(counter) {
            return false;
        }
        if counter > self.highest {
            self.shift(counter - self.highest);
            self.highest = counter;
            // The new highest is recorded EXPLICITLY. RFC 6479 keeps "seen" in
            // the ring, and so does this — which is the whole of the D-1 fix.
            self.set_bit(0);
        } else {
            let behind = self.highest - counter;
            self.set_bit(behind);
        }
        true
    }

    /// Whether the bit `behind` counters below `highest` is set.
    fn bit(&self, behind: u64) -> bool {
        if behind >= WINDOW_BITS {
            return false;
        }
        let idx = (behind / 64) as usize;
        let off = behind % 64;
        self.bitmap.get(idx).is_some_and(|w| (w >> off) & 1 == 1)
    }

    fn set_bit(&mut self, behind: u64) {
        if behind >= WINDOW_BITS {
            return;
        }
        let idx = (behind / 64) as usize;
        let off = behind % 64;
        if let Some(w) = self.bitmap.get_mut(idx) {
            *w |= 1u64 << off;
        }
    }

    /// Slides the window forward by `by` counters: bit `i` moves to bit `i + by`.
    ///
    /// Bits shifted past [`WINDOW_BITS`] fall out of the window, which is what
    /// makes an old counter indistinguishable from a replay and therefore
    /// refused.
    fn shift(&mut self, by: u64) {
        if by >= WINDOW_BITS {
            for w in &mut self.bitmap {
                *w = 0;
            }
            return;
        }
        let words = (by / 64) as usize;
        let bits = u32::try_from(by % 64).unwrap_or(0);
        let len = self.bitmap.len();
        for j in (0..len).rev() {
            let lo = j.checked_sub(words).map_or(0, |k| self.bitmap[k]);
            let carry = if bits == 0 {
                0
            } else {
                j.checked_sub(words + 1)
                    .map_or(0, |k| self.bitmap[k] >> (64 - bits))
            };
            self.bitmap[j] = if bits == 0 { lo } else { (lo << bits) | carry };
        }
    }
}

/// The send counter, with `REJECT_AFTER_MESSAGES` as its ceiling.
///
/// The counter is the AEAD nonce, so exhausting it and continuing would reuse a
/// nonce — the single worst failure mode available to a stream cipher. Hence
/// [`SendCounter::take_next`] returns `None` rather than wrapping.
///
/// **It starts at 0**, which is WireGuard's first transport nonce. See the
/// module documentation for why the receiver, not this, was the half D-1 moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendCounter(u64);

impl SendCounter {
    /// A fresh counter. The first value it yields is **0**.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// The next counter, or `None` when the generation is exhausted.
    ///
    /// Named `take_next` rather than `next` so it cannot be mistaken for an
    /// iterator step: exhausting this counter is not "the sequence ended", it is
    /// "sending again would reuse an AEAD nonce".
    ///
    /// `REJECT_AFTER_MESSAGES` is a **count**, so with a 0-based counter the
    /// last value issued is `REJECT_AFTER_MESSAGES − 1` and exactly that many
    /// messages are sent.
    pub fn take_next(&mut self) -> Option<u64> {
        if self.0 >= crate::rekey::REJECT_AFTER_MESSAGES {
            return None;
        }
        let v = self.0;
        self.0 += 1;
        Some(v)
    }

    /// How many have been issued.
    #[must_use]
    pub const fn issued(self) -> u64 {
        self.0
    }

    /// Whether a rekey is due on the message bound.
    #[must_use]
    pub const fn rekey_due(self) -> bool {
        self.0 >= crate::rekey::REKEY_AFTER_MESSAGES
    }
}
