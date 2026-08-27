//! The anti-replay window and the send counter.
//!
//! **Authority:** ADR-0001 §7.2 (the 64-bit counter nonce and the
//! `REJECT_AFTER_MESSAGES` bound), §7.6, §8 ("the `Session`, its keys, its
//! counters, and its replay window all persist" across a transport change);
//! `docs/reliability.md` §6.5.
//!
//! # A sliding-window bitmap, and why the size is stated
//!
//! WireGuard's window is 2048 entries. The size is a *reordering tolerance*: a
//! packet more than 2048 behind the highest accepted counter is refused, because
//! keeping an unbounded window is an unbounded allocation an attacker drives.
//!
//! # Replay detection is `FATAL`
//!
//! The registry classifies `CRYPTO.REPLAY_DETECTED` `FATAL`/`CRITICAL`. A
//! duplicate under a valid key is either an attack or a defect, and neither is
//! something to retry.

/// The window size, in counters.
pub const WINDOW_BITS: u64 = 2048;

/// The anti-replay window for one key generation.
///
/// **Survives a transport change** (§8) and a path migration (§6.5), and is
/// **lost** on a rekey, a process restart, and a suspend past the rekey window —
/// which is exactly §6.5's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: u64,
    /// One bit per counter below `highest`, `bitmap[0]` being `highest − 1`.
    bitmap: Vec<u64>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window. Counter zero has not been seen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest: 0,
            #[allow(clippy::cast_possible_truncation)]
            bitmap: vec![0u64; (WINDOW_BITS / 64) as usize],
        }
    }

    /// The highest counter accepted so far.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
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
            let shift = counter - self.highest;
            self.shift(shift);
            self.highest = counter;
            // The new highest is itself seen; index 0 is highest − 1, so the
            // highest is implied rather than stored.
        } else {
            let behind = self.highest - counter;
            self.set_bit(behind);
        }
        true
    }

    fn bit(&self, behind: u64) -> bool {
        if behind == 0 {
            // `highest` itself is always considered seen.
            return true;
        }
        let idx = ((behind - 1) / 64) as usize;
        let off = (behind - 1) % 64;
        self.bitmap.get(idx).is_some_and(|w| (w >> off) & 1 == 1)
    }

    fn set_bit(&mut self, behind: u64) {
        if behind == 0 {
            return;
        }
        let idx = ((behind - 1) / 64) as usize;
        let off = (behind - 1) % 64;
        if let Some(w) = self.bitmap.get_mut(idx) {
            *w |= 1u64 << off;
        }
    }

    fn shift(&mut self, by: u64) {
        if by >= WINDOW_BITS {
            for w in &mut self.bitmap {
                *w = 0;
            }
            // The old highest becomes seen only if it is still in range, which it
            // is not.
            return;
        }
        // Shifting the whole bitmap up by `by` bits, then marking the old
        // highest as seen at its new offset.
        let words = (by / 64) as usize;
        let bits = by % 64;
        let len = self.bitmap.len();
        if words > 0 {
            for i in (0..len).rev() {
                self.bitmap[i] = if i >= words {
                    self.bitmap[i - words]
                } else {
                    0
                };
            }
        }
        if bits > 0 {
            let mut carry = 0u64;
            for w in &mut self.bitmap {
                let next = *w >> (64 - bits);
                *w = (*w << bits) | carry;
                carry = next;
            }
        }
        // The previous `highest` is now `by` behind the new one and was seen.
        self.set_bit(by);
    }
}

/// The send counter, with `REJECT_AFTER_MESSAGES` as its ceiling.
///
/// The counter is the AEAD nonce, so exhausting it and continuing would reuse a
/// nonce — the single worst failure mode available to a stream cipher. Hence
/// [`SendCounter::take_next`] returns `None` rather than wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendCounter(u64);

impl SendCounter {
    /// A fresh counter.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// The next counter, or `None` when the generation is exhausted.
    ///
    /// Named `take_next` rather than `next` so it cannot be mistaken for an
    /// iterator step: exhausting this counter is not "the sequence ended", it is
    /// "sending again would reuse an AEAD nonce".
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
