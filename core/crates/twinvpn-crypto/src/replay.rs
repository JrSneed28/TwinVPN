//! The anti-replay receive window, and the counter discipline around it.
//!
//! **Authority:** ADR-0001 §7.1 ("64-bit nonce counter + 8192-bit sliding
//! receive window (RFC 6479 style)"), §7.2, §11 item 2, RFC 6479.
//!
//! # The composition rule this type exists to protect
//!
//! ADR-0001 §7.2 calls it "the single most important composition rule in this
//! ADR":
//!
//! > "Switching modes MUST NOT re-run the L-DATA handshake, **MUST NOT reset the
//! > L-DATA nonce counter or replay window**, and MUST NOT alter any L-DATA
//! > security property."
//!
//! And §7.3.2 RS-3 says the same of resumption:
//!
//! > "Resumption re-binds an existing `Tunnel` to a new `Path`. It MUST NOT
//! > create a second `Session`, reset counters, **or reset the replay window**."
//!
//! So [`ReplayWindow`] has **no `reset`, no `clear`, and no `set_highest`**. The
//! only mutation is [`ReplayWindow::accept`], which moves the window strictly
//! forward. A caller that wanted to reset it would have to construct a new one,
//! which is visible at the call site — and the one legitimate construction, a
//! fresh handshake, does exactly that.
//!
//! # Not weakenable
//!
//! The window size is a `const`, not a parameter. There is no constructor taking
//! a width, no feature that widens the acceptance, and no "lenient" mode. A
//! smaller window is a correctness problem on a reordering path; a larger one is
//! a longer replay horizon; either being *configurable* is the property this
//! module refuses to have.

use crate::{CryptoError, Result};

/// The window width in bits. ADR-0001 §7.1: 8192.
pub const WINDOW_BITS: u64 = 8192;

/// The window as `u64` words.
const WORDS: usize = (WINDOW_BITS / 64) as usize;

/// `REJECT_AFTER_MESSAGES` — ADR-0001 §7.2: `2^64 - 2^13 - 1`.
///
/// A counter at or above this makes the keys unusable; WireGuard's own bound,
/// reproduced exactly rather than approximated.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

/// `REKEY_AFTER_MESSAGES` — ADR-0001 §7.2: `2^60`.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// A sliding anti-replay window over a 64-bit counter.
///
/// `Debug` shows the highest counter and nothing else: the bitmap is a traffic
/// pattern, and a support bundle that carried it would describe which packets a
/// device received.
pub struct ReplayWindow {
    /// The highest counter accepted so far. Zero means "nothing accepted yet",
    /// and counter 0 is therefore acceptable exactly once — see
    /// [`Self::accept`].
    highest: u64,
    /// Bit `i` records that counter `highest - i` was seen.
    bitmap: [u64; WORDS],
    /// Whether anything has been accepted. Distinguishes "highest == 0 because
    /// nothing arrived" from "counter 0 arrived", which a bare `highest` cannot.
    started: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// A window for a freshly established session.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; WORDS],
            started: false,
        }
    }

    /// The highest counter accepted so far, or `None` if nothing has been.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        if self.started {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Whether `counter` would be accepted, **without** recording it.
    ///
    /// For a caller that must decide before it has authenticated the frame. The
    /// discipline WireGuard uses and this type assumes: *check* before the AEAD
    /// to shed obvious replays cheaply, then [`Self::accept`] only **after** the
    /// AEAD succeeds. Recording an unauthenticated counter would let an attacker
    /// advance the window with forged frames and lock out the real peer.
    #[must_use]
    pub fn would_accept(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if !self.started {
            return true;
        }
        if counter > self.highest {
            return true;
        }
        let behind = self.highest - counter;
        if behind >= WINDOW_BITS {
            return false;
        }
        !self.is_set(behind)
    }

    /// Records `counter` as received, returning an error if it is a replay.
    ///
    /// **Call only after the AEAD has authenticated the frame.**
    ///
    /// # Errors
    ///
    /// [`CryptoError::ReplayDetected`] if `counter` has been seen, has fallen
    /// out of the window, or is at or above [`REJECT_AFTER_MESSAGES`].
    pub fn accept(&mut self, counter: u64) -> Result<()> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(CryptoError::ReplayDetected { counter });
        }
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.set(0);
            return Ok(());
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.shift(shift);
            self.highest = counter;
            self.set(0);
            return Ok(());
        }
        let behind = self.highest - counter;
        if behind >= WINDOW_BITS {
            return Err(CryptoError::ReplayDetected { counter });
        }
        if self.is_set(behind) {
            return Err(CryptoError::ReplayDetected { counter });
        }
        self.set(behind);
        Ok(())
    }

    fn is_set(&self, behind: u64) -> bool {
        let w = (behind / 64) as usize;
        let b = behind % 64;
        self.bitmap[w] & (1u64 << b) != 0
    }

    fn set(&mut self, behind: u64) {
        let w = (behind / 64) as usize;
        let b = behind % 64;
        self.bitmap[w] |= 1u64 << b;
    }

    /// Slides the bitmap forward by `shift` positions.
    fn shift(&mut self, shift: u64) {
        if shift >= WINDOW_BITS {
            self.bitmap = [0; WORDS];
            return;
        }
        let words = (shift / 64) as usize;
        let bits = shift % 64;
        if words > 0 {
            for i in (words..WORDS).rev() {
                self.bitmap[i] = self.bitmap[i - words];
            }
            for slot in self.bitmap.iter_mut().take(words) {
                *slot = 0;
            }
        }
        if bits > 0 {
            let mut carry = 0u64;
            for slot in &mut self.bitmap {
                let next = *slot >> (64 - bits);
                *slot = (*slot << bits) | carry;
                carry = next;
            }
        }
    }
}

impl core::fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest())
            .field("bits", &WINDOW_BITS)
            .finish()
    }
}

/// The send-side counter.
///
/// Separate from the receive window because they are separate rules: the sender
/// must never reuse a nonce, and the receiver must never accept one twice. A
/// single "counter" type doing both is how a rekey comes to reset one of them.
#[derive(Debug)]
pub struct SendCounter {
    next: u64,
}

impl Default for SendCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SendCounter {
    /// A counter for a freshly established session.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Takes the next nonce.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RekeyFailed`] once [`REJECT_AFTER_MESSAGES`] is reached.
    /// ADR-0001 §7.2: past that bound "keys are unusable and are zeroed" — so
    /// this refuses rather than wrapping, because a wrapped nonce with the same
    /// key is a catastrophic AEAD failure, not a counter overflow.
    pub fn take(&mut self) -> Result<u64> {
        if self.next >= REJECT_AFTER_MESSAGES {
            return Err(CryptoError::RekeyFailed {
                step: "REJECT_AFTER_MESSAGES reached; the key is unusable",
            });
        }
        let n = self.next;
        self.next += 1;
        Ok(n)
    }

    /// Whether a rekey is due on volume grounds (`REKEY_AFTER_MESSAGES`).
    #[must_use]
    pub const fn rekey_due(&self) -> bool {
        self.next >= REKEY_AFTER_MESSAGES
    }

    /// How many messages have been sent under this key.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_order_stream_is_accepted() {
        let mut w = ReplayWindow::new();
        for c in 0..1000 {
            w.accept(c).expect("in order");
        }
        assert_eq!(w.highest(), Some(999));
    }

    /// **Attack test.** The base case: a frame replayed immediately.
    #[test]
    fn an_immediate_replay_is_rejected() {
        let mut w = ReplayWindow::new();
        w.accept(5).expect("first");
        let err = w.accept(5).expect_err("replay");
        assert!(matches!(err, CryptoError::ReplayDetected { counter: 5 }));
    }

    /// **Attack test.** A frame replayed after the window has moved on, but
    /// while it is still inside the window.
    #[test]
    fn a_replay_from_inside_the_window_is_rejected() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("first");
        w.accept(4000).expect("jump");
        w.accept(100).expect("late but unseen");
        let err = w.accept(100).expect_err("replay");
        assert!(matches!(err, CryptoError::ReplayDetected { counter: 100 }));
    }

    /// **Attack test.** A frame from before the window is rejected outright: an
    /// attacker who recorded traffic long ago must not be able to inject it.
    #[test]
    fn a_frame_older_than_the_window_is_rejected() {
        let mut w = ReplayWindow::new();
        w.accept(0).expect("first");
        w.accept(WINDOW_BITS + 100).expect("jump past the window");
        let err = w.accept(1).expect_err("too old");
        assert!(matches!(err, CryptoError::ReplayDetected { counter: 1 }));
        // And the boundary is exactly WINDOW_BITS behind.
        let oldest_ok = (WINDOW_BITS + 100) - (WINDOW_BITS - 1);
        assert!(w.would_accept(oldest_ok));
        assert!(!w.would_accept(oldest_ok - 1));
    }

    /// Out-of-order delivery inside the window is normal on a lossy or
    /// multipath link and must be accepted — a window that rejected it would
    /// turn reordering into packet loss.
    #[test]
    fn out_of_order_delivery_inside_the_window_is_accepted_once_each() {
        let mut w = ReplayWindow::new();
        w.accept(100).expect("first");
        for c in [99u64, 90, 50, 1] {
            w.accept(c)
                .unwrap_or_else(|_| panic!("{c} should be accepted"));
        }
        for c in [99u64, 90, 50, 1, 100] {
            assert!(
                w.accept(c).is_err(),
                "{c} should be a replay the second time"
            );
        }
    }

    /// **Attack test.** A large forward jump must clear the bitmap, so that a
    /// counter that was seen before the jump does not appear unseen afterwards
    /// — and must not make a *stale* counter acceptable.
    #[test]
    fn a_jump_beyond_the_window_clears_it_without_re_admitting_anything() {
        let mut w = ReplayWindow::new();
        w.accept(10).expect("first");
        w.accept(10 + WINDOW_BITS * 3).expect("jump");
        assert!(w.accept(10).is_err(), "an old counter must stay rejected");
        assert!(
            w.accept(10 + WINDOW_BITS * 3).is_err(),
            "and so must the newest"
        );
    }

    /// A shift by an exact multiple of 64 exercises the word-copy path; a shift
    /// by a non-multiple exercises the bit-carry path. Both are easy to get
    /// wrong and both would silently re-admit a replayed frame.
    #[test]
    fn the_bitmap_shift_is_correct_across_word_and_bit_boundaries() {
        for step in [1u64, 63, 64, 65, 127, 128, 4095, 8191] {
            let mut w = ReplayWindow::new();
            w.accept(0).expect("first");
            w.accept(step).expect("step");
            assert!(
                w.accept(0).is_err(),
                "counter 0 was re-admitted after a shift of {step}"
            );
            assert!(
                w.accept(step).is_err(),
                "counter {step} was re-admitted after its own shift"
            );
        }
    }

    /// `would_accept` must agree with `accept`, or a caller that pre-filters
    /// will drop frames the window would have taken.
    #[test]
    fn would_accept_agrees_with_accept() {
        let mut w = ReplayWindow::new();
        for c in [0u64, 5, 3, 900, 899, 4096] {
            let predicted = w.would_accept(c);
            let actual = w.accept(c).is_ok();
            assert_eq!(predicted, actual, "disagreement at {c}");
        }
    }

    /// ADR-0001 §7.2's `REJECT_AFTER_MESSAGES`, exactly.
    #[test]
    fn the_reject_after_messages_bound_is_the_adrs_value() {
        assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13) - 1);
        assert_eq!(REKEY_AFTER_MESSAGES, 1u64 << 60);
        let mut w = ReplayWindow::new();
        assert!(!w.would_accept(REJECT_AFTER_MESSAGES));
        assert!(w.accept(REJECT_AFTER_MESSAGES).is_err());
    }

    /// **Attack test.** A nonce must never be reused under one key, so the send
    /// counter refuses rather than wrapping.
    #[test]
    fn the_send_counter_refuses_rather_than_wrapping() {
        let mut c = SendCounter::new();
        assert_eq!(c.take().expect("0"), 0);
        assert_eq!(c.take().expect("1"), 1);
        assert!(!c.rekey_due());
        // Drive it to the bound without iterating 2^64 times.
        let mut c = SendCounter {
            next: REJECT_AFTER_MESSAGES - 1,
        };
        assert_eq!(c.take().expect("last"), REJECT_AFTER_MESSAGES - 1);
        assert!(c.take().is_err(), "the counter must not wrap");
    }

    #[test]
    fn the_send_counter_signals_a_volume_rekey() {
        let c = SendCounter {
            next: REKEY_AFTER_MESSAGES,
        };
        assert!(c.rekey_due());
        assert_eq!(c.sent(), REKEY_AFTER_MESSAGES);
    }

    /// The type carries no way to reset the window, which is ADR-0001 §7.2's
    /// composition rule and §7.3.2 RS-3 made structural. This test is a
    /// statement of intent that a future `reset` would have to delete.
    #[test]
    fn there_is_no_way_to_move_the_window_backwards() {
        let mut w = ReplayWindow::new();
        w.accept(5000).expect("first");
        // Every public mutation is `accept`, and `accept` never lowers
        // `highest`.
        for c in [0u64, 1, 4999] {
            let _ = w.accept(c);
            assert_eq!(w.highest(), Some(5000));
        }
    }

    #[test]
    fn debug_shows_the_high_water_mark_and_not_the_traffic_pattern() {
        let mut w = ReplayWindow::new();
        w.accept(7).expect("first");
        let s = format!("{w:?}");
        assert!(s.contains("highest: Some(7)"));
        assert!(!s.contains("bitmap"));
    }
}
