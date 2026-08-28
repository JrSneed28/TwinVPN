//! The erasing wrapper around `snow`'s transport state.
//!
//! **Authority:** ADR-0001 §7.2 (`REJECT_AFTER_TIME` — "keys are unusable and
//! are **zeroed**"), §7.3.2 RS-3, §11 item 2; ADR-0018 CB-5, CB-6a, CD-I2,
//! DP-4; ADR-0018 §11.3 (`panic = "unwind"` in every shipped profile);
//! `docs/implementation/ownership.md` §6 rule 11 and its
//! "do not weaken … session-key handling"; `docs/threat-model.md` TM-14.
//!
//! # The finding this module answers
//!
//! `snow` 0.10 implements **no `Drop` and no `Zeroize`** on its cipher states.
//! A `StatelessTransportState`'s send and receive keys are each a `[u8; 32]`
//! inside a `Box<dyn Cipher>` allocation, and dropping the state frees those
//! allocations **without overwriting them** — so the session keys go back to the
//! allocator intact, to be handed to whatever asks for 32 bytes next.
//!
//! Until `twinvpn_tunnel::bind` existed, no production code held a
//! `TransportSession`, so the defect was latent. It is now live on every tunnel,
//! and `REJECT_AFTER_TIME`'s "keys … are **zeroed**" was, in fact, a drop.
//!
//! # Why this is `twinvpn-crypto`'s problem and nobody else's
//!
//! CD-I2 makes this crate the only one permitted to name `snow`. A wrapper in
//! `twinvpn-tunnel` would have to name it to reach `rekey_manually`, which
//! `cargo run -p xtask -- lint` refuses. The boundary is here, so the fix is
//! here.
//!
//! # Why `zeroize` is not simply pointed at the key
//!
//! [`zeroize::Zeroize`] needs a `&mut [u8]` over the bytes it is to overwrite.
//! `snow`'s key array is a private field of a private type behind a
//! `Box<dyn Cipher>`; there is no safe way to obtain that slice, and
//! manufacturing one would mean `unsafe` pointer arithmetic over **another
//! crate's private layout** — which is the opposite of what DP-4's `unsafe`
//! allowlist exists for. This crate's `unsafe` stays in [`crate::locked`], where
//! every block is about an allocation this crate itself made.
//!
//! # What actually overwrites the key
//!
//! `snow` has exactly one public API that writes into that array in place:
//! `StatelessTransportState::rekey_manually`, which forwards to
//! `Cipher::set(&mut self, key)` and copies the caller's bytes over the existing
//! ones. It is the *same* allocation the later drop frees, so a `rekey_manually`
//! to an all-zero key is a real overwrite of the real key bytes, performed
//! through a sanctioned API rather than through pointer surgery.
//!
//! The width is pinned at compile time rather than asserted: `rekey_manually`
//! takes a `&[u8; snow::constants::CIPHERKEYLEN]`, so [`ERASURE_KEY`] would stop
//! compiling if `snow` ever changed it.
//!
//! # Why the overwrite cannot be optimised away
//!
//! A store to memory that is about to be freed is exactly the store a compiler
//! is entitled to delete. Two barriers stop it, in this order:
//!
//! 1. [`zeroize::Zeroize::zeroize`] on the buffer that was just handed to
//!    `snow`. `zeroize`'s guarantee is a volatile write followed by
//!    `compiler_fence(SeqCst)`, and that fence is **sequenced after the
//!    `rekey_manually` store**, so the store cannot be sunk past it. This is the
//!    same mechanism [`crate::locked`] relies on, not a second one.
//! 2. [`core::hint::black_box`] over the state. It makes the optimiser assume an
//!    opaque callee may read through that pointer, so the key bytes are not dead
//!    at the point of the drop that follows.
//!
//! # What this does **not** achieve, stated before it is relied on
//!
//! - It does not erase copies the compiler may have left in a register spill or
//!   a stack temporary while the key was in use, nor the copy `snow`'s `Split()`
//!   made on the way into the cipher state. TM-14 already records key extraction
//!   from process memory as **undefended**; this narrows the window, it does not
//!   close it.
//! - It does not reach [`crate::noise::Handshake`]. `snow`'s `HandshakeState`
//!   holds the local static private key and the handshake ephemeral behind
//!   `Box<dyn Dh>`, exposes **no** `rekey_manually` or any other in-place
//!   setter, and destructures itself on the way into the transport state. There
//!   is no API from here that reaches those bytes. That residual is reported as
//!   an integration item rather than papered over.
//! - It is not a secure element. CB-5 row 1 keys never come near this crate.

use snow::StatelessTransportState;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// The value both cipher keys are overwritten with.
///
/// All zeroes rather than random bytes: this function takes no `Env`, CD-2
/// forbids it acquiring one on the side, and CD-3 forbids reaching for the
/// platform CSPRNG here. Zeroes are also what makes the erasure *observable* —
/// see `overwriting_the_cipher_keys_leaves_a_key_independent_constant`, which
/// proves the overwrite happened by showing that two sessions with different
/// keys become indistinguishable after it.
///
/// The array width is `snow::constants::CIPHERKEYLEN`, pinned by
/// `rekey_manually`'s signature rather than by a comment.
const ERASURE_KEY: [u8; 32] = [0u8; 32];

/// A `snow` transport state that is erased before it is freed.
///
/// It is `pub(crate)` deliberately: the only way to obtain an established
/// session in this crate is [`crate::noise::Handshake::into_transport`], and
/// that returns a [`crate::noise::TransportSession`] which holds one of these.
/// There is no path by which a caller gets a bare `StatelessTransportState`,
/// so there is no path by which one is dropped unerased.
pub(crate) struct ErasingTransport {
    state: StatelessTransportState,
    /// Set before the overwrite, never cleared. A session whose keys have been
    /// erased is finished — ADR-0001 §7.2's `REJECT_AFTER_TIME` outcome is
    /// "keys are unusable", and there is no method here that makes one usable
    /// again.
    erased: bool,
}

impl ErasingTransport {
    /// Takes custody of an established transport state.
    pub(crate) const fn new(state: StatelessTransportState) -> Self {
        Self {
            state,
            erased: false,
        }
    }

    /// Whether the keys have been erased.
    pub(crate) const fn is_erased(&self) -> bool {
        self.erased
    }

    /// Overwrites both cipher keys and marks the session finished.
    ///
    /// Idempotent, so the explicit call and the drop cannot double-erase into a
    /// surprise, and so a caller may erase early without having to know whether
    /// anything else already did.
    pub(crate) fn erase(&mut self) {
        if self.erased {
            return;
        }
        // The flag moves **first**. If the overwrite below were ever to unwind
        // — it cannot, `rekey_manually` is infallible — the session would still
        // be refused rather than left usable.
        self.erased = true;
        // Test-only instrumentation. A destructor cannot be observed from safe
        // Rust after the value is gone, and manufacturing an observation with
        // `ManuallyDrop` + `ptr::drop_in_place` would need `unsafe` outside
        // `crate::locked`, which DP-4 does not license for a test. One counter
        // increment, compiled out of every shipped build, is the smaller price.
        #[cfg(test)]
        tests::note_erase();
        overwrite(&mut self.state);
    }

    /// Encrypts under the send key at `nonce`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RekeyFailed`] once the keys are erased — **before** the
    /// AEAD, so a caller can never seal under [`ERASURE_KEY`];
    /// [`CryptoError::HandshakeRejected`] if `snow` refuses the buffers.
    pub(crate) fn write_message(
        &self,
        nonce: u64,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        self.usable()?;
        self.state
            .write_message(nonce, payload, out)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "transport seal",
            })
    }

    /// Decrypts under the receive key at `nonce`.
    ///
    /// # Errors
    ///
    /// As [`Self::write_message`], and [`CryptoError::HandshakeRejected`] on any
    /// authentication failure.
    pub(crate) fn read_message(&self, nonce: u64, frame: &[u8], out: &mut [u8]) -> Result<usize> {
        self.usable()?;
        self.state
            .read_message(nonce, frame, out)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "transport open",
            })
    }

    /// The peer's static, as established by the handshake.
    ///
    /// Still available after erasure: it is a **public** key, it is the identity
    /// the session was established against, and a diagnostic that could not name
    /// the peer of a session it just tore down would be less useful for no
    /// security gain.
    pub(crate) fn remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }

    /// The guard every keyed operation passes through.
    ///
    /// `pub(crate)` so [`crate::noise::TransportSession::seal`] can refuse
    /// **before** it takes a nonce from the send counter: an erased session must
    /// not spend a counter value it can never seal under, because
    /// `twinvpn-tunnel` runs its own counter in lockstep with this one and a
    /// silently consumed nonce would desynchronise the two.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RekeyFailed`] once erased.
    pub(crate) fn usable(&self) -> Result<()> {
        if self.erased {
            Err(CryptoError::RekeyFailed {
                step: "session keys have been erased",
            })
        } else {
            Ok(())
        }
    }
}

impl Drop for ErasingTransport {
    /// ADR-0018 §11.3 pins `panic = "unwind"` in every shipped profile, so a
    /// panic between establishment and an explicit erase is a **real** path out
    /// of a scope holding session keys, not a theoretical one. Erasing in `Drop`
    /// is what makes that path, and every early return, cover the same ground as
    /// the explicit call.
    fn drop(&mut self) {
        self.erase();
    }
}

impl Zeroize for ErasingTransport {
    fn zeroize(&mut self) {
        self.erase();
    }
}

impl ZeroizeOnDrop for ErasingTransport {}

impl core::fmt::Debug for ErasingTransport {
    /// Never renders the state. `snow`'s own `Debug` is already empty, but
    /// relying on a dependency's redaction is relying on a dependency not to
    /// change it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ErasingTransport")
            .field("erased", &self.erased)
            .finish_non_exhaustive()
    }
}

/// Overwrites both of `state`'s cipher keys in place.
///
/// Separated from [`ErasingTransport::erase`] with no flag of its own so the
/// tests below can observe the overwrite through `snow` itself rather than
/// through the flag that records it. See the module documentation for why each
/// of the three statements is here.
fn overwrite(state: &mut StatelessTransportState) {
    let mut key = ERASURE_KEY;
    state.rekey_manually(Some(&key), Some(&key));
    // `zeroize`'s volatile write plus its `compiler_fence(SeqCst)`. The fence is
    // the load-bearing half: it is sequenced after the store above, so that
    // store cannot be sunk past it or deleted as dead.
    key.zeroize();
    // And the optimiser must now assume the state may still be read.
    let _opaque = core::hint::black_box(state);
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use twinvpn_env::virtual_time::VirtualTime;
    use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};

    use super::{overwrite, ErasingTransport, ERASURE_KEY};
    use crate::locked::LockedBytes;
    use crate::noise::{static_public_key, Handshake, HandshakeConfig, Role};
    use crate::prologue::{IdentityBinding, NegotiationBinding, Prologue, TwinnetTag};
    use crate::psk::TwinNetPsk;

    /// A deterministic, **non-cryptographic** entropy source, as
    /// `tests/noise_handshake.rs`: CD-3 bans the platform CSPRNG outside
    /// `twinvpn-env`'s binding, and these tests need reproducibility, not
    /// unpredictability.
    struct CountingEntropy(Mutex<u64>);

    impl Entropy for CountingEntropy {
        fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
            let mut s = self.0.lock().expect("test mutex");
            for b in dst.iter_mut() {
                *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                // Taking the low byte of a PRNG word is the point, not a lost
                // value: `to_le_bytes()[0]` says so without a cast.
                *b = (*s >> 33).to_le_bytes()[0];
            }
            Ok(())
        }
    }

    fn test_env(seed: u64) -> Env {
        let vt = VirtualTime::new(WallClockReading::Unset);
        let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy(Mutex::new(seed)));
        Env::new(EnvParts {
            monotonic: vt.monotonic(),
            elapsed: vt.elapsed(),
            wall: vt.wall(),
            timer: vt.timer(),
            runtime: vt.runtime(),
            entropy: Arc::clone(&entropy),
            rng: Arc::new(SystemRngSource::new(entropy)),
        })
    }

    fn static_key(seed: u8) -> LockedBytes {
        LockedBytes::new_with(32, |dst| {
            dst.fill(seed);
            dst[0] = seed | 0x01;
        })
        .expect("locked static")
    }

    fn prologue() -> Prologue {
        Prologue::new(
            &IdentityBinding {
                twinnet: TwinnetTag::from_twinnet_id("tn-erase"),
                device_id_init: [0x01; 32],
                device_id_resp: [0x02; 32],
                trust_epoch: 1,
                psk_epoch: 1,
                anchor_version: 1,
                delegation_set_digest: [0x03; 32],
            },
            &NegotiationBinding {
                h_initiator: [0x04; 32],
                h_responder: [0x05; 32],
                selection_dcbor: vec![0xa0],
            },
        )
    }

    // Counts `ErasingTransport::erase` calls **on this thread**.
    //
    // Thread-local rather than a global atomic: the test harness gives each
    // `#[test]` its own thread, so a thread-local count is exact, where a
    // process-wide one could be moved by a concurrent test and would turn
    // "the destructor erased" into "something, somewhere, erased".
    thread_local! {
        static ERASE_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    /// Called from [`ErasingTransport::erase`] under `cfg(test)` only.
    pub(super) fn note_erase() {
        ERASE_CALLS.with(|c| c.set(c.get() + 1));
    }

    fn erase_calls() -> usize {
        ERASE_CALLS.with(core::cell::Cell::get)
    }

    /// Runs a whole `Noise_IKpsk2` handshake and returns the **initiator's**
    /// established session. `seed` varies the statics and the PSK, so two calls
    /// with different seeds yield sessions with unrelated keys.
    fn established(seed: u8) -> crate::noise::TransportSession {
        let init_static = static_key(seed);
        let resp_static = static_key(seed ^ 0xff);
        let resp_pub = static_public_key(&resp_static).expect("public");
        let remote = crate::testkit::verified_tunnel_key(&resp_pub);
        let p = prologue();
        let psk = TwinNetPsk::derive(b"pair-secret", &[seed; 32], "tn-erase", 1).expect("psk");

        let mut initiator = Handshake::new(
            &test_env(u64::from(seed)),
            Role::Initiator,
            &HandshakeConfig {
                local_static: &init_static,
                remote_static: Some(&remote),
                psk: &psk,
                prologue: &p,
            },
        )
        .expect("initiator");
        let mut responder = Handshake::new(
            &test_env(u64::from(seed) + 1),
            Role::Responder,
            &HandshakeConfig {
                local_static: &resp_static,
                remote_static: None,
                psk: &psk,
                prologue: &p,
            },
        )
        .expect("responder");

        let mut msg = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = initiator.write_message(&[], &mut msg).expect("initiation");
        responder
            .read_message(&msg[..n], &mut scratch)
            .expect("read initiation");
        let n = responder.write_message(&[], &mut msg).expect("response");
        initiator
            .read_message(&msg[..n], &mut scratch)
            .expect("read response");

        initiator.into_transport().expect("transport")
    }

    /// One probe record, sealed at a fixed nonce so the only thing that can vary
    /// between two calls is the key.
    ///
    /// It goes to `snow` directly rather than through
    /// [`ErasingTransport::write_message`], which refuses an erased session by
    /// design. Bypassing the guard is the whole point: it is what lets a test
    /// *see* the key an erased session is holding instead of taking the flag's
    /// word for it.
    fn probe(t: &crate::noise::TransportSession) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let n = t
            .transport_for_test()
            .state
            .write_message(0, b"erasure-probe", &mut out)
            .expect("probe seal");
        out.truncate(n);
        out
    }

    /// Overwrites a session's keys without touching the flag that records it.
    fn overwrite_only(t: &mut crate::noise::TransportSession) {
        overwrite(&mut t.transport_for_test_mut().state);
    }

    /// **The erasure proof.**
    ///
    /// Two sessions established from *independent* handshakes hold unrelated
    /// send keys, so the same plaintext at the same nonce seals to different
    /// ciphertext. After [`overwrite`], the two produce **byte-identical**
    /// ciphertext — which is only possible if each cipher state's key is now a
    /// value that does not depend on the key it held before. That is the
    /// overwrite, observed through `snow`'s own encryption rather than asserted
    /// from the fact that a function was called.
    ///
    /// # What this proves
    ///
    /// That the 32 bytes `snow` uses as the send key — the bytes living in the
    /// `Box<dyn Cipher>` allocation that the subsequent drop frees — have been
    /// replaced by a key-independent constant, in place, in that allocation.
    ///
    /// # What this does **not** prove
    ///
    /// It does not prove that no copy of the original key survives anywhere else
    /// in the process: a register spill, a stack temporary, or the copy `snow`
    /// made during `Split()` are all outside what any safe API can observe or
    /// reach. TM-14 records key extraction from process memory as undefended and
    /// this test does not change that. It also says nothing about the receive
    /// key beyond the fact that the same call overwrites it — the assertion is
    /// on the send direction only, because that is the one a stateless transport
    /// lets a test drive without a peer.
    #[test]
    fn overwriting_the_cipher_keys_leaves_a_key_independent_constant() {
        let mut a = established(0x11);
        let mut b = established(0x44);

        let before_a = probe(&a);
        let before_b = probe(&b);
        assert_ne!(
            before_a, before_b,
            "two independent handshakes must not already share a send key"
        );

        overwrite_only(&mut a);
        overwrite_only(&mut b);

        let after_a = probe(&a);
        let after_b = probe(&b);
        assert_eq!(
            after_a, after_b,
            "after erasure the ciphertext must no longer depend on the erased key"
        );
        assert_ne!(after_a, before_a, "the key must actually have changed");
        assert_ne!(after_b, before_b, "the key must actually have changed");
    }

    /// The public erasure path performs that same overwrite, rather than only
    /// recording that it happened: a session erased through
    /// [`crate::noise::TransportSession::erase`] seals identically to one whose
    /// keys were overwritten directly.
    #[test]
    fn erase_performs_the_overwrite_and_does_not_merely_record_it() {
        let mut through_api = established(0x11);
        let mut direct = established(0x44);
        through_api.erase();
        overwrite_only(&mut direct);
        assert!(through_api.is_erased());
        assert_eq!(probe(&through_api), probe(&direct));
    }

    /// `Drop` runs the erasure.
    ///
    /// A destructor's effect cannot be read back from safe Rust after the value
    /// is gone, so what is asserted here is that the destructor **called** the
    /// erasure routine — and
    /// `erase_performs_the_overwrite_and_does_not_merely_record_it` is what
    /// establishes that the routine overwrites the key. The two together are the
    /// claim; neither is it alone.
    #[test]
    fn dropping_a_session_runs_the_erasure() {
        let before = erase_calls();
        {
            let _session = established(0x11);
        }
        assert_eq!(
            erase_calls(),
            before + 1,
            "Drop must erase; a panic or an early return must not skip it"
        );
    }

    /// The same, for the path that matters most: an **unwind** through a scope
    /// holding session keys. ADR-0018 §11.3 pins `panic = "unwind"` in every
    /// shipped profile, so this is a live path, not a theoretical one.
    #[test]
    fn an_unwind_through_a_live_session_still_erases_it() {
        let before = erase_calls();
        let outcome = std::panic::catch_unwind(|| {
            let _session = established(0x11);
            panic!("simulated fault while the session is live");
        });
        assert!(outcome.is_err());
        assert_eq!(erase_calls(), before + 1, "unwinding must not skip erasure");
    }

    /// A session refuses every keyed operation once erased, so the all-zero
    /// [`ERASURE_KEY`] can never protect a record. ADR-0001 §7.2's
    /// `REJECT_AFTER_TIME`: "keys are unusable **and** are zeroed" — both
    /// halves, in that order.
    #[test]
    fn an_erased_session_refuses_to_seal_or_open() {
        let mut t = established(0x11);
        t.erase();
        let mut out = [0u8; 128];
        let err = t.seal(b"never", &mut out).expect_err("seal after erasure");
        assert_eq!(err.reason_code().as_str(), "CRYPTO.REKEY_FAILED");
        let err = t
            .open(0, &[0u8; 32], &mut out)
            .expect_err("open after erasure");
        assert_eq!(err.reason_code().as_str(), "CRYPTO.REKEY_FAILED");
    }

    /// Erasing twice is not an error, does not undo anything, and does not
    /// re-run the overwrite.
    #[test]
    fn erasure_is_idempotent() {
        let mut t = established(0x11);
        t.erase();
        let after_first = erase_calls();
        let once = probe(&t);
        t.erase();
        assert_eq!(probe(&t), once);
        assert_eq!(erase_calls(), after_first);
        assert!(t.is_erased());
    }

    /// The erasure value is the all-zero key, which is what makes the proof
    /// above a proof: any two sessions converge on the *same* constant.
    #[test]
    fn the_erasure_key_is_the_all_zero_key() {
        assert_eq!(ERASURE_KEY, [0u8; 32]);
    }

    /// `Debug` never renders the state, erased or not.
    #[test]
    fn debug_shows_liveness_and_nothing_else() {
        let t = established(0x11);
        let rendered = format!("{:?}", t.transport_for_test());
        assert!(rendered.contains("erased: false"));
        assert!(!rendered.contains("cipher"));
        let _keep_alive: &ErasingTransport = t.transport_for_test();
    }
}
