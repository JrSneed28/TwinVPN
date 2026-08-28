//! A deterministic fuzz engine for the core's externally supplied decoders.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! # Why this is hand-rolled rather than `cargo fuzz`
//!
//! `cargo fuzz` needs libFuzzer, which needs a nightly toolchain.
//! `rust-toolchain.toml` pins **one exact stable version** and ADR-0018 §11.3
//! makes advancing it a reviewed commit that re-runs the whole §11.9 matrix. A
//! fuzz harness that cannot run in the gate is a fuzz harness nobody runs, so
//! this one runs under `cargo test` on the pinned toolchain instead.
//!
//! The trade is stated rather than hidden: there is **no coverage feedback**
//! here, so this does not find what a coverage-guided fuzzer finds. What it does
//! give — and what libFuzzer does not — is that every input is a pure function
//! of a `u64` seed, so a failure reproduces exactly, in the gate, a year later.
//! The corpus compensates for the missing feedback by seeding from *valid*
//! encodings and mutating them, which is where a structure-aware fuzzer spends
//! its time anyway.
//!
//! # The three properties every decoder must hold
//!
//! 1. **Totality.** No input panics. Not a slice index, not an `unwrap`, not an
//!    arithmetic overflow in a debug build, not a recursion that overflows the
//!    stack. A decoder reads bytes an attacker chose.
//! 2. **Determinism.** The same bytes decode to the same outcome twice. A
//!    decoder that reads uninitialised padding, a clock, or a hash seed would
//!    fail this — and would make every other test in this repository flaky
//!    rather than failing.
//! 3. **No partial accept.** A rejection yields no value. This one is a property
//!    of the *signature* — every decoder here returns `Result` or `Option` — so
//!    the engine asserts it structurally by fingerprinting the outcome rather
//!    than by inspecting a half-built value that cannot exist.

use std::panic::{self, RefUnwindSafe};
use std::sync::Once;

// Where a caught panic's message is stashed, so the report can name it.
//
// A `panic::set_hook` is process-global and tests run in parallel threads, so
// the hook writes here — thread-local — and the catching thread reads its own.
thread_local! {
    static LAST_PANIC: std::cell::RefCell<Option<String>> = const {
        std::cell::RefCell::new(None)
    };
    // Whether this thread is currently inside a fuzz probe. A panic from
    // anywhere else — an ordinary failing assertion in an ordinary test — must
    // still reach the default hook with its backtrace intact.
    static IN_PROBE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

static QUIET_HOOK: Once = Once::new();

/// Installs the recording hook exactly once per process.
///
/// The default hook prints a backtrace for every caught panic, which for a
/// hundred thousand fuzz inputs is a hundred thousand backtraces. This one
/// records instead of printing; the engine prints the *one* that matters.
fn install_hook() {
    QUIET_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !IN_PROBE.with(std::cell::Cell::get) {
                previous(info);
                return;
            }
            let rendered = format!(
                "{} at {}",
                info.payload()
                    .downcast_ref::<&str>()
                    .map(ToString::to_string)
                    .or_else(|| info.payload().downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_owned()),
                info.location()
                    .map_or_else(|| "<unknown>".to_owned(), ToString::to_string),
            );
            LAST_PANIC.with(|slot| *slot.borrow_mut() = Some(rendered));
        }));
    });
}

/// `splitmix64`. Chosen because it is four lines, has no state to get wrong, and
/// produces the identical stream on every platform this repository targets — the
/// same reason CD-4's seeded streams exist.
#[derive(Debug, Clone)]
pub struct Fuzzer {
    state: u64,
}

impl Fuzzer {
    /// A generator seeded by `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A byte.
    pub fn byte(&mut self) -> u8 {
        #[allow(clippy::cast_possible_truncation)]
        {
            (self.next_u64() >> 24) as u8
        }
    }

    /// A value in `0..n`. Returns 0 for `n == 0` rather than dividing by it.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            (self.next_u64() % (n as u64)) as usize
        }
    }

    /// A coin that lands true one time in `n`.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    /// Uniform random bytes, length in `0..=max_len`.
    pub fn random_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.byte()).collect()
    }

    /// Mostly-zero bytes with a scattering of random ones.
    ///
    /// Uniform bytes almost never produce a valid length prefix, a valid tag, or
    /// a run of padding. This shape does, and those are the paths where an
    /// off-by-one lives.
    pub fn sparse_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        let mut out = vec![0u8; len];
        let pokes = self.below(len / 8 + 2);
        for _ in 0..pokes {
            if len > 0 {
                let at = self.below(len);
                out[at] = self.byte();
            }
        }
        out
    }

    /// Bytes drawn from an alphabet — protobuf tags, CBOR heads, length
    /// prefixes, boundary values.
    ///
    /// This is the closest this engine gets to structure awareness without a
    /// grammar: a decoder that dispatches on a leading tag byte reaches its
    /// interesting branches roughly as often as it has branches, instead of
    /// roughly never.
    pub fn alphabet_bytes(&mut self, alphabet: &[u8], max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }

    /// One mutation of `seed`, drawn from the eight shapes below.
    ///
    /// Seeding from a **valid** encoding and mutating it is what reaches the
    /// code past the first length check. A uniformly random 200-byte string is
    /// rejected by byte three of every decoder here; a valid statement with one
    /// bit flipped is not.
    #[allow(clippy::too_many_lines)]
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut out = seed.to_vec();
        match self.below(8) {
            // Flip one bit.
            0 => {
                if !out.is_empty() {
                    let at = self.below(out.len());
                    out[at] ^= 1u8 << self.below(8);
                }
            }
            // Overwrite one byte with an arbitrary value.
            1 => {
                if !out.is_empty() {
                    let at = self.below(out.len());
                    out[at] = self.byte();
                }
            }
            // Truncate at an arbitrary prefix. Every decoder must survive every
            // prefix of a valid message: that is what a short read looks like.
            2 => {
                let keep = self.below(out.len() + 1);
                out.truncate(keep);
            }
            // Append trailing bytes. A decoder that ignores a remainder accepts
            // two encodings of one message; a canonical one must not.
            3 => {
                let extra = self.below(17);
                for _ in 0..extra {
                    out.push(self.byte());
                }
            }
            // Splice out a run.
            4 => {
                if out.len() > 1 {
                    let at = self.below(out.len());
                    let len = self.below(out.len() - at).min(16);
                    out.drain(at..at + len);
                }
            }
            // Duplicate a run in place — the shape a replayed or re-framed
            // fragment has.
            5 => {
                if !out.is_empty() {
                    let at = self.below(out.len());
                    let len = self.below(out.len() - at).min(32);
                    let run: Vec<u8> = out[at..at + len].to_vec();
                    out.splice(at..at, run);
                }
            }
            // Swap two chunks — reordering, at the byte level.
            6 => {
                if out.len() > 3 {
                    let a = self.below(out.len());
                    let b = self.below(out.len());
                    out.swap(a, b);
                }
            }
            // Set a run to a boundary value: 0x00, 0xFF, 0x80, 0x7F.
            _ => {
                if !out.is_empty() {
                    let fill = [0x00u8, 0xFF, 0x80, 0x7F][self.below(4)];
                    let at = self.below(out.len());
                    let end = (at + self.below(out.len() - at).min(24) + 1).min(out.len());
                    for b in &mut out[at..end] {
                        *b = fill;
                    }
                }
            }
        }
        out
    }
}

/// What one fuzz run measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Inputs presented to the decoder.
    pub inputs: u32,
    /// Inputs the decoder accepted.
    pub accepted: u32,
    /// Inputs the decoder rejected.
    pub rejected: u32,
}

impl Report {
    /// Whether the run reached the decoder's accepting path at all.
    ///
    /// A fuzz run that never accepted anything tested the first length check
    /// and nothing else, which is the failure mode a fuzz suite is most likely
    /// to have and least likely to notice.
    #[must_use]
    pub const fn reached_accept(&self) -> bool {
        self.accepted > 0
    }

    /// Whether the run reached the decoder's rejecting path at all.
    #[must_use]
    pub const fn reached_reject(&self) -> bool {
        self.rejected > 0
    }
}

/// The outcome of one decode, as the engine sees it.
///
/// The fingerprint is what makes determinism checkable without every decoder's
/// output type having to implement `PartialEq`: a caller renders the outcome to
/// a string, and two runs of one input must render identically.
pub struct Outcome {
    /// Whether the decoder accepted the input.
    pub accepted: bool,
    /// A total, stable rendering of the result.
    pub fingerprint: String,
}

impl Outcome {
    /// An accepted decode.
    #[must_use]
    pub fn accept(fingerprint: impl Into<String>) -> Self {
        Self {
            accepted: true,
            fingerprint: fingerprint.into(),
        }
    }

    /// A rejected decode.
    #[must_use]
    pub fn reject(fingerprint: impl Into<String>) -> Self {
        Self {
            accepted: false,
            fingerprint: fingerprint.into(),
        }
    }
}

/// Renders a `Result` whose halves both `Debug` into an [`Outcome`].
///
/// Most decoders in the core return exactly this shape, so most targets are one
/// line.
pub fn outcome_of<T: core::fmt::Debug, E: core::fmt::Debug>(r: &Result<T, E>) -> Outcome {
    match r {
        Ok(v) => Outcome::accept(format!("{v:?}")),
        Err(e) => Outcome::reject(format!("{e:?}")),
    }
}

/// Hex, for a failure message that can be pasted back into a regression test.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Runs `decode` over `corpus` and asserts totality, determinism, and that a
/// rejection produced no value.
///
/// # Panics
///
/// Naming the decoder, the seed, and the exact input, if any input panics or
/// decodes differently on a second call.
pub fn fuzz<F>(name: &'static str, corpus: &[Vec<u8>], decode: F) -> Report
where
    F: Fn(&[u8]) -> Outcome + RefUnwindSafe,
{
    install_hook();
    let mut report = Report {
        inputs: 0,
        accepted: 0,
        rejected: 0,
    };
    for input in corpus {
        report.inputs += 1;
        let first = probe(name, input, &decode);
        // (2) Determinism. The second call must agree with the first, byte for
        // byte, or every other test in this repository is running on sand.
        let second = probe(name, input, &decode);
        assert_eq!(
            first.fingerprint,
            second.fingerprint,
            "{name} is not deterministic on input {} ({} B)",
            hex(input),
            input.len(),
        );
        if first.accepted {
            report.accepted += 1;
        } else {
            report.rejected += 1;
        }
    }
    report
}

/// One call, with a panic turned into a failure that names the input.
fn probe<F>(name: &'static str, input: &[u8], decode: &F) -> Outcome
where
    F: Fn(&[u8]) -> Outcome + RefUnwindSafe,
{
    LAST_PANIC.with(|slot| *slot.borrow_mut() = None);
    IN_PROBE.with(|f| f.set(true));
    let caught = panic::catch_unwind(|| decode(input));
    IN_PROBE.with(|f| f.set(false));
    match caught {
        Ok(outcome) => outcome,
        Err(_) => {
            let detail = LAST_PANIC
                .with(|slot| slot.borrow().clone())
                .unwrap_or_else(|| "<no message>".to_owned());
            panic!(
                "decoder `{name}` PANICKED on a {} B input.\n  \
                 panic: {detail}\n  \
                 input: {}\n\
                 A decoder reads bytes an attacker chose; a panic in one is a \
                 remote denial of service, not a test failure.",
                input.len(),
                hex(input),
            );
        }
    }
}

/// The standard corpus: random, sparse, alphabet-drawn, and mutations of every
/// valid seed supplied.
///
/// `iterations` is *per shape*, so the returned corpus is roughly
/// `3 * iterations + seeds.len() * iterations` inputs.
#[must_use]
pub fn corpus(seed: u64, iterations: usize, max_len: usize, valid: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // Protobuf field tags for fields 1..8 at every wire type, the CBOR major-type
    // heads, and the boundary bytes a length prefix is most often wrong about.
    const ALPHABET: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x20, 0x22,
        0x28, 0x2a, 0x30, 0x32, 0x38, 0x3a, 0x40, 0x42, 0x58, 0x59, 0x5f, 0x60, 0x78, 0x7f, 0x80,
        0x81, 0x82, 0x83, 0x9f, 0xa0, 0xa1, 0xa2, 0xbf, 0xd8, 0xf6, 0xf7, 0xff,
    ];
    let mut f = Fuzzer::new(seed);
    let mut out = Vec::with_capacity(iterations * (3 + valid.len()));
    for _ in 0..iterations {
        out.push(f.random_bytes(max_len));
        out.push(f.sparse_bytes(max_len));
        out.push(f.alphabet_bytes(ALPHABET, max_len));
        for v in valid {
            out.push(f.mutate(v));
        }
    }
    // Every valid seed unmutated, and the empty input, which is the one every
    // decoder is asked for first and the one a length check is most often wrong
    // about.
    out.push(Vec::new());
    out.extend(valid.iter().cloned());
    out
}

// ---------------------------------------------------------------------------
// The engine's own tests.
//
// `core/README.md` §6 states the principle for the T1 lints: "a lint nobody has
// seen fail is not a lint". The same is true of a fuzz harness. Each test below
// plants a decoder with a known defect and asserts the engine reports it — so a
// refactor that quietly turned `fuzz` into a no-op fails here rather than
// passing everything for the rest of the project's life.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::{corpus, fuzz, hex, Fuzzer, Outcome};

    /// Runs `f`, returning its panic message if it panicked.
    ///
    /// The engine has already restored the default hook by the time it panics,
    /// so this catches an ordinary panic in the ordinary way.
    fn message_from_panic(f: impl FnOnce() + std::panic::UnwindSafe) -> Option<String> {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(f);
        std::panic::set_hook(previous);
        caught.err().map(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(ToString::to_string))
                .unwrap_or_default()
        })
    }

    #[test]
    fn the_engine_reports_a_decoder_that_panics_and_names_the_input() {
        let inputs = vec![vec![0u8], vec![1u8, 2, 3]];
        let message = message_from_panic(|| {
            let _ = fuzz("planted::panics_on_a_leading_one", &inputs, |b| {
                assert_ne!(b.first(), Some(&1), "planted defect");
                Outcome::accept("")
            });
        })
        .expect("the engine must not pass a panicking decoder");
        assert!(message.contains("PANICKED"), "{message}");
        assert!(
            message.contains("planted::panics_on_a_leading_one"),
            "{message}"
        );
        // The input has to be in the message or the failure is unreproducible.
        assert!(message.contains("010203"), "{message}");
    }

    #[test]
    fn the_engine_reports_a_decoder_that_is_not_deterministic() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CALLS: AtomicU32 = AtomicU32::new(0);
        let inputs = vec![vec![9u8, 9, 9]];
        let message = message_from_panic(|| {
            let _ = fuzz("planted::counts_its_own_calls", &inputs, |_| {
                Outcome::accept(CALLS.fetch_add(1, Ordering::SeqCst).to_string())
            });
        })
        .expect("the engine must not pass a non-deterministic decoder");
        assert!(message.contains("not deterministic"), "{message}");
        assert!(message.contains("090909"), "{message}");
    }

    #[test]
    fn a_total_decoder_passes_and_the_report_counts_both_paths() {
        let inputs = vec![vec![], vec![0u8], vec![1u8], vec![1u8, 2]];
        let report = fuzz("planted::accepts_even_lengths", &inputs, |b| {
            if b.len() % 2 == 0 {
                Outcome::accept(format!("len={}", b.len()))
            } else {
                Outcome::reject("odd")
            }
        });
        assert_eq!(report.inputs, 4);
        assert_eq!(report.accepted, 2);
        assert_eq!(report.rejected, 2);
        assert!(report.reached_accept() && report.reached_reject());
    }

    #[test]
    fn the_corpus_is_a_pure_function_of_its_seed() {
        // The whole reproducibility claim rests on this. Two rigs at one seed
        // produce the identical corpus — the same property CD-4 gives the
        // product's own random draws.
        let seeds = vec![b"a valid encoding".to_vec()];
        let a = corpus(0xfeed_face, 20, 64, &seeds);
        let b = corpus(0xfeed_face, 20, 64, &seeds);
        assert_eq!(a, b);
        let different = corpus(0xfeed_fade, 20, 64, &seeds);
        assert_ne!(
            a, different,
            "a different seed must produce a different corpus"
        );
    }

    #[test]
    fn every_mutation_shape_is_reachable_and_none_of_them_panics() {
        // A mutator that silently stopped mutating would make every target above
        // pass while testing one input. Measured, not assumed.
        let seed = b"0123456789abcdef".to_vec();
        let mut f = Fuzzer::new(1);
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..2_000 {
            distinct.insert(f.mutate(&seed));
        }
        assert!(
            distinct.len() > 100,
            "the mutator produced only {} distinct outputs",
            distinct.len()
        );
        // Shorter, longer and same-length outputs must all appear, or a whole
        // family of shapes is unreachable.
        assert!(distinct.iter().any(|m| m.len() < seed.len()));
        assert!(distinct.iter().any(|m| m.len() > seed.len()));
        assert!(distinct.iter().any(|m| m.len() == seed.len() && *m != seed));
    }

    #[test]
    fn the_mutator_survives_an_empty_seed() {
        // Every `below(len)` in the mutator divides by a length the seed chose.
        let mut f = Fuzzer::new(7);
        for _ in 0..200 {
            let _ = f.mutate(&[]);
        }
    }

    #[test]
    fn hex_round_trips_a_reported_input() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }
}
