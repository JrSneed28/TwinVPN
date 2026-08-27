//! CD-1 and CD-1a: three clocks that are not interchangeable at the type level.
//!
//! **Authority:** ADR-0018 §11.8 CD-1/CD-1a, ADR-0022 LC-8 / I-03b (which owns
//! the per-platform primitive table), `docs/architecture.md` §5.2 R-DET-1,
//! `contracts/docs/timestamps.md`.
//!
//! # Why three types rather than three names
//!
//! ADR-0018 gives three reasons, and this module is built to satisfy all three:
//!
//! 1. **The same spelling means opposite things across our targets.** Linux
//!    `CLOCK_MONOTONIC` *excludes* suspend; Darwin's *includes* it; Windows'
//!    `QueryUnbiasedInterruptTime` excludes it ("unbiased" means sleep is
//!    excluded). So the *mapping* is per-platform (LC-8's table) and lives in the
//!    binding, while the *meaning* is fixed here by the type.
//! 2. **Rust's obvious default is wrong half the time.** `std::time::Instant` is
//!    suspend-exclusive on Linux and Darwin — right for [`MonotonicClock`],
//!    silently wrong for anything needing the gap. CD-3's deny-list therefore
//!    bans `Instant::now` outright rather than steering it, and
//!    `cargo run -p xtask -- lint` permits it only under `src/binding/`.
//! 3. **Getting it backwards defeats recovery.** With one advancing clock,
//!    resuming from an eight-hour sleep fires every short-horizon timer's accrued
//!    backlog at once, and `T_DEAD` (15 s) declares every path dead *before* the
//!    wake ladder can re-validate one.
//!
//! The mechanism: [`MonotonicInstant`] and [`ElapsedInstant`] are distinct
//! newtypes with **no conversion between them** — no `From`, no `into()`, no
//! arithmetic that mixes them — and [`crate::Timer`] accepts only the monotonic
//! one. A call site cannot silently take the wrong clock because the wrong clock
//! does not type-check.
//!
//! # CD-1a: the wall clock is a three-state value
//!
//! Most `GC-0` hardware has no RTC and boots to epoch 0 on every power cycle. A
//! bare timestamp would read as 1970, which makes **every `nbf` check pass and
//! every `exp` check fail** — the worst possible failure direction for admission
//! control. So [`WallClockReading::Unset`] carries **no timestamp at all**: there
//! is no number to misuse, and [`ValidityClock`] — the only type that can
//! evaluate a validity window — cannot be constructed from it.

use core::time::Duration;

use twinvpn_types::codes;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{Component, Diagnostic};

/// A reading of the **suspend-exclusive** monotonic clock, in microseconds from
/// an unspecified host-local origin.
///
/// This is what every timer in `docs/reliability.md` §5 runs on: establishment,
/// liveness, recovery, migration, quality, dwell, backoff, and the LC-37
/// watchdog. It does **not** advance while the host is suspended.
///
/// The origin is process-local and meaningless off-device. `common.proto` states
/// the consequences: a value of this kind "MUST NOT be transmitted between
/// devices, compared across a process restart, or persisted and reloaded as if
/// still valid."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicInstant(u64);

/// A reading of the **suspend-inclusive** elapsed clock, in microseconds.
///
/// LC-8: measuring the suspend gap, the rekey-window comparison of
/// `docs/reliability.md` §11.3, NAT binding-lifetime attribution, and the
/// `T_REHYDRATE` span. Never a liveness or recovery timer.
///
/// LC-8's finding F2 adds a second class: **long-horizon policy deadlines**
/// (`T_TRUST_REFRESH`, `T_TRUST_STALE`, `T_TRUST_HARD`, `T_IK_OVERLAP`,
/// `T_TK_OVERLAP`, `PortalExemptionGrant` expiry, credential expiry) must read
/// this clock rather than [`MonotonicInstant`] — a laptop closed for sixty days
/// accrues no monotonic time, so `T_TRUST_HARD` would never expire and the device
/// would keep exercising authority R-24 exists to suspend. Better still, compare
/// against the **signed validity window** in the document itself, which survives a
/// reboot that this clock does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElapsedInstant(u64);

macro_rules! instant {
    ($name:ident, $doc:literal) => {
        impl $name {
            #[doc = concat!("The zero point of this ", $doc, " clock's origin.")]
            pub const ORIGIN: $name = $name(0);

            #[doc = concat!("Builds a ", $doc, " reading from microseconds since the origin.")]
            ///
            /// Only a clock binding calls this. It is `pub` because a binding
            /// lives outside this module, not because a component should.
            #[must_use]
            pub const fn from_micros(micros: u64) -> Self {
                Self(micros)
            }

            /// Microseconds since this clock's origin.
            #[must_use]
            pub const fn as_micros(self) -> u64 {
                self.0
            }

            /// The interval to a later reading **of the same clock**.
            ///
            /// Saturates at zero rather than wrapping: a non-monotone pair is a
            /// binding defect, and producing a huge duration from it would turn
            /// that defect into a timer that never fires.
            #[must_use]
            pub const fn duration_since(self, earlier: Self) -> Duration {
                Duration::from_micros(self.0.saturating_sub(earlier.0))
            }

            /// This reading advanced by `d`, saturating at `u64::MAX`.
            #[must_use]
            pub const fn saturating_add(self, d: Duration) -> Self {
                // `u64::try_from` is not const, so the clamp is written out. A
                // duration wider than u64 microseconds is 584 000 years; it can
                // only be a computed nonsense, and saturating is the safe end.
                let micros = d.as_micros();
                let micros = if micros > u64::MAX as u128 {
                    u64::MAX
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        micros as u64
                    }
                };
                Self(self.0.saturating_add(micros))
            }

            /// Whether this reading is at or after `deadline`.
            #[must_use]
            pub const fn reached(self, deadline: Self) -> bool {
                self.0 >= deadline.0
            }
        }
    };
}

instant!(MonotonicInstant, "monotonic");
instant!(ElapsedInstant, "elapsed");

/// The suspend-**exclusive** clock. Every timer takes this.
pub trait MonotonicClock: Send + Sync {
    /// The current reading.
    fn now(&self) -> MonotonicInstant;
}

/// The suspend-**inclusive** clock.
///
/// # No portable default exists, and that is deliberate
///
/// `std` offers no suspend-inclusive clock: `Instant` is `CLOCK_MONOTONIC` on
/// Linux and `mach_absolute_time()` on Darwin, both suspend-*exclusive*. The
/// primitive is `CLOCK_BOOTTIME` / `mach_continuous_time()` /
/// `QueryInterruptTimePrecise`, all of which need either a syscall (which
/// `#![forbid(unsafe_code)]` rules out here) or a per-OS branch (which CB-3 rules
/// out above the adapter). So **the platform binding supplies this**, exactly as
/// LC-8's table implies, and this crate ships no production implementation of it.
pub trait ElapsedClock: Send + Sync {
    /// The current reading.
    fn now(&self) -> ElapsedInstant;
}

/// The wall clock. **Evidence only — never a timer input.**
pub trait WallClock: Send + Sync {
    /// The current reading, as a three-state value (CD-1a).
    fn now(&self) -> WallClockReading;
}

/// UTC milliseconds since the Unix epoch.
///
/// `contracts/docs/timestamps.md`: advisory, UTC always, no timezone field.
/// Permitted uses are exactly three — rendering to a human, evaluating a signed
/// statement's own validity window against local time with an explicit skew
/// allowance, and TTL expiry of ephemeral hints. Prohibited: ordering, freshness
/// proofs, retry and backoff scheduling, any protocol timeout, and any
/// authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallMillis(u64);

impl WallMillis {
    /// Builds a wall-clock reading. Only a clock binding calls this.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// UTC milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Where a non-`Trusted` wall-clock offset came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OffsetSource {
    /// A relay supplied the offset (ADR-0005).
    Relay,
    /// The control plane supplied it (ADR-0009 K-2/K-6).
    ControlPlane,
    /// A peer's advisory `sender_time_ms`, used only where being wrong costs a
    /// wasted probe.
    Peer,
    /// Persisted from a previous run of this device.
    PersistedLastKnown,
}

/// CD-1a: the wall clock's three states.
///
/// `Unset` deliberately carries **no timestamp field**. That is the whole
/// mechanism: there is no number to accidentally read as 1970, so "the clock is
/// not yet resolved" is unrepresentable as a time value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockReading {
    /// No usable wall time. The device booted to epoch 0 and has not yet
    /// received an offset. **Not an error** — it is the normal state of an
    /// RTC-less `GC-0` device between power-on and its first offset.
    Unset,
    /// A wall time derived from an offset supplied by `source`.
    Offset {
        /// The derived time.
        millis: WallMillis,
        /// Who supplied the offset.
        source: OffsetSource,
    },
    /// A wall time the platform reports as synchronised.
    Trusted {
        /// The reported time.
        millis: WallMillis,
    },
}

impl WallClockReading {
    /// Whether the clock has resolved to anything usable.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        !matches!(self, WallClockReading::Unset)
    }
}

/// How much confidence a [`ValidityClock`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockConfidence {
    /// Derived from an offset.
    Offset(OffsetSource),
    /// Platform-synchronised.
    Trusted,
}

/// A wall clock **proven** usable for evaluating a validity window.
///
/// # The CD-1a mechanism
///
/// ADR-0018 requires that "the core MUST NOT evaluate any validity window —
/// `nbf`/`exp`, TTL, certificate `not_after`, pairing expiry — against a wall
/// clock in the `Unset` state", and asks for "a `Trusted`-only API that cannot be
/// called with an `Unset` clock" so that "the check is at compile time rather
/// than in review".
///
/// This is that type. [`ValidityClock::evaluate`] is the **only** validity-window
/// evaluator in the workspace, it is a method on this type, and this type has no
/// constructor other than [`ValidityClock::try_from_reading`] and
/// [`ValidityClock::require`] — both of which take a [`WallClockReading`] and both
/// of which fail on `Unset`. There is no `From<u64>`, no `Default`, and
/// `WallClockReading::Unset` holds no timestamp to smuggle in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityClock {
    millis: WallMillis,
    confidence: WallClockConfidence,
}

impl ValidityClock {
    /// The deferral path: `None` when the clock is `Unset`.
    ///
    /// This is the **correct** call for anything that can wait. An RTC-less
    /// device between power-on and its first offset is in a normal operating
    /// state, and ADR-0005's relay-supplied offset and ADR-0009 K-2/K-6 already
    /// resolve it — so the answer is "not yet", not "defect".
    #[must_use]
    pub const fn try_from_reading(reading: WallClockReading) -> Option<Self> {
        match reading {
            WallClockReading::Unset => None,
            WallClockReading::Offset { millis, source } => Some(Self {
                millis,
                confidence: WallClockConfidence::Offset(source),
            }),
            WallClockReading::Trusted { millis } => Some(Self {
                millis,
                confidence: WallClockConfidence::Trusted,
            }),
        }
    }

    /// The invariant path: a registered diagnostic when the clock is `Unset`.
    ///
    /// ADR-0018 CD-1a names the boundary case exactly: "`INTERNAL.INVARIANT_VIOLATED`
    /// if a validity window is evaluated against `Unset` — **that is a defect, not
    /// an operating state**." Use this only where the caller has already
    /// established, by some other means, that the clock must be resolved.
    ///
    /// # Errors
    ///
    /// `INTERNAL.INVARIANT_VIOLATED` when `reading` is `Unset`.
    pub fn require(reading: WallClockReading, component: Component) -> Result<Self, Diagnostic> {
        Self::try_from_reading(reading).ok_or_else(|| {
            Diagnostic::invariant_violated(
                component,
                "validity window evaluated against an Unset wall clock (CD-1a)",
            )
        })
    }

    /// The clock's confidence.
    #[must_use]
    pub const fn confidence(self) -> WallClockConfidence {
        self.confidence
    }

    /// The reading, for rendering or for an `occurred_at_ms` field.
    #[must_use]
    pub const fn millis(self) -> WallMillis {
        self.millis
    }

    /// Evaluates a signed statement's validity window against local time with an
    /// **explicit** skew allowance.
    ///
    /// The skew allowance is a parameter and has no default, because the right
    /// value differs per statement class and a hidden default is how a window
    /// becomes wider than anyone intended.
    #[must_use]
    pub fn evaluate(self, window: ValidityWindow, skew: Duration) -> WindowVerdict {
        let now = self.millis.as_millis();
        let skew_ms = u64::try_from(skew.as_millis()).unwrap_or(u64::MAX);
        if let Some(nbf) = window.not_before_ms {
            if now.saturating_add(skew_ms) < nbf {
                return WindowVerdict::NotYetValid { not_before_ms: nbf };
            }
        }
        if let Some(exp) = window.not_after_ms {
            if now.saturating_sub(skew_ms) >= exp {
                return WindowVerdict::Expired {
                    not_after_ms: exp,
                    skew_allowance_ms: skew_ms,
                };
            }
        }
        WindowVerdict::Valid
    }
}

/// A signed statement's bounded lifetime. `contracts/proto` `Auth.not_before_ms`
/// and `Auth.not_after_ms`; a bounded lifetime is mandatory (ADR-0003 B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValidityWindow {
    /// Not valid before this UTC millisecond, if bounded below.
    pub not_before_ms: Option<u64>,
    /// Not valid at or after this UTC millisecond, if bounded above.
    pub not_after_ms: Option<u64>,
}

/// The outcome of evaluating a [`ValidityWindow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVerdict {
    /// Inside the window.
    Valid,
    /// The window has not opened.
    NotYetValid {
        /// The window's lower bound.
        not_before_ms: u64,
    },
    /// The window has closed.
    Expired {
        /// The window's upper bound.
        not_after_ms: u64,
        /// The skew allowance that was applied.
        skew_allowance_ms: u64,
    },
}

impl WindowVerdict {
    /// Whether the statement is inside its window.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, WindowVerdict::Valid)
    }

    /// The registered diagnostic for a failed verdict.
    ///
    /// `AUTH.STATEMENT_EXPIRED` with its declared evidence
    /// `{statement_type, not_after_ms, skew_allowance_ms}`. `contracts/docs/timestamps.md`:
    /// "Failure surfaces as `AUTH.STATEMENT_EXPIRED`, never a silent drop."
    #[must_use]
    pub fn diagnostic(
        self,
        component: Component,
        statement_type: &'static str,
    ) -> Option<Diagnostic> {
        match self {
            WindowVerdict::Valid => None,
            WindowVerdict::NotYetValid { not_before_ms } => Some(
                Diagnostic::builder(codes::AUTH_STATEMENT_EXPIRED, component)
                    .evidence(
                        "statement_type",
                        EvidenceValue::Text(statement_type.to_owned()),
                    )
                    .evidence("not_after_ms", EvidenceValue::Uint(not_before_ms))
                    .build(),
            ),
            WindowVerdict::Expired {
                not_after_ms,
                skew_allowance_ms,
            } => Some(
                Diagnostic::builder(codes::AUTH_STATEMENT_EXPIRED, component)
                    .evidence(
                        "statement_type",
                        EvidenceValue::Text(statement_type.to_owned()),
                    )
                    .evidence("not_after_ms", EvidenceValue::Uint(not_after_ms))
                    .evidence("skew_allowance_ms", EvidenceValue::Uint(skew_allowance_ms))
                    .build(),
            ),
        }
    }
}

/// LC-8's third discriminator, which is **not a clock**.
///
/// After a reboot both monotonic clocks restart at zero, which is
/// indistinguishable from "no time passed". `boot_id` is what separates a reboot
/// from a resume: Linux `/proc/sys/kernel/random/boot_id`, `kern.boottime` on
/// Apple platforms, the Windows boot time, Android's `elapsedRealtime` base.
///
/// Supplied by the platform binding for the same reason as [`ElapsedClock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId([u8; 16]);

impl BootId {
    /// Builds a boot identity from sixteen opaque bytes.
    #[must_use]
    pub const fn from_array(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The opaque bytes. Compared only for equality.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The source of the boot identity.
pub trait BootIdSource: Send + Sync {
    /// This boot's identity. Stable for the life of the boot.
    fn boot_id(&self) -> BootId;
}
