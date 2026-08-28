//! §3.4's impairment matrix, and §3.5's reason for not using `netem loss`.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4, §3.4.1 (composition rule),
//! §3.5.
//!
//! # The one non-obvious mechanism
//!
//! `netem`'s loss, reorder and duplication draws come from the kernel PRNG and
//! are **not seedable from userspace**. A `BIT` scenario therefore must not use
//! them; it uses a precomputed drop schedule — a seeded bitmap over packet index
//! consumed by an eBPF `tc` classifier. [`LossSchedule`] is that bitmap, derived
//! from the scenario seed through CD-4's per-consumer stream, so two runs at one
//! seed drop the **identical** packet indices (§3.4.2's conformance row).
//!
//! [`Impairment::determinism`] answers, per condition, which class §3.4's table
//! assigns it — so a scenario cannot declare `BIT` while carrying `netem jitter`.

use twinvpn_env::consumers;

use crate::capability::Facility;
use crate::determinism::Class;
use crate::error::LabError;
use crate::seed::LabEnv;

/// One row of §3.4's matrix.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Impairment {
    /// `tc qdisc netem delay` on the transit veth.
    Latency {
        /// One-way delay in milliseconds.
        ms: u32,
    },
    /// `netem delay <base> <jitter> distribution normal`.
    Jitter {
        /// Base delay.
        base_ms: u32,
        /// Jitter amplitude.
        jitter_ms: u32,
    },
    /// A **seeded** deterministic drop schedule. Not `netem loss` (§3.5).
    SeededLoss {
        /// Percent, as a rate over the schedule length.
        pct: u32,
        /// Schedule length in packets.
        packets: u32,
    },
    /// `netem loss` — reproducible in distribution only.
    StatisticalLoss {
        /// Percent.
        pct: u32,
    },
    /// `netem duplicate`.
    Duplication {
        /// Percent.
        pct_tenths: u32,
    },
    /// `netem delay <d> reorder <p> <corr>`.
    Reordering {
        /// Reorder probability, percent.
        pct: u32,
        /// Correlation, percent.
        correlation_pct: u32,
    },
    /// `netem corrupt`. Corroborates AEAD rejection counters; §3.4 forbids it as
    /// the mechanism of a functional test.
    Corruption {
        /// Percent, in hundredths.
        pct_hundredths: u32,
    },
    /// `tbf` / `htb` on the transit veth.
    Bandwidth {
        /// Rate in megabits per second.
        mbit: u32,
    },
    /// `ip link set dev <transit veth> mtu N`.
    Mtu {
        /// The link MTU.
        bytes: u32,
    },
    /// Reduced MTU **plus** an `nft` drop of ICMPv4 type 3 code 4 and ICMPv6
    /// type 2 — both, because a v4-only black hole is not the condition.
    PmtuBlackHole {
        /// The reduced link MTU.
        bytes: u32,
    },
    /// `nft` drop of UDP egress, both families.
    BlockedUdp {
        /// Whether UDP/443 is exempted ("all but 443").
        allow_443: bool,
    },
    /// `nft` accept `tcp dport {80,443}` + `udp dport 443`, drop otherwise.
    EgressRestrictedTo443 {
        /// Whether a transparent proxy demanding `CONNECT` is in the path.
        transparent_proxy: bool,
    },
    /// Transit-namespace `dnat` of all HTTP/HTTPS to a portal host.
    CaptivePortal {
        /// Whether the token has been presented.
        authenticated: bool,
    },
    /// Move the device's `veth` leg between bridges, producing genuine
    /// `EV_LINK_DOWN` / `EV_ADDR_CHANGED`.
    InterfaceChange {
        /// Whether the new link is a different address family.
        cross_family: bool,
        /// Whether the old link stays up during the move.
        make_before_break: bool,
    },
    /// An `nft` blackhole between two named transit segments.
    Partition {
        /// `false` means only one direction is dropped, which is a distinct case.
        symmetric: bool,
    },
}

impl Impairment {
    /// The determinism class §3.4's table assigns this condition.
    #[must_use]
    pub const fn determinism(&self) -> Class {
        match self {
            Impairment::Latency { .. }
            | Impairment::Jitter { .. }
            | Impairment::StatisticalLoss { .. }
            | Impairment::Duplication { .. }
            | Impairment::Reordering { .. }
            | Impairment::Corruption { .. } => Class::Statistical,
            // "BIT for shaping, STATISTICAL for goodput" — the mechanism is
            // deterministic; only a throughput measurement over it is not.
            Impairment::Bandwidth { .. }
            | Impairment::SeededLoss { .. }
            | Impairment::Mtu { .. }
            | Impairment::PmtuBlackHole { .. }
            | Impairment::BlockedUdp { .. }
            | Impairment::EgressRestrictedTo443 { .. }
            | Impairment::CaptivePortal { .. }
            | Impairment::InterfaceChange { .. }
            | Impairment::Partition { .. } => Class::Bit,
        }
    }

    /// What the host must provide to apply this for real.
    #[must_use]
    pub fn required_facilities(&self) -> Vec<Facility> {
        match self {
            Impairment::Latency { .. }
            | Impairment::Jitter { .. }
            | Impairment::StatisticalLoss { .. }
            | Impairment::Duplication { .. }
            | Impairment::Reordering { .. }
            | Impairment::Corruption { .. } => vec![Facility::Netem],
            Impairment::Bandwidth { .. } => vec![Facility::Shaping],
            Impairment::Mtu { .. } => vec![Facility::NetworkNamespaces, Facility::Veth],
            // A PMTU black hole is a reduced MTU AND a dropped ICMP; without the
            // second half it is just a small MTU, which is a different test.
            Impairment::PmtuBlackHole { .. } => vec![Facility::Nftables, Facility::Ipv6],
            Impairment::BlockedUdp { .. }
            | Impairment::EgressRestrictedTo443 { .. }
            | Impairment::CaptivePortal { .. }
            | Impairment::Partition { .. } => vec![Facility::Nftables],
            Impairment::InterfaceChange { .. } => {
                vec![
                    Facility::NetworkNamespaces,
                    Facility::Veth,
                    Facility::Bridge,
                ]
            }
            // §3.5: a BIT loss scenario needs an eBPF tc classifier, because
            // netem's draws are not seedable from userspace.
            Impairment::SeededLoss { .. } => vec![Facility::EbpfTcClassifier],
        }
    }

    /// The real command this impairment runs on `dev`, as the run record carries
    /// it. `None` where the mechanism is an `nft` ruleset rather than a `tc` one.
    #[must_use]
    pub fn tc_argv(&self, dev: &str) -> Option<Vec<String>> {
        let a = |s: &str| s.to_owned();
        let base = vec![a("qdisc"), a("add"), a("dev"), a(dev), a("root")];
        let mut v = base;
        match self {
            Impairment::Latency { ms } => {
                v.extend([a("netem"), a("delay"), format!("{ms}ms")]);
            }
            Impairment::Jitter { base_ms, jitter_ms } => v.extend([
                a("netem"),
                a("delay"),
                format!("{base_ms}ms"),
                format!("{jitter_ms}ms"),
                a("distribution"),
                a("normal"),
            ]),
            Impairment::StatisticalLoss { pct } => {
                v.extend([a("netem"), a("loss"), format!("{pct}%")]);
            }
            Impairment::Duplication { pct_tenths } => v.extend([
                a("netem"),
                a("duplicate"),
                format!("{}.{}%", pct_tenths / 10, pct_tenths % 10),
            ]),
            Impairment::Reordering {
                pct,
                correlation_pct,
            } => v.extend([
                a("netem"),
                a("delay"),
                a("10ms"),
                a("reorder"),
                format!("{pct}%"),
                format!("{correlation_pct}%"),
            ]),
            Impairment::Corruption { pct_hundredths } => v.extend([
                a("netem"),
                a("corrupt"),
                format!("{}.{:02}%", pct_hundredths / 100, pct_hundredths % 100),
            ]),
            Impairment::Bandwidth { mbit } => v.extend([
                a("tbf"),
                a("rate"),
                format!("{mbit}mbit"),
                a("burst"),
                a("32kbit"),
                a("latency"),
                a("50ms"),
            ]),
            _ => return None,
        }
        Some(v)
    }
}

/// §3.4.1's composition rule: an impairment set is a *set*, applied atomically
/// before the scenario's first packet.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ImpairmentSet {
    /// The conditions, in declaration order.
    pub conditions: Vec<Impairment>,
}

impl ImpairmentSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a condition.
    #[must_use]
    pub fn with(mut self, condition: Impairment) -> Self {
        self.conditions.push(condition);
        self
    }

    /// The strongest determinism class this set can support.
    ///
    /// `BIT` only when **every** condition is `BIT`. One `netem jitter` makes
    /// the whole scenario `STATISTICAL`, which is §3.5 rule L-2 applied to the
    /// composition rather than left to a reviewer.
    #[must_use]
    pub fn achievable_class(&self) -> Class {
        if self
            .conditions
            .iter()
            .all(|c| matches!(c.determinism(), Class::Bit))
        {
            Class::Bit
        } else {
            Class::Statistical
        }
    }

    /// Refuses a set whose conditions cannot support the declared class.
    ///
    /// # Errors
    ///
    /// [`LabError::DeterminismClass`] naming the first condition that is weaker
    /// than the declaration.
    pub fn check_class(&self, declared: Class) -> Result<(), LabError> {
        if matches!(declared, Class::Bit) {
            if let Some(c) = self
                .conditions
                .iter()
                .find(|c| !matches!(c.determinism(), Class::Bit))
            {
                return Err(LabError::DeterminismClass {
                    class: "BIT",
                    assertion: format!(
                        "impairment {c:?} draws from the kernel PRNG and is STATISTICAL (§3.5)"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Every facility this set needs, deduplicated.
    #[must_use]
    pub fn required_facilities(&self) -> Vec<Facility> {
        let mut out: Vec<Facility> = Vec::new();
        for c in &self.conditions {
            for f in c.required_facilities() {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        out
    }
}

/// §3.5's seeded drop schedule: a bitmap over packet index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossSchedule {
    bits: Vec<bool>,
}

impl LossSchedule {
    /// Derives a schedule of `packets` entries dropping approximately `pct` of
    /// them, from the scenario seed's `lab/loss-schedule` stream.
    ///
    /// The count is **exact**, not sampled: a Fisher–Yates selection of
    /// `packets * pct / 100` indices. §3.4.2's conformance row wants "two runs
    /// at one seed drop the identical packet indices", and an exact count also
    /// makes the measured rate assertion a `BIT` one rather than a binomial.
    ///
    /// # Errors
    ///
    /// Propagates a derivation failure from the environment.
    ///
    /// # Panics
    ///
    /// Never in practice: the only `expect` is on `NonZeroU64::new(i + 1)` where
    /// `i >= 1`, which is an invariant of the loop bound.
    // `uniform_below(i + 1)` is bounded by `packets`, a `u32`, so the `usize`
    // cast cannot truncate on any target this laboratory runs on.
    #[allow(clippy::cast_possible_truncation)]
    pub fn derive(env: &LabEnv, packets: u32, pct: u32) -> Result<Self, LabError> {
        let n = packets as usize;
        let drops = (n * (pct.min(100) as usize)) / 100;
        let mut rng = env.rng_for(consumers::LOSS_SCHEDULE)?;
        let mut order: Vec<usize> = (0..n).collect();
        // Fisher-Yates over the whole index space, then take the first `drops`.
        for i in (1..n).rev() {
            let bound = core::num::NonZeroU64::new((i + 1) as u64).expect("i + 1 > 0");
            let j = rng.uniform_below(bound) as usize;
            order.swap(i, j);
        }
        let mut bits = vec![false; n];
        for &idx in order.iter().take(drops) {
            bits[idx] = true;
        }
        Ok(Self { bits })
    }

    /// Whether packet `index` is dropped. Indices past the schedule wrap, so a
    /// long run keeps the same period rather than silently becoming lossless.
    #[must_use]
    pub fn drops(&self, index: usize) -> bool {
        if self.bits.is_empty() {
            return false;
        }
        self.bits[index % self.bits.len()]
    }

    /// The number of dropped indices.
    #[must_use]
    pub fn drop_count(&self) -> usize {
        self.bits.iter().filter(|b| **b).count()
    }

    /// The schedule length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether the schedule is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// The dropped indices, for the eBPF map and for the run record.
    #[must_use]
    pub fn dropped_indices(&self) -> Vec<usize> {
        self.bits
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.then_some(i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ScenarioSeed;

    fn env(seed: u8) -> LabEnv {
        LabEnv::new(ScenarioSeed::from_bytes([seed; 16]))
    }

    #[test]
    fn two_runs_at_one_seed_drop_the_identical_packet_indices() {
        // §3.4.2's conformance row for the loss shim, verbatim.
        let a = LossSchedule::derive(&env(0x9f), 10_000, 1).unwrap();
        let b = LossSchedule::derive(&env(0x9f), 10_000, 1).unwrap();
        assert_eq!(a.dropped_indices(), b.dropped_indices());
        assert!(!a.dropped_indices().is_empty());
    }

    #[test]
    fn a_different_seed_drops_different_indices() {
        // The negative control: without it, a schedule that ignored the seed
        // would satisfy the reproducibility assertion perfectly.
        let a = LossSchedule::derive(&env(1), 10_000, 5).unwrap();
        let b = LossSchedule::derive(&env(2), 10_000, 5).unwrap();
        assert_ne!(a.dropped_indices(), b.dropped_indices());
        assert_eq!(
            a.drop_count(),
            b.drop_count(),
            "the rate is exact either way"
        );
    }

    #[test]
    fn the_measured_rate_is_exact_rather_than_sampled() {
        for pct in [1u32, 2, 5, 20] {
            let s = LossSchedule::derive(&env(3), 100_000, pct).unwrap();
            assert_eq!(s.drop_count(), (100_000 * pct as usize) / 100);
        }
    }

    #[test]
    fn a_zero_percent_schedule_drops_nothing_and_a_hundred_drops_everything() {
        assert_eq!(
            LossSchedule::derive(&env(4), 1000, 0).unwrap().drop_count(),
            0
        );
        assert_eq!(
            LossSchedule::derive(&env(4), 1000, 100)
                .unwrap()
                .drop_count(),
            1000
        );
    }

    #[test]
    fn a_bit_set_refuses_a_netem_drawn_condition() {
        // §3.5's reason for rejecting `netem loss` in a BIT scenario, mechanised.
        let set = ImpairmentSet::new()
            .with(Impairment::Mtu { bytes: 1280 })
            .with(Impairment::StatisticalLoss { pct: 1 });
        assert_eq!(set.achievable_class(), Class::Statistical);
        let err = set.check_class(Class::Bit).expect_err("must refuse");
        assert!(err.to_string().contains("STATISTICAL"), "{err}");
    }

    #[test]
    fn positive_control_an_all_bit_set_is_accepted_as_bit() {
        let set = ImpairmentSet::new()
            .with(Impairment::Mtu { bytes: 1280 })
            .with(Impairment::SeededLoss {
                pct: 1,
                packets: 1000,
            })
            .with(Impairment::BlockedUdp { allow_443: true });
        assert_eq!(set.achievable_class(), Class::Bit);
        set.check_class(Class::Bit).expect("all-BIT set");
    }

    #[test]
    fn a_seeded_loss_scenario_needs_the_ebpf_classifier_and_not_netem() {
        let seeded = Impairment::SeededLoss {
            pct: 1,
            packets: 100,
        };
        assert_eq!(seeded.required_facilities(), [Facility::EbpfTcClassifier]);
        assert_eq!(
            Impairment::StatisticalLoss { pct: 1 }.required_facilities(),
            [Facility::Netem]
        );
    }

    #[test]
    fn a_pmtu_black_hole_requires_the_v6_half_too() {
        // A v4-only black hole is a different condition; ADR-0010 R1 is one
        // story covering both families and the impairment must be too.
        assert!(Impairment::PmtuBlackHole { bytes: 1400 }
            .required_facilities()
            .contains(&Facility::Ipv6));
    }

    #[test]
    fn tc_argv_is_a_real_command_for_the_netem_rows_and_absent_for_the_nft_ones() {
        assert_eq!(
            Impairment::Latency { ms: 40 }.tc_argv("veth-t"),
            Some(
                ["qdisc", "add", "dev", "veth-t", "root", "netem", "delay", "40ms"]
                    .map(ToOwned::to_owned)
                    .to_vec()
            )
        );
        assert!(Impairment::BlockedUdp { allow_443: false }
            .tc_argv("veth-t")
            .is_none());
        // The seeded schedule is deliberately NOT a tc netem command.
        assert!(Impairment::SeededLoss {
            pct: 1,
            packets: 10
        }
        .tc_argv("veth-t")
        .is_none());
    }
}
