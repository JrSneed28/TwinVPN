//! The mapping table — the part of a NAT that a traversal strategy is actually
//! fighting.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3, `docs/networking.md` §3.1,
//! §3.6.
//!
//! # The two decisions this table makes
//!
//! 1. **What external port an outbound packet gets**, which is [`Mapping`].
//! 2. **Whether an inbound packet is allowed to use one**, which is
//!    [`Filtering`].
//!
//! They are separate fields, separate methods and separate tests, because §3.3
//! says they are independent axes and the legacy "cone/symmetric" vocabulary is
//! precisely the conflation that hides a defect.
//!
//! # Why the allocator is seeded rather than random
//!
//! §3.6 distinguishes `-RAND` from `-SEQ` because ADR-0004's prediction
//! strategies attack them differently. A `-RAND` middlebox whose allocation
//! came from the OS entropy pool would make a failed prediction unreproducible,
//! and "the birthday attack missed" and "the birthday attack is broken" would
//! be the same observation. The allocator here is a seeded SplitMix64: uniform
//! enough to be the birthday target, and reproducible from the scenario seed.

use std::collections::HashMap;
use std::net::IpAddr;

use super::config::{Filtering, Mapping};

/// A remote endpoint, as filtering records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Remote {
    /// The peer address.
    pub addr: IpAddr,
    /// The peer port.
    pub port: u16,
}

/// One translation.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The internal address.
    pub int_addr: IpAddr,
    /// The internal port.
    pub int_port: u16,
    /// The external port this middlebox allocated.
    pub ext_port: u16,
    /// The protocol.
    pub proto: u8,
    /// Every remote this mapping has been written to, which is what
    /// [`Filtering`] consults. A `Vec` rather than a set because the order in
    /// which peers were contacted is evidence in a hairpinning or a
    /// simultaneous-open scenario, and a set would discard it.
    pub seen: Vec<Remote>,
    /// Monotonic milliseconds at which the mapping was last used, in either
    /// direction. RFC 4787 REQ-6: inbound traffic refreshes a mapping.
    pub last_used_ms: u64,
}

impl Entry {
    fn permits(&self, filtering: Filtering, from: Remote) -> bool {
        match filtering {
            Filtering::None | Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => self.seen.iter().any(|r| r.addr == from.addr),
            Filtering::AddressPortDependent => self.seen.contains(&from),
        }
    }

    fn note(&mut self, to: Remote, now_ms: u64) {
        if !self.seen.contains(&to) {
            self.seen.push(to);
        }
        self.last_used_ms = now_ms;
    }
}

/// What an outbound lookup keys on. Endpoint-independent mapping ignores the
/// remote; address-and-port-dependent mapping does not, and that one difference
/// is the whole of "symmetric".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    proto: u8,
    int_addr: IpAddr,
    int_port: u16,
    remote: Option<Remote>,
}

/// Why an outbound packet got no mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocFailure {
    /// Every port in the budget is in use.
    ///
    /// §3.3 requires this state to be *reachable* on the CGNAT tier, so it is a
    /// named outcome rather than a panic or a silent drop.
    Exhausted,
}

/// The mapping table of one middlebox.
#[derive(Debug)]
pub struct Table {
    mapping: Mapping,
    filtering: Filtering,
    port_low: u16,
    port_high: u16,
    lifetime_ms: u64,
    by_key: HashMap<Key, u16>,
    by_ext: HashMap<(u8, u16), Entry>,
    rng: u64,
    next_sequential: u32,
    /// Counted rather than logged: a conformance run asserts that exhaustion
    /// was reached, and a log line is not an assertion.
    pub exhaustions: u64,
    /// Inbound packets refused by the filter. The number a
    /// `RELAY_EXPECTED` scenario expects to be non-zero.
    pub filtered_in: u64,
}

impl Table {
    /// A table for one personality.
    #[must_use]
    pub fn new(
        mapping: Mapping,
        filtering: Filtering,
        port_low: u16,
        port_high: u16,
        lifetime_ms: u64,
        seed: u64,
    ) -> Self {
        Table {
            mapping,
            filtering,
            port_low,
            port_high,
            lifetime_ms,
            by_key: HashMap::new(),
            by_ext: HashMap::new(),
            // SplitMix64 tolerates a zero seed; the increment is what moves it.
            rng: seed,
            next_sequential: 0,
            exhaustions: 0,
            filtered_in: 0,
        }
    }

    /// Drops every mapping idle for longer than the configured lifetime.
    ///
    /// Called on every packet rather than on a timer: a timer would be a second
    /// clock in a laboratory that already has one, and the cost at these packet
    /// rates is a walk over a table with tens of entries.
    pub fn expire(&mut self, now_ms: u64) {
        let lifetime = self.lifetime_ms;
        let dead: Vec<(u8, u16)> = self
            .by_ext
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.last_used_ms) > lifetime)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            if let Some(entry) = self.by_ext.remove(&k) {
                self.by_key.retain(|key, port| {
                    !(key.proto == entry.proto
                        && key.int_addr == entry.int_addr
                        && key.int_port == entry.int_port
                        && *port == entry.ext_port)
                });
            }
        }
    }

    /// The external port an outbound packet should carry, allocating one if this
    /// is a new flow.
    ///
    /// # Errors
    ///
    /// [`AllocFailure::Exhausted`] when the port budget is full. The caller
    /// drops the packet, which is what a real CGN does.
    pub fn outbound(
        &mut self,
        proto: u8,
        int_addr: IpAddr,
        int_port: u16,
        to: Remote,
        now_ms: u64,
    ) -> Result<u16, AllocFailure> {
        let key = Key {
            proto,
            int_addr,
            int_port,
            remote: match self.mapping {
                Mapping::EndpointIndependent | Mapping::None => None,
                Mapping::AddressPortDependentRandom | Mapping::AddressPortDependentSequential => {
                    Some(to)
                }
            },
        };
        if let Some(&ext) = self.by_key.get(&key) {
            if let Some(entry) = self.by_ext.get_mut(&(proto, ext)) {
                entry.note(to, now_ms);
                return Ok(ext);
            }
            self.by_key.remove(&key);
        }
        let ext = self.allocate(proto)?;
        self.by_key.insert(key, ext);
        self.by_ext.insert(
            (proto, ext),
            Entry {
                int_addr,
                int_port,
                ext_port: ext,
                proto,
                seen: vec![to],
                last_used_ms: now_ms,
            },
        );
        Ok(ext)
    }

    /// Where an inbound packet should go, or `None` if there is no mapping or
    /// the filter refuses it.
    ///
    /// The two cases are deliberately merged in the return type and separated in
    /// the counters: a caller drops both, and a conformance run needs to know
    /// which happened.
    pub fn inbound(
        &mut self,
        proto: u8,
        ext_port: u16,
        from: Remote,
        now_ms: u64,
    ) -> Option<(IpAddr, u16)> {
        let filtering = self.filtering;
        let entry = self.by_ext.get_mut(&(proto, ext_port))?;
        if !entry.permits(filtering, from) {
            self.filtered_in += 1;
            return None;
        }
        entry.last_used_ms = now_ms;
        Some((entry.int_addr, entry.int_port))
    }

    /// Every live mapping, for the conformance report and the run record.
    #[must_use]
    pub fn entries(&self) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.by_ext.values().collect();
        v.sort_by_key(|e| e.ext_port);
        v
    }

    /// How many mappings are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ext.len()
    }

    /// Whether the table holds no mappings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_ext.is_empty()
    }

    fn allocate(&mut self, proto: u8) -> Result<u16, AllocFailure> {
        let span = u32::from(self.port_high) - u32::from(self.port_low) + 1;
        for _ in 0..span {
            let candidate = if self.mapping == Mapping::AddressPortDependentSequential {
                let p = u32::from(self.port_low) + (self.next_sequential % span);
                self.next_sequential = self.next_sequential.wrapping_add(1);
                p as u16
            } else {
                let r = self.next_random();
                (u32::from(self.port_low) + (r % u64::from(span)) as u32) as u16
            };
            if !self.by_ext.contains_key(&(proto, candidate)) {
                return Ok(candidate);
            }
        }
        self.exhaustions += 1;
        Err(AllocFailure::Exhausted)
    }

    /// SplitMix64. Chosen because it is four lines a reviewer can check and has
    /// no state beyond the seed, so two runs at one seed allocate the identical
    /// sequence of ports — which is what makes a `-RAND` prediction failure
    /// reproducible.
    fn next_random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn client() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
    }

    fn peer(last: u8, port: u16) -> Remote {
        Remote {
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
            port,
        }
    }

    fn table(m: Mapping, f: Filtering) -> Table {
        Table::new(m, f, 40_000, 40_100, 30_000, 7)
    }

    #[test]
    fn endpoint_independent_mapping_reuses_one_port_for_every_destination() {
        let mut t = table(Mapping::EndpointIndependent, Filtering::EndpointIndependent);
        let a = t.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        let b = t.outbound(17, client(), 5000, peer(2, 9), 0).unwrap();
        assert_eq!(a, b, "EIM must not allocate per destination");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn address_port_dependent_mapping_allocates_per_destination() {
        let mut t = table(
            Mapping::AddressPortDependentRandom,
            Filtering::AddressPortDependent,
        );
        let a = t.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        let b = t.outbound(17, client(), 5000, peer(2, 9), 0).unwrap();
        assert_ne!(a, b, "APDM must allocate per destination tuple");
    }

    #[test]
    fn the_sequential_allocator_is_the_delta_prediction_target_and_the_random_one_is_not() {
        let mut seq = table(
            Mapping::AddressPortDependentSequential,
            Filtering::AddressPortDependent,
        );
        let ports: Vec<u16> = (0..4)
            .map(|i| seq.outbound(17, client(), 5000, peer(i, 9), 0).unwrap())
            .collect();
        let deltas: Vec<i32> = ports
            .windows(2)
            .map(|w| i32::from(w[1]) - i32::from(w[0]))
            .collect();
        assert!(
            deltas.iter().all(|d| *d == 1),
            "a monotone allocator must have a constant delta, got {deltas:?}"
        );

        let mut rand = table(
            Mapping::AddressPortDependentRandom,
            Filtering::AddressPortDependent,
        );
        let ports: Vec<u16> = (0..8)
            .map(|i| rand.outbound(17, client(), 5000, peer(i, 9), 0).unwrap())
            .collect();
        let deltas: Vec<i32> = ports
            .windows(2)
            .map(|w| i32::from(w[1]) - i32::from(w[0]))
            .collect();
        assert!(
            deltas.windows(2).any(|w| w[0] != w[1]),
            "a uniform allocator must not produce a constant delta, got {deltas:?}"
        );
    }

    #[test]
    fn two_tables_at_one_seed_allocate_the_identical_port_sequence() {
        let run = || {
            let mut t = table(
                Mapping::AddressPortDependentRandom,
                Filtering::AddressPortDependent,
            );
            (0..16)
                .map(|i| t.outbound(17, client(), 5000, peer(i, 9), 0).unwrap())
                .collect::<Vec<u16>>()
        };
        assert_eq!(run(), run(), "a seeded allocator must be reproducible");
    }

    #[test]
    fn endpoint_independent_filtering_admits_a_stranger_and_address_dependent_does_not() {
        let mut eif = table(Mapping::EndpointIndependent, Filtering::EndpointIndependent);
        let ext = eif.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        assert!(
            eif.inbound(17, ext, peer(9, 1), 0).is_some(),
            "EIF admits a source that was never written to"
        );

        let mut adf = table(Mapping::EndpointIndependent, Filtering::AddressDependent);
        let ext = adf.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        assert!(
            adf.inbound(17, ext, peer(9, 1), 0).is_none(),
            "ADF refuses an address that was never written to"
        );
        assert!(
            adf.inbound(17, ext, peer(1, 77), 0).is_some(),
            "ADF admits the written address on a different port"
        );
        assert_eq!(adf.filtered_in, 1);
    }

    #[test]
    fn address_port_dependent_filtering_refuses_the_written_address_on_another_port() {
        let mut t = table(
            Mapping::EndpointIndependent,
            Filtering::AddressPortDependent,
        );
        let ext = t.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        assert!(t.inbound(17, ext, peer(1, 77), 0).is_none());
        assert!(t.inbound(17, ext, peer(1, 9), 0).is_some());
    }

    #[test]
    fn a_mapping_expires_at_its_configured_lifetime_and_inbound_traffic_refreshes_it() {
        let mut t = table(Mapping::EndpointIndependent, Filtering::EndpointIndependent);
        let ext = t.outbound(17, client(), 5000, peer(1, 9), 0).unwrap();
        t.expire(29_000);
        assert_eq!(t.len(), 1, "not yet at the lifetime");
        // RFC 4787 REQ-6: an inbound packet refreshes the mapping.
        assert!(t.inbound(17, ext, peer(1, 9), 29_000).is_some());
        t.expire(50_000);
        assert_eq!(t.len(), 1, "the inbound packet refreshed it");
        t.expire(90_000);
        assert_eq!(t.len(), 0, "idle past the lifetime, the mapping is gone");
    }

    #[test]
    fn the_port_budget_is_exhaustible_and_exhaustion_is_reported_rather_than_hidden() {
        let mut t = Table::new(
            Mapping::AddressPortDependentRandom,
            Filtering::AddressPortDependent,
            40_000,
            40_002,
            30_000,
            1,
        );
        for i in 0..3 {
            assert!(t.outbound(17, client(), 5000, peer(i, 9), 0).is_ok());
        }
        assert_eq!(
            t.outbound(17, client(), 5000, peer(200, 9), 0),
            Err(AllocFailure::Exhausted)
        );
        assert_eq!(t.exhaustions, 1);
    }
}
