//! The middlebox itself: two interfaces, one mapping table, and no flag inside
//! TwinVPN.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1, §3.3.
//!
//! # What makes this a legitimate realization of §3.3
//!
//! §3.3's `Realization` column names `nftables` and `conntrack`. That is *a*
//! mechanism, and where they exist the laboratory should prefer them. Where they
//! do not, §3.1 is the governing sentence and it constrains the **observable
//! semantics**, not the subsystem:
//!
//! > Every condition TwinLab reproduces MUST be produced by a mechanism with the
//! > same observable semantics as the real thing, never by a flag inside
//! > TwinVPN. A test MUST NOT be able to detect that it is running in TwinLab by
//! > inspecting the product's own configuration.
//!
//! This process is a real middlebox on the path. It sees real frames on a real
//! `veth`, holds real per-flow state with real timers, and re-emits real frames
//! with recomputed checksums. TwinVPN cannot detect it, because there is nothing
//! in TwinVPN to detect it *with*: no build flag, no environment variable, no
//! configuration key. The only way to tell it apart from an `nftables` NAT is to
//! probe its behaviour — which is exactly what §3.4.2's conformance suite does,
//! with a prober that is not TwinVPN code.
//!
//! **What it is not.** It is not a general-purpose router. It forwards exactly
//! the traffic a scenario puts through it, does not reassemble fragments, and
//! does not implement PCP, NAT-PMP or UPnP — §3.3 makes `none` the default for
//! that axis, and a middlebox that offered a port-mapping protocol nobody asked
//! for would make every traversal scenario pass for the wrong reason.

pub mod config;
pub mod pmtu;
pub mod table;
pub mod xlat;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::afpacket::PacketSocket;
use crate::error::Result;
use crate::ip::{self, Parsed};
use crate::observer::Prefix;
use crate::rewrite;
use config::{Egress, Mapping, NatConfig};
use table::{Remote, Table};
use xlat::Pref64;

/// The counters a conformance run reads back.
#[derive(Debug, Default, serde::Serialize)]
pub struct Counters {
    /// Frames seen on the inside interface.
    pub in_seen: u64,
    /// Frames translated and forwarded outbound.
    pub out_forwarded: u64,
    /// Outbound frames the egress policy refused. The "blocked UDP" evidence.
    pub egress_denied: u64,
    /// Outbound frames dropped because the port budget was full.
    pub exhausted: u64,
    /// Frames seen on the outside interface.
    pub ext_seen: u64,
    /// Inbound frames delivered to the inside.
    pub in_forwarded: u64,
    /// Inbound frames with no mapping at all.
    pub unmapped: u64,
    /// Inbound frames refused by the filtering behaviour. Non-zero is what
    /// makes a `RELAY_EXPECTED` pair's expectation an observation rather than an
    /// assumption.
    pub filtered: u64,
    /// Frames hairpinned back to the inside.
    pub hairpinned: u64,
    /// Frames dropped because the hop limit reached zero — a forwarding loop,
    /// which is a laboratory defect and must be visible as one.
    pub expired: u64,
    /// IPv6 packets translated into IPv4 and forwarded.
    pub translated_out: u64,
    /// IPv4 packets translated into IPv6 and delivered.
    pub translated_in: u64,
    /// Oversize packets this middlebox dropped **and reported**, which is what
    /// an ordinary MTU mismatch looks like and is the control the black hole is
    /// read against.
    pub pmtu_reported: u64,
    /// Path-MTU-discovery messages swallowed by the black hole. The number a
    /// §3.4.2 conformance run reads to confirm the condition was produced at
    /// all — a black hole that never had anything to swallow is a scenario in
    /// which PMTU discovery was never attempted.
    pub pmtu_dropped: u64,
    /// Packets a NAT64 refused to translate. **Not forwarded**: see
    /// `xlat::Refusal`. Non-zero here is the number a NAT64 conformance run
    /// reads to find out what it is not covering.
    pub untranslatable: u64,
}

macro_rules! bump {
    ($c:expr, $field:ident) => {
        $c.$field.fetch_add(1, Ordering::Relaxed)
    };
}

/// Atomic mirrors of [`Counters`], so the two forwarding threads and the
/// snapshot thread never contend on a lock for a count.
#[derive(Debug, Default)]
struct Atomics {
    in_seen: AtomicU64,
    out_forwarded: AtomicU64,
    egress_denied: AtomicU64,
    exhausted: AtomicU64,
    ext_seen: AtomicU64,
    in_forwarded: AtomicU64,
    unmapped: AtomicU64,
    filtered: AtomicU64,
    hairpinned: AtomicU64,
    expired: AtomicU64,
    pmtu_reported: AtomicU64,
    pmtu_dropped: AtomicU64,
    translated_out: AtomicU64,
    translated_in: AtomicU64,
    untranslatable: AtomicU64,
}

impl Atomics {
    fn snapshot(&self) -> Counters {
        Counters {
            in_seen: self.in_seen.load(Ordering::Relaxed),
            out_forwarded: self.out_forwarded.load(Ordering::Relaxed),
            egress_denied: self.egress_denied.load(Ordering::Relaxed),
            exhausted: self.exhausted.load(Ordering::Relaxed),
            ext_seen: self.ext_seen.load(Ordering::Relaxed),
            in_forwarded: self.in_forwarded.load(Ordering::Relaxed),
            unmapped: self.unmapped.load(Ordering::Relaxed),
            filtered: self.filtered.load(Ordering::Relaxed),
            hairpinned: self.hairpinned.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            pmtu_reported: self.pmtu_reported.load(Ordering::Relaxed),
            pmtu_dropped: self.pmtu_dropped.load(Ordering::Relaxed),
            translated_out: self.translated_out.load(Ordering::Relaxed),
            translated_in: self.translated_in.load(Ordering::Relaxed),
            untranslatable: self.untranslatable.load(Ordering::Relaxed),
        }
    }
}

/// What the middlebox writes to its stats file, and what a conformance run
/// asserts against.
#[derive(Debug, serde::Serialize)]
pub struct Snapshot {
    /// §3.3's name for the configured combination.
    pub personality: String,
    /// The counters.
    pub counters: Counters,
    /// Live mappings, as `internal:port -> external port [remotes seen]`.
    pub mappings: Vec<MappingRow>,
    /// How many times the port budget was exhausted.
    pub exhaustions: u64,
}

/// One live mapping, flattened for a report.
#[derive(Debug, serde::Serialize)]
pub struct MappingRow {
    /// The internal address.
    pub internal: String,
    /// The internal port.
    pub internal_port: u16,
    /// The allocated external port.
    pub external_port: u16,
    /// The protocol number.
    pub proto: u8,
    /// Every remote this mapping has been written to.
    pub remotes: Vec<String>,
}

struct Shared {
    inside: Vec<Prefix>,
    cfg: NatConfig,
    table: Mutex<Table>,
    /// Learned on the inside: which host behind this middlebox owns an address.
    inside_macs: Mutex<HashMap<IpAddr, [u8; 6]>>,
    /// Learned on the outside, seeded from the configuration. Kept separate
    /// from the inside table on purpose: one map would let a spoofed inside
    /// packet redirect an outside next hop, which is a laboratory that can be
    /// steered by the traffic it is measuring.
    outside_macs: Mutex<HashMap<IpAddr, [u8; 6]>>,
    counters: Atomics,
    started: Instant,
    stop: AtomicBool,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn public(&self, family_of: IpAddr) -> Option<IpAddr> {
        match family_of {
            IpAddr::V4(_) => self.cfg.public_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.cfg.public_v6.map(IpAddr::V6),
        }
    }
}

/// The two `procfs` files that say whether the kernel of a namespace forwards.
///
/// Named here rather than spelled at each of the two readers, because the two
/// read them from different namespaces: [`run`] reads its own, and
/// [`crate::fabric::Fabric::start_nat`] reads the node's through the sandbox
/// agent. A pair that drifted apart would leave one of the two guards checking
/// the wrong thing.
pub const FORWARDING_KNOBS: [&str; 2] = [
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];

/// Why this middlebox must not run in this namespace, or `None`.
///
/// **A middlebox owns the forwarding path or it is not a middlebox.** This
/// process moves frames between two interfaces itself; if the kernel of the
/// same namespace also forwards, every packet has two ways out and the
/// untranslated one usually wins the race. The observable result is a NAT that
/// appears to be in the path and translates nothing: the far end sees the
/// client's private address, the client's peer punches at an address that is
/// not routable, and the scenario reports a traversal failure that has nothing
/// to do with traversal.
///
/// That happened (job 100276849297). It is a fail-open shape — the laboratory
/// ran a scenario as if a middlebox were realizing it — so the answer is to
/// refuse, naming the knob and the value, rather than to translate what the
/// kernel has not already carried away.
///
/// Takes the file *contents* rather than reading them, so both readers share
/// one decision and a test can inject the state no host here has.
#[must_use]
pub fn forwarding_conflict(values: &[(&str, &str)]) -> Option<String> {
    let on: Vec<&str> = values
        .iter()
        .filter(|(_, v)| v.trim() != "0")
        .map(|(k, _)| *k)
        .collect();
    if on.is_empty() {
        return None;
    }
    Some(format!(
        "the kernel of this namespace forwards ({} is not 0), so it would carry \
         frames around this middlebox untranslated and the scenario would measure \
         the kernel rather than the personality. A fresh namespace inherits these \
         from the initial one (net/ipv4/devinet.c, devinet_init_net), so a host \
         running Docker hands every namespace ip_forward=1; the topology must set \
         them to 0 for a node that has a middlebox in it",
        on.join(" and ")
    ))
}

/// Reads [`FORWARDING_KNOBS`] in this process's own namespace.
fn own_forwarding_conflict() -> Option<String> {
    let read: Vec<(&str, String)> = FORWARDING_KNOBS
        .iter()
        // A knob that cannot be read is not evidence of forwarding: a kernel
        // built without IPv6 has no such file, and refusing to start there
        // would be a refusal about a family the scenario never used.
        .filter_map(|k| std::fs::read_to_string(k).ok().map(|v| (*k, v)))
        .collect();
    let borrowed: Vec<(&str, &str)> = read.iter().map(|(k, v)| (*k, v.as_str())).collect();
    forwarding_conflict(&borrowed)
}

/// Runs the middlebox until the process is signalled.
///
/// Two threads, one per direction, sharing the mapping table. A single-threaded
/// loop with a read timeout would add that timeout to every packet's latency,
/// and this laboratory measures latency.
///
/// # Errors
///
/// [`crate::error::NetError::Unavailable`] if either raw socket cannot be
/// opened, [`crate::error::NetError::Malformed`] if the configuration
/// contradicts itself or if the kernel of this namespace forwards as well —
/// see [`forwarding_conflict`].
pub fn run(cfg: NatConfig) -> Result<()> {
    cfg.validate().map_err(crate::error::NetError::Malformed)?;
    if let Some(why) = own_forwarding_conflict() {
        return Err(crate::error::NetError::Malformed(why));
    }
    let mut inside = PacketSocket::open(&cfg.inside_if)?;
    let mut outside = PacketSocket::open(&cfg.outside_if)?;
    inside.set_promiscuous()?;
    outside.set_promiscuous()?;
    // A forwarder that read back its own transmissions would forward each
    // packet to itself for ever.
    inside.ignore_outgoing(true);
    outside.ignore_outgoing(true);

    let inside_prefixes: Vec<Prefix> = cfg
        .inside_prefixes
        .iter()
        .filter_map(|p| Prefix::parse(p).ok())
        .collect();
    if inside_prefixes.len() != cfg.inside_prefixes.len() {
        return Err(crate::error::NetError::Malformed(format!(
            "one of the inside prefixes {:?} is not a prefix",
            cfg.inside_prefixes
        )));
    }
    let shared = Arc::new(Shared {
        inside: inside_prefixes,
        table: Mutex::new(Table::new(
            cfg.mapping,
            cfg.filtering,
            cfg.port_low,
            cfg.port_high,
            cfg.mapping_lifetime_ms,
            cfg.seed,
        )),
        inside_macs: Mutex::new(HashMap::new()),
        outside_macs: Mutex::new(
            cfg.outside_neighbours
                .iter()
                .filter_map(|n| n.addr.parse::<IpAddr>().ok().map(|a| (a, n.mac)))
                .collect(),
        ),
        counters: Atomics::default(),
        started: Instant::now(),
        stop: AtomicBool::new(false),
        cfg,
    });

    let stats = shared.cfg.stats_path.clone();
    let out_side = Arc::clone(&shared);
    let in_side = Arc::clone(&shared);
    let snap_side = Arc::clone(&shared);

    std::thread::scope(|scope| {
        let (inside, outside) = (&inside, &outside);
        scope.spawn(move || pump_outbound(&out_side, inside, outside));
        scope.spawn(move || pump_inbound(&in_side, outside, inside));
        if let Some(path) = stats {
            scope.spawn(move || {
                while !snap_side.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    write_snapshot(&snap_side, &path);
                }
            });
        }
    });
    Ok(())
}

fn write_snapshot(shared: &Shared, path: &str) {
    let table = shared.table.lock().expect("the mapping table lock");
    let snapshot = Snapshot {
        personality: shared.cfg.personality.clone(),
        counters: shared.counters.snapshot(),
        exhaustions: table.exhaustions,
        mappings: table
            .entries()
            .into_iter()
            .map(|e| MappingRow {
                internal: e.int_addr.to_string(),
                internal_port: e.int_port,
                external_port: e.ext_port,
                proto: e.proto,
                remotes: e
                    .seen
                    .iter()
                    .map(|r| format!("{}:{}", r.addr, r.port))
                    .collect(),
            })
            .collect(),
    };
    drop(table);
    if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
        // A temp-then-rename so a reader never sees half a snapshot.
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn pump_outbound(shared: &Shared, inside: &PacketSocket, outside: &PacketSocket) {
    let mut buf = vec![0u8; 65_536];
    while !shared.stop.load(Ordering::Relaxed) {
        let Ok(Some(n)) = inside.recv(&mut buf) else {
            continue;
        };
        bump!(shared.counters, in_seen);
        let frame = &mut buf[..n];
        let Some(mut p) = ip::parse(frame) else {
            continue;
        };
        shared
            .inside_macs
            .lock()
            .expect("the inside mac table lock")
            .insert(p.src, p.eth_src);

        if matches!(shared.cfg.egress, Egress::Blackhole) {
            bump!(shared.counters, egress_denied);
            continue;
        }
        if !shared.cfg.egress.permits(p.proto, p.dst_port.unwrap_or(0)) {
            bump!(shared.counters, egress_denied);
            continue;
        }
        if !rewrite::decrement_hop_limit(frame, &p) {
            bump!(shared.counters, expired);
            continue;
        }

        // Inside to inside: routed, never translated. A packet that does not
        // leave has nothing to be translated to.
        if shared.inside.iter().any(|pre| pre.contains(p.dst)) {
            complete_checksums(frame, &p);
            let mac = mac_for(shared, p.dst);
            rewrite::set_ethernet(frame, mac, shared.cfg.inside_mac);
            let _ = inside.send(frame);
            bump!(shared.counters, in_forwarded);
            continue;
        }

        // Hairpinning: an inside host addressing this middlebox's own public
        // address. RFC 4787 REQ-9, off unless the scenario asked for it.
        if Some(p.dst) == shared.public(p.dst) {
            if shared.cfg.hairpin {
                hairpin(shared, frame, &mut p, inside);
            }
            continue;
        }

        if shared.cfg.drop_pmtu_icmp && is_pmtu_signal(frame, &p) {
            bump!(shared.counters, pmtu_dropped);
            continue;
        }
        if constricted(shared, &p, frame.len()) {
            // Too big for the egress. A router drops it and reports the MTU;
            // a black hole drops it and says nothing.
            if shared.cfg.drop_pmtu_icmp {
                bump!(shared.counters, pmtu_dropped);
            } else if let Some(mtu) = shared.cfg.egress_mtu {
                if let Some(report) = pmtu::too_big(frame, &p, mtu, shared.cfg.inside_mac) {
                    let _ = inside.send(&report);
                    bump!(shared.counters, pmtu_reported);
                }
            }
            continue;
        }

        // A router does not forward link-local or multicast, and neither does
        // this one. Dropping them is not tidiness: an interface emits router
        // solicitations and MLD reports from a link-local address the moment it
        // comes up, and a middlebox that forwarded those would put them on a
        // segment no scenario ever addressed.
        if is_unforwardable(p.src) || is_unforwardable(p.dst) {
            continue;
        }

        // §3.3's `N-NAT64`. Checked before the routed and the family-passthrough
        // branches, because a destination inside the translation prefix is
        // neither: forwarding it would put an IPv6 address on an IPv4 network.
        if let Some(pref64) = shared.cfg.pref64 {
            if xlat::translated_destination(pref64, &p).is_some() {
                translate_outbound(shared, frame, &p, pref64, outside);
                continue;
            }
            // An IPv6 destination outside the translation prefix, on a NAT64
            // whose outside is IPv4-only. There is no IPv6 next hop, so this is
            // dropped rather than forwarded.
            //
            // **This was a defect, and the wire oracle is what found it.** The
            // general "a family this middlebox does not translate is routed"
            // branch below is right for a dual-stack middlebox and wrong here:
            // it forwarded the client's own router solicitation onto the
            // IPv4-only segment. A NAT64 that emits IPv6 towards IPv4 is the one
            // thing `nat::xlat` exists to prevent, and it was doing it for every
            // packet that was not addressed through the prefix.
            if matches!(p.dst, IpAddr::V6(_)) {
                bump!(shared.counters, untranslatable);
                continue;
            }
        }

        if shared.cfg.mapping == Mapping::None {
            complete_checksums(frame, &p);
            let next = next_hop(shared, p.dst);
            rewrite::set_ethernet(frame, next, shared.cfg.outside_mac);
            let _ = outside.send(frame);
            bump!(shared.counters, out_forwarded);
            continue;
        }
        let Some(public) = shared.public(p.src) else {
            // A family this middlebox does not translate. §3.2's last row makes
            // native v6 the case that keeps working, so a v6 packet through a
            // v4-only NAT is *routed*, not dropped.
            complete_checksums(frame, &p);
            let next = next_hop(shared, p.dst);
            rewrite::set_ethernet(frame, next, shared.cfg.outside_mac);
            let _ = outside.send(frame);
            bump!(shared.counters, out_forwarded);
            continue;
        };
        let remote = Remote {
            addr: p.dst,
            port: p.dst_port.unwrap_or(0),
        };
        let now = shared.now_ms();
        let allocated = {
            let mut t = shared.table.lock().expect("the mapping table lock");
            t.expire(now);
            t.outbound(p.proto, p.src, p.src_port.unwrap_or(0), remote, now)
        };
        let Ok(ext) = allocated else {
            bump!(shared.counters, exhausted);
            continue;
        };
        let next = next_hop(shared, p.dst);
        rewrite::set_src(frame, &mut p, public);
        rewrite::set_src_port(frame, &mut p, ext);
        rewrite::set_ethernet(frame, next, shared.cfg.outside_mac);
        let _ = outside.send(frame);
        bump!(shared.counters, out_forwarded);
    }
}

fn pump_inbound(shared: &Shared, outside: &PacketSocket, inside: &PacketSocket) {
    let mut buf = vec![0u8; 65_536];
    while !shared.stop.load(Ordering::Relaxed) {
        let Ok(Some(n)) = outside.recv(&mut buf) else {
            continue;
        };
        bump!(shared.counters, ext_seen);
        let frame = &mut buf[..n];
        let Some(mut p) = ip::parse(frame) else {
            continue;
        };
        if shared.cfg.drop_pmtu_icmp && is_pmtu_signal(frame, &p) {
            bump!(shared.counters, pmtu_dropped);
            continue;
        }
        if is_unforwardable(p.src) || is_unforwardable(p.dst) {
            continue;
        }
        shared
            .outside_macs
            .lock()
            .expect("the outside mac table lock")
            .insert(p.src, p.eth_src);
        if matches!(shared.cfg.egress, Egress::Blackhole) {
            continue;
        }
        if !rewrite::decrement_hop_limit(frame, &p) {
            bump!(shared.counters, expired);
            continue;
        }
        if let Some(pref64) = shared.cfg.pref64 {
            if shared.cfg.public_v4.map(IpAddr::V4) == Some(p.dst) {
                translate_inbound(shared, frame, &p, pref64, inside);
                continue;
            }
        }

        if shared.cfg.mapping == Mapping::None || shared.public(p.dst) != Some(p.dst) {
            // Routed, or a family this middlebox does not translate.
            complete_checksums(frame, &p);
            let mac = mac_for(shared, p.dst);
            rewrite::set_ethernet(frame, mac, shared.cfg.inside_mac);
            let _ = inside.send(frame);
            bump!(shared.counters, in_forwarded);
            continue;
        }
        let from = Remote {
            addr: p.src,
            port: p.src_port.unwrap_or(0),
        };
        let now = shared.now_ms();
        let (resolved, filtered_before, filtered_after) = {
            let mut t = shared.table.lock().expect("the mapping table lock");
            t.expire(now);
            let before = t.filtered_in;
            let r = t.inbound(p.proto, p.dst_port.unwrap_or(0), from, now);
            (r, before, t.filtered_in)
        };
        let Some((int_addr, int_port)) = resolved else {
            if filtered_after > filtered_before {
                bump!(shared.counters, filtered);
            } else {
                bump!(shared.counters, unmapped);
            }
            continue;
        };
        rewrite::set_dst(frame, &mut p, int_addr);
        rewrite::set_dst_port(frame, &mut p, int_port);
        let mac = mac_for(shared, int_addr);
        rewrite::set_ethernet(frame, mac, shared.cfg.inside_mac);
        let _ = inside.send(frame);
        bump!(shared.counters, in_forwarded);
    }
}

/// Translates a packet an inside host sent to this middlebox's own public
/// address and returns it to the inside.
fn hairpin(shared: &Shared, frame: &mut [u8], p: &mut Parsed, inside: &PacketSocket) {
    let Some(public) = shared.public(p.src) else {
        return;
    };
    let now = shared.now_ms();
    let remote = Remote {
        addr: p.dst,
        port: p.dst_port.unwrap_or(0),
    };
    let (target, sender_ext) = {
        let mut t = shared.table.lock().expect("the mapping table lock");
        t.expire(now);
        let target = t.inbound(p.proto, p.dst_port.unwrap_or(0), remote, now);
        // RFC 4787 REQ-9(a): the hairpinned packet's source MUST be the
        // sender's *external* address, not its internal one. A middlebox that
        // skipped this would let the receiving peer learn an address it can
        // never reach from outside, and the scenario would pass for a reason
        // that does not exist in a real network.
        let ext = t
            .outbound(p.proto, p.src, p.src_port.unwrap_or(0), remote, now)
            .ok();
        (target, ext)
    };
    let (Some((int_addr, int_port)), Some(ext)) = (target, sender_ext) else {
        return;
    };
    rewrite::set_src(frame, p, public);
    rewrite::set_src_port(frame, p, ext);
    rewrite::set_dst(frame, p, int_addr);
    rewrite::set_dst_port(frame, p, int_port);
    let mac = mac_for(shared, int_addr);
    rewrite::set_ethernet(frame, mac, shared.cfg.inside_mac);
    let _ = inside.send(frame);
    bump!(shared.counters, hairpinned);
}

/// Translates an IPv6 packet bound for the v4 Internet, and sends it.
///
/// The mapping table is the same one every other personality uses: the internal
/// endpoint it stores is simply an IPv6 one. That is what makes a NAT64's
/// mapping and filtering behaviour the *same* two axes as everything else in
/// §3.3, rather than a special case whose RFC 4787 semantics nobody checked.
fn translate_outbound(
    shared: &Shared,
    frame: &[u8],
    p: &Parsed,
    pref64: Pref64,
    outside: &PacketSocket,
) {
    let (Some(v4_dst), Some(public)) = (
        xlat::translated_destination(pref64, p),
        shared.cfg.public_v4,
    ) else {
        return;
    };
    let now = shared.now_ms();
    let remote = Remote {
        addr: IpAddr::V4(v4_dst),
        port: p.dst_port.unwrap_or(0),
    };
    let allocated = {
        let mut t = shared.table.lock().expect("the mapping table lock");
        t.expire(now);
        t.outbound(
            translated_proto(p.proto),
            p.src,
            p.src_port.unwrap_or(0),
            remote,
            now,
        )
    };
    let Ok(ext) = allocated else {
        bump!(shared.counters, exhausted);
        return;
    };
    let Ok(mut out) = xlat::v6_to_v4(frame, p, public, v4_dst, Some(ext)) else {
        // A refusal, never a pass-through: see `xlat::Refusal`.
        bump!(shared.counters, untranslatable);
        return;
    };
    let next = next_hop(shared, IpAddr::V4(v4_dst));
    rewrite::set_ethernet(&mut out, next, shared.cfg.outside_mac);
    let _ = outside.send(&out);
    bump!(shared.counters, translated_out);
    bump!(shared.counters, out_forwarded);
}

/// Translates an IPv4 reply back into IPv6, and sends it to the client.
fn translate_inbound(
    shared: &Shared,
    frame: &[u8],
    p: &Parsed,
    pref64: Pref64,
    inside: &PacketSocket,
) {
    let IpAddr::V4(v4_src) = p.src else {
        return;
    };
    let now = shared.now_ms();
    let from = Remote {
        addr: p.src,
        port: p.src_port.unwrap_or(0),
    };
    let resolved = {
        let mut t = shared.table.lock().expect("the mapping table lock");
        t.expire(now);
        t.inbound(
            translated_proto(p.proto),
            p.dst_port.unwrap_or(0),
            from,
            now,
        )
    };
    let Some((IpAddr::V6(client), int_port)) = resolved else {
        bump!(shared.counters, unmapped);
        return;
    };
    let Ok(mut out) = xlat::v4_to_v6(frame, p, pref64.embed(v4_src), client, Some(int_port)) else {
        bump!(shared.counters, untranslatable);
        return;
    };
    let mac = mac_for(shared, IpAddr::V6(client));
    rewrite::set_ethernet(&mut out, mac, shared.cfg.inside_mac);
    let _ = inside.send(&out);
    bump!(shared.counters, translated_in);
    bump!(shared.counters, in_forwarded);
}

/// The protocol number a flow is keyed on across a translation.
///
/// ICMPv6 and ICMP are the *same flow* seen from two sides, and keying the
/// outbound half on 58 while the reply arrives as 1 would leave every
/// translated ping unmatched — a NAT64 that worked for UDP and silently did not
/// for `ping`, which is the first thing anyone tries.
const fn translated_proto(proto: u8) -> u8 {
    match proto {
        crate::ip::proto::ICMPV6 => crate::ip::proto::ICMP,
        other => other,
    }
}

/// Completes a checksum the sending kernel left partial.
///
/// **This is not cosmetic, and the defect it fixes is worth recording.** A
/// packet a host generates for a `veth` may carry `CHECKSUM_PARTIAL`: the
/// transport checksum on the wire is an incomplete value the receiving stack is
/// told to ignore, because both ends are the same kernel. A middlebox that
/// captures such a frame with `AF_PACKET` and re-injects it on another
/// interface hands the receiver a raw frame with no offload promise attached,
/// and the receiver drops it for a bad checksum.
///
/// The translating paths never hit this, because they recompute the checksum as
/// part of the rewrite. The pass-through paths — `N-ROUTED`, and a family this
/// middlebox does not translate — did, and the symptom was precise and
/// misleading: **every NAT personality traversed and the router did not.**
fn complete_checksums(frame: &mut [u8], p: &Parsed) {
    rewrite::fix_ip_checksum(frame, p);
    rewrite::fix_l4_checksum(frame, p);
}

/// Whether a packet is larger than this middlebox will forward.
///
/// Measured against the IP packet, not the Ethernet frame: an MTU is a layer-3
/// number, and comparing a frame against it would constrict 14 bytes early.
fn constricted(shared: &Shared, p: &Parsed, frame_len: usize) -> bool {
    let Some(mtu) = shared.cfg.egress_mtu else {
        return false;
    };
    frame_len.saturating_sub(p.l3_off) > mtu as usize
}

/// Whether a packet is the ICMP message Path MTU discovery depends on.
///
/// ICMPv4 type 3 code 4 (`fragmentation needed and DF set`) and ICMPv6 type 2
/// (`packet too big`). Nothing else: dropping every ICMP error would make a
/// black hole indistinguishable from a firewall, and §3.4 asks for the former.
fn is_pmtu_signal(frame: &[u8], p: &Parsed) -> bool {
    let Some(body) = frame.get(p.l4_off..p.l4_off + 2) else {
        return false;
    };
    match p.proto {
        crate::ip::proto::ICMP => body[0] == 3 && body[1] == 4,
        crate::ip::proto::ICMPV6 => body[0] == 2,
        _ => false,
    }
}

/// Whether an address is one no router forwards.
///
/// Link-local in either family, and any multicast destination. A middlebox that
/// forwarded these would carry a segment's own housekeeping onto another
/// segment, where it is indistinguishable from a leak.
fn is_unforwardable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            // `is_unicast_link_local` is not stable, so the prefix is checked
            // directly: fe80::/10.
            let o = v6.octets();
            (o[0] == 0xfe && (o[1] & 0xc0) == 0x80) || v6.is_multicast()
        }
    }
}

fn mac_for(shared: &Shared, addr: IpAddr) -> [u8; 6] {
    shared
        .inside_macs
        .lock()
        .expect("the inside mac table lock")
        .get(&addr)
        .copied()
        .unwrap_or(shared.cfg.inside_peer_mac)
}

/// The link-layer next hop for an outside destination: a configured neighbour,
/// then one observed, then the default.
fn next_hop(shared: &Shared, addr: IpAddr) -> [u8; 6] {
    shared
        .outside_macs
        .lock()
        .expect("the outside mac table lock")
        .get(&addr)
        .copied()
        .unwrap_or(shared.cfg.outside_peer_mac)
}

#[cfg(test)]
mod tests {
    use super::{forwarding_conflict, FORWARDING_KNOBS};

    const V4: &str = FORWARDING_KNOBS[0];
    const V6: &str = FORWARDING_KNOBS[1];

    #[test]
    fn a_namespace_that_forwards_nothing_lets_the_middlebox_run() {
        assert_eq!(forwarding_conflict(&[(V4, "0\n"), (V6, "0\n")]), None);
    }

    #[test]
    fn either_family_forwarding_is_enough_to_refuse_and_the_reason_names_it() {
        for (v4, v6, expected) in [("1\n", "0\n", V4), ("0\n", "1\n", V6)] {
            let why = forwarding_conflict(&[(V4, v4), (V6, v6)])
                .unwrap_or_else(|| panic!("ip_forward={v4:?} v6={v6:?} must refuse"));
            assert!(
                why.contains(expected),
                "the refusal must name the knob that is on, so a reader turns the \
                 right one off: {why}"
            );
        }
    }

    #[test]
    fn both_families_forwarding_are_reported_together_and_not_one_at_a_time() {
        // A refusal naming only the first would send a reader round the loop
        // twice for one topology defect.
        let why = forwarding_conflict(&[(V4, "1"), (V6, "1")]).expect("two knobs on must refuse");
        assert!(why.contains(V4) && why.contains(V6), "{why}");
    }

    #[test]
    fn a_knob_that_does_not_exist_is_not_read_as_forwarding() {
        // A kernel built without IPv6 has no such file, and refusing there
        // would be a refusal about a family the scenario never used. Both
        // readers drop a knob they cannot read, so an absent one arrives here
        // as an absent entry.
        assert_eq!(forwarding_conflict(&[]), None);
        assert_eq!(forwarding_conflict(&[(V4, "0")]), None);
    }

    #[test]
    fn a_value_that_is_not_recognisably_off_is_refused_rather_than_assumed_off() {
        // The only safe reading of a knob whose value this cannot make sense of
        // is that the kernel might forward. A middlebox is the wrong place to
        // guess in the permissive direction.
        for odd in ["", "  \n", "2", "on"] {
            assert!(
                forwarding_conflict(&[(V4, odd)]).is_some(),
                "`{odd:?}` was treated as forwarding-off"
            );
        }
    }
}
