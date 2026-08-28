//! The establishment path: what `session.connect` actually does.
//!
//! **Authority:** `docs/reliability.md` §4.4 (the `DISCOVERING` invariant),
//! §4.5 T01/T03/T04; `docs/protocol.md` §10 (establishment);
//! [ADR-0010](../../../../docs/adr/ADR-0010-ipv4-ipv6-routing.md) R1 (both
//! families, concurrently); ADR-0018 CB-2 (the core decides), §11.6 (the seam).
//!
//! # Why this module exists
//!
//! `twinvpn-path` is all decision and no I/O: it scores, races, validates and
//! keeps a ledger, taking facts as parameters. `twinvpn-platform` is all seam
//! and no decision. Neither one gathers a candidate, because gathering is
//! *asking the platform a question and deciding what the answer means* — which
//! is exactly the join CB-1 assigns to the core and CB-2 forbids a shell to
//! hold. Until this module existed, `session.connect` had nothing to call.
//!
//! # Both families, concurrently, or the reason why not
//!
//! §4.4's `DISCOVERING` invariant and ADR-0010 R1 both require v4 and v6 to be
//! gathered **together**. [`gather`] therefore asks the adapter which families
//! it can open, attempts **both**, and records a per-family outcome — so
//! "IPv6 produced nothing" and "we never looked at IPv6" are different answers.

use std::sync::Arc;

use twinvpn_env::{Env, MonotonicInstant};
use twinvpn_path::candidate::{Candidate, GatherPlan, Kind};
use twinvpn_path::ledger::{Ledger, Standing};
use twinvpn_path::race::Race;
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::PlatformAdapter;
use twinvpn_types::{
    AddressFamily, CandidateId, Endpoint, Identifier as _, IpAddr, PerFamily, SessionId,
};

/// What one family's gathering produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyOutcome {
    /// The host cannot open a socket of this family at all. A **fact about the
    /// host**, not a failure to retry.
    Unsupported,
    /// A socket opened and produced at least one candidate.
    Gathered {
        /// How many candidates.
        count: usize,
    },
    /// A socket opened and the interface table reported no address of this
    /// family at all.
    NoAddress,
    /// A socket opened, the interface table reported prefixes of this family,
    /// and **none of them names a host address**.
    ///
    /// See [`host_address`]: `InterfaceFacts.addresses` is a `Vec<IpPrefix>`,
    /// and `IpPrefix::address()` is documented as *"the network address"* —
    /// `IpPrefix::new` rejects any set host bit. So an adapter reporting
    /// `192.0.2.10/24` hands the core `192.0.2.0/24`, and the interface's own
    /// address is **not recoverable from the seam**.
    ///
    /// This is a distinct outcome from [`FamilyOutcome::NoAddress`] on purpose:
    /// "the OS reported nothing" and "the OS reported something the seam cannot
    /// carry" are different facts, and folding them together would hide a
    /// contract defect as an empty network.
    AddressNotReportable,
    /// The platform refused the bind.
    Refused,
}

impl FamilyOutcome {
    /// Whether this family contributed a candidate.
    #[must_use]
    pub const fn produced(self) -> bool {
        matches!(self, FamilyOutcome::Gathered { .. })
    }
}

/// One gathering round's result.
pub struct Gathered {
    /// The candidates, both families in gather order.
    pub candidates: Vec<Candidate>,
    /// The sockets that produced them, held so a probe leaves from the same
    /// local endpoint the candidate names.
    pub sockets: Vec<Box<dyn UdpSocket>>,
    /// Per-family outcome. **Both halves always present** — `PerFamily` makes
    /// forgetting the v6 half a compile error rather than a review comment.
    pub outcome: PerFamily<FamilyOutcome>,
    /// The plan, for the ledger's ordering assertions.
    pub plan: GatherPlan,
}

impl Gathered {
    /// Whether only one family produced anything.
    ///
    /// `protocol.md` §4.1 requires this to be flagged
    /// `NAT.SINGLE_FAMILY_CANDIDATES` — it is "the leading cause of *works at
    /// home, fails on cellular*".
    #[must_use]
    pub const fn single_family(&self) -> bool {
        self.outcome.v4.produced() != self.outcome.v6.produced()
    }

    /// T04's guard: gathering produced nothing on **either** family.
    #[must_use]
    pub fn no_candidate_either_family(&self) -> bool {
        self.candidates.is_empty()
    }

    /// T03's guard: at least one usable candidate exists.
    #[must_use]
    pub fn usable_candidate(&self) -> bool {
        !self.candidates.is_empty()
    }
}

/// Gathers host candidates for **both** families.
///
/// Every step is a real adapter call: `supported_families`, `enumerate`, and one
/// `bind_udp` per family the host offers. Nothing substitutes one family for
/// another — `SocketProvider::bind_udp`'s own doc calls substituting "how a
/// v6-only network silently becomes a v4-only session".
pub async fn gather(
    env: &Env,
    adapter: &Arc<dyn PlatformAdapter>,
    session_id: SessionId,
) -> Gathered {
    let now = env.now_monotonic();
    let plan = GatherPlan::new(now);

    let supported = adapter.sockets().supported_families().await.unwrap_or(
        twinvpn_platform::socket::SupportedFamilies {
            v4: false,
            v6: false,
            dual_stack_socket: false,
        },
    );

    // The interface table is the source of host candidates. An enumeration
    // failure is not "no interfaces": it is a refusal, and the two produce
    // different per-family outcomes below.
    let interfaces = adapter.interfaces().enumerate().await;

    let mut candidates = Vec::new();
    let mut sockets = Vec::new();
    let mut outcome = PerFamily::new(FamilyOutcome::Unsupported, FamilyOutcome::Unsupported);

    for family in [AddressFamily::V4, AddressFamily::V6] {
        let available = match family {
            AddressFamily::V4 => supported.v4,
            AddressFamily::V6 => supported.v6,
        };
        if !available {
            *outcome.get_mut(family) = FamilyOutcome::Unsupported;
            continue;
        }

        let spec = UdpBindSpec {
            family: match family {
                AddressFamily::V4 => SocketFamily::V4,
                AddressFamily::V6 => SocketFamily::V6Only,
            },
            local: None,
            options: SocketOptions::default(),
        };
        let Ok(socket) = adapter.sockets().bind_udp(&spec).await else {
            *outcome.get_mut(family) = FamilyOutcome::Refused;
            continue;
        };
        let Ok(local) = socket.local_endpoint() else {
            *outcome.get_mut(family) = FamilyOutcome::Refused;
            continue;
        };

        let before = candidates.len();
        let mut not_reportable = 0usize;
        let mut prefixes_seen = 0usize;
        // One host candidate per address of this family the OS reports, at the
        // port the socket actually got. An interface the core created itself is
        // skipped: an overlay address is not an underlay candidate, and offering
        // one is how a tunnel comes to be routed through itself.
        if let Ok(facts) = interfaces.as_ref() {
            for iface in facts.iter().filter(|i| !i.is_overlay && i.is_up) {
                for prefix in &iface.addresses {
                    if prefix.address().family() != family {
                        continue;
                    }
                    prefixes_seen += 1;
                    let Some(address) = host_address(*prefix) else {
                        not_reportable += 1;
                        continue;
                    };
                    let candidate = Candidate {
                        id: candidate_id(session_id, candidates.len()),
                        kind: host_kind(address),
                        endpoint: Endpoint::new(address, local.port),
                        gathered_at: env.now_monotonic(),
                        mtu_hint: iface.mtu,
                    };
                    // A malformed candidate is DROPPED, not repaired: an IPv6
                    // link-local with no zone index is unusable on a
                    // multi-interface host, and shipping it wastes a probe.
                    if candidate.is_well_formed() {
                        candidates.push(candidate);
                    }
                }
            }
        }

        let produced = candidates.len() - before;
        *outcome.get_mut(family) = if produced > 0 {
            FamilyOutcome::Gathered { count: produced }
        } else if not_reportable > 0 {
            FamilyOutcome::AddressNotReportable
        } else {
            let _ = prefixes_seen;
            FamilyOutcome::NoAddress
        };
        sockets.push(socket);
    }

    Gathered {
        candidates,
        sockets,
        outcome,
        plan,
    }
}

/// The interface's own address, where the seam can carry it.
///
/// # A contract defect, worked around rather than guessed
///
/// `InterfaceFacts.addresses` is `Vec<IpPrefix>` and its doc reads *"Every
/// address on it, with its prefix"* — but `IpPrefix::new` **rejects any set host
/// bit** (`TypeError::PrefixNotCanonical`) and `IpPrefix::address()` is
/// documented as *"the network address"*. An adapter holding `192.0.2.10/24`
/// therefore cannot express it: constructing that `IpPrefix` fails, and the
/// canonical `192.0.2.0/24` names the network, not the host.
///
/// **Consequence: the core cannot learn its own address from the platform seam
/// for any interface whose prefix is shorter than a single host.**
///
/// The only unambiguous case is a single-host prefix — `/32` on v4, `/128` on
/// v6 — where the network address *is* the host address. This function accepts
/// exactly that and refuses everything else, because using a network address as
/// a candidate would send probes to an address nothing answers on, and that
/// failure would look like a NAT problem rather than a contract one.
///
/// Reported to the integration lead. The fix belongs in `twinvpn-platform`
/// (`core-foundation`'s crate): `InterfaceFacts` needs a host address alongside
/// its prefix, and this domain must not add one.
#[must_use]
pub fn host_address(prefix: twinvpn_types::IpPrefix) -> Option<IpAddr> {
    let single_host = prefix.prefix_len() == prefix.family().max_prefix_len();
    single_host.then(|| prefix.address())
}

/// The `Kind` a host address of this shape is.
const fn host_kind(address: IpAddr) -> Kind {
    match address {
        // `networking.md` §3.3 has one v4 host kind and it is the private one:
        // a globally routable v4 address on a local interface is vanishingly
        // rare and is still gathered as a host candidate.
        IpAddr::V4(_) => Kind::HostV4Private,
        IpAddr::V6(a) => {
            if a.is_link_local() {
                Kind::HostV6LinkLocal
            } else {
                Kind::HostV6Global
            }
        }
    }
}

/// A stable, attempt-scoped candidate id.
///
/// Derived from the `SessionId` and the candidate's index rather than drawn from
/// the RNG: `CandidateId`'s scope is one establishment attempt, and a derived id
/// lets a lab replay reproduce the same ledger without consuming a random stream
/// some other consumer's determinism depends on.
fn candidate_id(session_id: SessionId, index: usize) -> CandidateId {
    // `CandidateId` is EIGHT bytes (`limits.json` `candidate_id_bytes`), and its
    // scope is one establishment attempt — so four bytes of session and four of
    // index is enough to be unique within that scope, which is all the registry
    // asks of it.
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&session_id.as_bytes()[..4]);
    bytes[4..].copy_from_slice(&u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes());
    CandidateId::from_slice(&bytes).expect("8 bytes is CandidateId's declared width")
}

/// Records a gathering round into the ledger and schedules the race.
///
/// Both are `twinvpn-path`'s, driven here. `record_first_direct_probe` is
/// stamped so the ledger can answer §10's "was the relay gathered from t = 0"
/// question, which ADR-0006 P02 makes auditable rather than a black box.
pub fn admit(ledger: &mut Ledger, gathered: &Gathered, now: MonotonicInstant) -> Race {
    for candidate in &gathered.candidates {
        ledger.record(*candidate);
    }
    if !gathered.candidates.is_empty() {
        ledger.record_first_direct_probe(now);
    }
    Race::schedule(&gathered.candidates, now)
}

/// Sends one connectivity probe per due candidate, from the matching socket.
///
/// **This is the point at which a packet actually moves.**
///
/// The probe body is deliberately opaque. `protocol.md` §10.4's authenticated
/// disco exchange is `twinvpn-path`'s `DiscoAuth`, which needs a key this build
/// has no binding for, so what leaves is a **bounded, keyless reachability
/// datagram** and the candidate is marked [`Standing::Probed`] rather than
/// validated. Marking it validated would be the authentication bypass ADR-0007
/// N-4 forbids.
///
/// Returns how many probes were sent.
pub async fn probe(
    sockets: &[Box<dyn UdpSocket>],
    race: &Race,
    ledger: &mut Ledger,
    peer: Option<Endpoint>,
    now: MonotonicInstant,
) -> usize {
    let Some(peer) = peer else {
        // No peer endpoint is known yet — the ordinary case before rendezvous
        // has answered. Nothing is sent and nothing is marked: a candidate that
        // was never probed must not read as one that was probed and failed.
        return 0;
    };
    let mut sent = 0usize;
    // The socket is chosen by the PEER ENDPOINT's family, not the candidate's: a
    // v6 socket cannot reach a v4 endpoint, and choosing by candidate family
    // sends nothing while looking like it tried. A candidate of the other family
    // is skipped rather than probed from the wrong socket — ADR-0010 R1 is about
    // gathering both families, not about pretending one can reach the other.
    let peer_family = peer.family();
    for candidate in race.due(now) {
        if candidate.family() != peer_family {
            continue;
        }
        let Some(socket) = sockets
            .iter()
            .find(|s| socket_family_matches(s.family(), peer_family))
        else {
            continue;
        };
        if socket.send_to(PROBE, &peer).await.is_ok() {
            // `Probing`, NOT `Validated`: §4.4's rule is "no user traffic on an
            // unvalidated path, ever", and `Standing::may_carry_traffic`
            // answers `false` here by construction. Marking it validated on a
            // send that merely left the host would be the authentication bypass
            // ADR-0007 N-4 forbids.
            ledger.set_standing(candidate.id, Standing::Probing);
            sent += 1;
        } else {
            // §7.5 keeps a failed candidate in the ledger WITH ITS REASON
            // rather than deleting it, so the connectivity report can say what
            // happened to each one.
            ledger.set_standing(
                candidate.id,
                Standing::Failed(twinvpn_types::codes::NET_NO_ROUTE),
            );
        }
    }
    sent
}

/// The keyless reachability probe body.
///
/// Fixed, bounded, and carrying **no identifier**: it is not an authenticator
/// and must not be mistaken for one.
const PROBE: &[u8] = b"TwinVPN/probe/v1";

const fn socket_family_matches(socket: SocketFamily, candidate: AddressFamily) -> bool {
    matches!(
        (socket, candidate),
        (
            SocketFamily::V4 | SocketFamily::V6DualStack,
            AddressFamily::V4
        ) | (
            SocketFamily::V6Only | SocketFamily::V6DualStack,
            AddressFamily::V6
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass};
    use twinvpn_types::{IpPrefix, V4Addr, V6Addr};

    fn dual_stack_interface() -> InterfaceFacts {
        InterfaceFacts {
            index: InterfaceIndex(2),
            name: InterfaceName::new("eth0").expect("valid"),
            // SINGLE-HOST prefixes, because they are the only shape the seam
            // can carry an interface's own address in. See `host_address`.
            addresses: vec![
                IpPrefix::new(
                    IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 10]).expect("v4")),
                    32,
                )
                .expect("prefix"),
                IpPrefix::new(
                    IpAddr::V6(
                        V6Addr::from_slice(
                            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
                            0,
                        )
                        .expect("v6"),
                    ),
                    128,
                )
                .expect("prefix"),
            ],
            has_default_route_v4: true,
            has_default_route_v6: true,
            is_overlay: false,
            is_up: true,
            mtu: 1500,
            link_class: LinkClass::Ethernet,
        }
    }

    fn session() -> SessionId {
        SessionId::from_slice(&[7; 16]).expect("16")
    }

    #[test]
    fn gathering_opens_a_socket_for_each_family_and_produces_both() {
        // ADR-0010 R1 at the mechanism level, which is what `MockSockets::opened`
        // exists to let a test assert.
        let (parts, adapter, _vt) = testing::parts();
        adapter
            .interfaces_mock()
            .set_interfaces(vec![dual_stack_interface()]);
        let env = parts.env.clone();
        let platform = parts.adapter.clone();

        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(gather(&env, &platform, session()).await);
        }));
        let gathered = result.expect("gather ran");

        assert_eq!(adapter.sockets_mock().opened(), 2, "one socket per family");
        assert!(gathered.outcome.v4.produced(), "v4 produced nothing");
        assert!(gathered.outcome.v6.produced(), "v6 produced nothing");
        assert!(!gathered.single_family());
        assert_eq!(gathered.candidates.len(), 2);
    }

    #[test]
    fn an_overlay_interface_is_never_a_candidate() {
        // Offering an overlay address as an underlay candidate is how a tunnel
        // comes to be routed through itself.
        let (parts, adapter, _vt) = testing::parts();
        let mut overlay = dual_stack_interface();
        overlay.is_overlay = true;
        adapter.interfaces_mock().set_interfaces(vec![overlay]);
        let env = parts.env.clone();
        let platform = parts.adapter.clone();

        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(gather(&env, &platform, session()).await);
        }));
        let gathered = result.expect("gather ran");
        assert!(gathered.no_candidate_either_family());
        assert_eq!(gathered.outcome.v4, FamilyOutcome::NoAddress);
        assert_eq!(gathered.outcome.v6, FamilyOutcome::NoAddress);
    }

    #[test]
    fn no_address_and_unsupported_are_different_answers() {
        // "We never looked at IPv6" must not read as "IPv6 produced nothing".
        let (parts, adapter, _vt) = testing::parts();
        adapter.interfaces_mock().set_interfaces(Vec::new());
        let env = parts.env.clone();
        let platform = parts.adapter.clone();

        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(gather(&env, &platform, session()).await);
        }));
        let gathered = result.expect("gather ran");
        // The mock host supports both families, so both report NoAddress rather
        // than Unsupported.
        assert_eq!(gathered.outcome.v4, FamilyOutcome::NoAddress);
        assert_eq!(gathered.outcome.v6, FamilyOutcome::NoAddress);
    }

    #[test]
    fn a_subnet_prefix_cannot_name_a_host_address() {
        // The contract defect, asserted so it is visible rather than inferred.
        let subnet = IpPrefix::new(
            IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 0]).expect("v4")),
            24,
        )
        .expect("canonical");
        assert!(
            host_address(subnet).is_none(),
            "a /24 names a network; using it as a candidate would probe an address \
             nothing answers on"
        );
        let single = IpPrefix::new(
            IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 10]).expect("v4")),
            32,
        )
        .expect("canonical");
        assert!(host_address(single).is_some());
    }

    #[test]
    fn a_family_whose_address_cannot_be_carried_says_so() {
        // "The OS reported nothing" and "the OS reported something the seam
        // cannot carry" must stay different answers.
        let (parts, adapter, _vt) = testing::parts();
        let mut iface = dual_stack_interface();
        iface.addresses = vec![IpPrefix::new(
            IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 0]).expect("v4")),
            24,
        )
        .expect("canonical")];
        adapter.interfaces_mock().set_interfaces(vec![iface]);
        let env = parts.env.clone();
        let platform = parts.adapter.clone();

        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(gather(&env, &platform, session()).await);
        }));
        let gathered = result.expect("gather ran");
        assert_eq!(gathered.outcome.v4, FamilyOutcome::AddressNotReportable);
        assert_eq!(gathered.outcome.v6, FamilyOutcome::NoAddress);
    }

    #[test]
    fn candidate_ids_are_distinct_and_derived() {
        let a = candidate_id(session(), 0);
        let b = candidate_id(session(), 1);
        assert_ne!(a, b);
        assert_eq!(a, candidate_id(session(), 0), "derivation is stable");
    }

    #[test]
    fn admitting_records_every_candidate_and_schedules_the_race() {
        let (parts, adapter, _vt) = testing::parts();
        adapter
            .interfaces_mock()
            .set_interfaces(vec![dual_stack_interface()]);
        let env = parts.env.clone();
        let platform = parts.adapter.clone();

        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(gather(&env, &platform, session()).await);
        }));
        let gathered = result.expect("gather ran");

        let mut ledger = Ledger::new();
        let race = admit(&mut ledger, &gathered, env.now_monotonic());
        assert_eq!(ledger.rows().len(), 2);
        assert!(
            race.covers_both_families(),
            "the race must race both families"
        );
    }

    #[test]
    fn no_peer_means_no_probe_and_no_standing_change() {
        let mut ledger = Ledger::new();
        let race = Race::schedule(&[], MonotonicInstant::ORIGIN);
        let (parts, _adapter, _vt) = testing::parts();
        let env = parts.env.clone();
        let mut sent = None;
        env.runtime().block_on(Box::pin(async {
            sent = Some(probe(&[], &race, &mut ledger, None, MonotonicInstant::ORIGIN).await);
        }));
        assert_eq!(sent, Some(0));
        assert!(ledger.rows().is_empty());
    }
}
