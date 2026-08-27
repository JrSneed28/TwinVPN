//! Route conflicts: P1–P6, detected **before** anything is installed, and never
//! resolved silently.
//!
//! **Authority:** ADR-0010 §11.6 (P1–P6), R7; `docs/networking.md` §7.4;
//! ADR-0008 N-8 ("conflict-checked against pre-existing system state BEFORE any
//! mutation"); I6.
//!
//! # Silent resolution is forbidden
//!
//! P5: "Conflicts are always surfaced (`ROUTE.CONFLICT_UNRESOLVED`) naming both
//! prefixes, both sources, and the winner." So [`Conflict`] carries all three,
//! [`resolve`] returns every conflict it found alongside the program, and there
//! is no code path that drops one.

use twinvpn_types::{DeviceId, IpPrefix};

/// Where a candidate prefix came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The TwinNet's own overlay prefixes.
    Overlay,
    /// A subnet advertised by a `LANGateway`.
    LanGateway(DeviceId),
    /// A default route offered by a selected `ExitNode`.
    ExitNode(DeviceId),
    /// An on-link physical LAN prefix the host already has.
    OnLinkPhysical,
    /// A route the user pinned explicitly (P3).
    UserPin,
}

impl Source {
    /// The advertising device, where there is one.
    #[must_use]
    pub const fn device(self) -> Option<DeviceId> {
        match self {
            Source::LanGateway(d) | Source::ExitNode(d) => Some(d),
            _ => None,
        }
    }
}

/// One prefix competing to be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The prefix, canonical.
    pub prefix: IpPrefix,
    /// Where it came from.
    pub source: Source,
    /// P4's tie-break input: the measured path score, higher is better.
    pub measured_score: i32,
    /// P4's second tie-break: the contract metric, lower is preferred.
    pub metric: u32,
}

/// A conflict, with everything P5 requires it to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conflict {
    /// One of the two competing prefixes.
    pub left: Candidate,
    /// The other.
    pub right: Candidate,
    /// Which one was installed.
    pub winner: Candidate,
}

/// The result of conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The prefixes that will be installed, longest-prefix first.
    pub installed: Vec<Candidate>,
    /// Every conflict found. **Never empty when one occurred**, and every entry
    /// must be surfaced as `ROUTE.CONFLICT_UNRESOLVED` or
    /// `ROUTE.PREFIX_CONFLICT`.
    pub conflicts: Vec<Conflict>,
}

/// Applies P1–P4 to a candidate set and reports every conflict.
///
/// | # | Rule |
/// |---|---|
/// | P1 | Longest prefix match governs; identical prefixes are never installed twice. |
/// | P2 | An on-link physical LAN prefix beats an advertised overlay route of equal or shorter length, **by default**. |
/// | P3 | An explicit per-prefix user pin overrides P2 in either direction. |
/// | P4 | Between equal-length advertised routes from different gateways, better measured path wins; ties break on contract priority. |
/// | P5 | Conflicts are always surfaced. |
#[must_use]
pub fn resolve(candidates: &[Candidate]) -> Resolution {
    let mut installed: Vec<Candidate> = Vec::new();
    let mut conflicts: Vec<Conflict> = Vec::new();

    for cand in candidates {
        // P1: identical prefixes are never installed twice.
        if let Some(pos) = installed
            .iter()
            .position(|c| c.prefix == cand.prefix)
        {
            let existing = installed[pos];
            let winner = pick(existing, *cand);
            conflicts.push(Conflict {
                left: existing,
                right: *cand,
                winner,
            });
            installed[pos] = winner;
            continue;
        }

        // An overlap that is not an exact match is still a conflict worth
        // naming — §7.4's "two homes on 192.168.1.0/24" is exactly this shape —
        // but longest-prefix match resolves the forwarding question, so both are
        // installed and the conflict is reported.
        if let Some(other) = installed
            .iter()
            .copied()
            .find(|c| overlaps(c.prefix, cand.prefix))
        {
            conflicts.push(Conflict {
                left: other,
                right: *cand,
                winner: pick(other, *cand),
            });
        }
        installed.push(*cand);
    }

    // Longest prefix first, so the installed order reads the way forwarding
    // resolves it.
    installed.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    Resolution {
        installed,
        conflicts,
    }
}

/// P2, P3, P4 applied to one pair.
fn pick(a: Candidate, b: Candidate) -> Candidate {
    // P3 first: a user pin overrides P2 in either direction.
    match (a.source, b.source) {
        (Source::UserPin, _) => return a,
        (_, Source::UserPin) => return b,
        _ => {}
    }
    // P2: an on-link physical prefix beats an advertised overlay route of equal
    // or shorter length. Breaking the user's own printer to reach a remote one
    // is the wrong default.
    match (a.source, b.source) {
        (Source::OnLinkPhysical, _) if a.prefix.prefix_len() >= b.prefix.prefix_len() => return a,
        (_, Source::OnLinkPhysical) if b.prefix.prefix_len() >= a.prefix.prefix_len() => return b,
        _ => {}
    }
    // P1: longest prefix.
    if a.prefix.prefix_len() != b.prefix.prefix_len() {
        return if a.prefix.prefix_len() > b.prefix.prefix_len() {
            a
        } else {
            b
        };
    }
    // P4: better measured path, then contract metric (lower preferred), then a
    // stable tie-break on the advertiser so the outcome is reproducible rather
    // than dependent on iteration order.
    if a.measured_score != b.measured_score {
        return if a.measured_score > b.measured_score { a } else { b };
    }
    if a.metric != b.metric {
        return if a.metric < b.metric { a } else { b };
    }
    match (a.source.device(), b.source.device()) {
        (Some(da), Some(db)) if da.to_array() > db.to_array() => b,
        _ => a,
    }
}

/// Whether two prefixes of the same family overlap.
#[must_use]
pub fn overlaps(a: IpPrefix, b: IpPrefix) -> bool {
    if a.family() != b.family() {
        return false;
    }
    a.contains(b.address()) || b.contains(a.address())
}

/// P6: `0.0.0.0/0` and `::/0` may be advertised only by a **selected**
/// `ExitNode`; otherwise `ROUTE.SCOPE_VIOLATION`.
#[must_use]
pub fn default_route_permitted(cand: Candidate, selected_exit_node: Option<DeviceId>) -> bool {
    if cand.prefix.prefix_len() != 0 {
        return true;
    }
    matches!(
        (cand.source, selected_exit_node),
        (Source::ExitNode(d), Some(sel)) if d == sel
    )
}

/// `networking.md` §7.5: does the underlay itself use our IPv4 overlay space?
///
/// A client behind carrier CGNAT assigned from `100.64.0.0/10` could have a
/// `/32` in the overlay shadow the underlay's next hop. Detected at bring-up by
/// comparing on-link underlay prefixes and the underlay default gateway against
/// the assigned `TwinNet` `/22`(s) — never resolved by clobbering.
#[must_use]
pub fn cgnat_space_collision(twinnet_v4_blocks: &[IpPrefix], underlay_on_link: &[IpPrefix]) -> bool {
    twinnet_v4_blocks
        .iter()
        .any(|t| underlay_on_link.iter().any(|u| overlaps(*t, *u)))
}
