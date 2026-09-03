//! What a session is made of: the families, the phase expectations, and the two
//! records — an arrival and a phase boundary — that everything else is derived
//! from.
//!
//! These types are separated from the verdict logic in `lib.rs` deliberately.
//! They are the vocabulary the control API, the data plane and the report all
//! speak, and a reader checking what was recorded should not have to read the
//! adjudication to find it.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::PathKind;

/// Which egress path an observation arrived over.
///
/// This is read from the LISTENER, never from anything the client said. A
/// client that claims IPv6 while arriving on the IPv4 socket is recorded as
/// what it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
    Dns,
}

impl Family {
    pub const ALL: [Family; 3] = [Family::Ipv4, Family::Ipv6, Family::Dns];

    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
            Family::Dns => "dns",
        }
    }
}

/// What a phase asserts about egress while it is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Expectation {
    /// Traffic must arrive. The positive control.
    Observe,
    /// Traffic must not arrive. The criterion.
    Silence,
}

/// One beacon that actually arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub family: Family,
    /// The peer address the kernel reported. Not anything the client asserted.
    pub source: IpAddr,
    pub at_ms: u64,
    /// The sequence label the probe put in the beacon, carried through so a
    /// reader can line an observation up against the probe's own log.
    pub seq: String,
    /// Which path the PROBE believed this beacon was taking, from the
    /// `path_tag` label in a DNS query name. Evidence of intent only: the
    /// oracle derives the actual path from the arriving address and compares
    /// the two. `None` when the probe encoded no tag.
    #[serde(default)]
    pub path_tag: Option<PathKind>,
}

/// A phase boundary declared by the probe, plus the constraints it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub name: String,
    pub expectation: Expectation,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    /// Families that MUST be observed for an `Observe` phase to count as a
    /// positive control. Empty means "any one family will do".
    #[serde(default)]
    pub require_families: Vec<Family>,
    /// The name of an earlier phase whose source addresses this phase's must
    /// NOT overlap. Used for `BASELINE -> TUNNELLED`: if the tunnelled phase
    /// still egresses from the baseline address, nothing entered the tunnel.
    #[serde(default)]
    pub sources_disjoint_from: Option<String>,
    /// The name of an earlier phase whose source addresses this phase's must be
    /// a subset of. Used for `TUNNELLED -> RESTORED`: traffic must resume only
    /// through TwinVPN.
    #[serde(default)]
    pub sources_subset_of: Option<String>,
    /// Which egress path this phase was driving traffic over, when it was
    /// driving one. It is what makes `ipv4_identity_distinct` computable: the
    /// oracle collects the addresses that actually ARRIVED during protected and
    /// unprotected phases and checks the two sets do not overlap. The tag says
    /// which bucket to put an arrival in; it never says what the address was.
    #[serde(default, alias = "path_tag", deserialize_with = "deserialize_path")]
    pub path: Option<PathKind>,
}

/// The final answer for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Fail,
    /// The sequence did not establish enough to answer. NOT a pass, and
    /// `report.py` counts it against eligibility exactly as a failure does — an
    /// oracle that proved it could see nothing at all has not proved silence.
    Inconclusive,
}

/// `"p"`/`"protected"`, `"u"`/`"unprotected"`, and — the reason this is not
/// just `Option<PathKind>` — `"n"` for NO CLAIM, which the probe sends whenever
/// a phase was driven without a declared path.
///
/// `"n"` and `null` mean the same thing and must both be distinguishable from
/// `"p"` and `"u"`. Rejecting `"n"` would 400 the whole phase call, and a phase
/// that never opened is a phase whose observations land in the previous one —
/// which is how a leak ends up attributed to the wrong window.
pub fn deserialize_path<'de, D>(d: D) -> Result<Option<PathKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(d)?;
    match raw.as_deref() {
        None | Some("n") => Ok(None),
        Some(other) => PathKind::from_wire(other).map(Some).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "{other:?} is not a path: use \"p\"/\"protected\", \"u\"/\"unprotected\", \
                 or \"n\"/null for no claim"
            ))
        }),
    }
}
