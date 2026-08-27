//! Tier-1 bundle assembly and the R-23 connectivity report.
//!
//! **Authority:** [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.8 (the eight parts of the connectivity report), §11.9 (the remote-support
//! workflow), §11.4 (redaction), §11.10 (the privacy summary); ADR-0018 S-46.
//!
//! # What a bundle is, and what it deliberately is not
//!
//! §11.9 is a six-step workflow, and three of its properties are structural here
//! rather than procedural:
//!
//! - **There is no support-initiated pull.** Nothing in this module can be
//!   triggered by a remote message: [`Bundle::assemble`] is called by the core in
//!   response to a local command and takes its window as a parameter. §7 makes
//!   that a security requirement, not a workflow preference.
//! - **The user sees it before anyone else does** (O-10). The bundle is a value
//!   the caller renders; this module produces no transport and knows no
//!   destination.
//! - **It is signed by the shell, not here.** Signing needs the `DeviceKey`,
//!   which CB-5 keeps on the far side of the vtable. [`Bundle::signing_payload`]
//!   produces the exact bytes to sign and [`Bundle::attach_signature`] takes the
//!   result, so the core never holds the key and the bundle is still signed.
//!
//! # Expiry
//!
//! O-21 requires a stamped expiry. It is carried as an **absolute wall-clock
//! millisecond**, because a bundle outlives the process that made it and a
//! monotonic instant means nothing to the reader. The value is supplied by the
//! caller from `Env`'s three-state wall clock, so a device with no RTC produces a
//! bundle with **no** expiry rather than one dated 1970.

use core::fmt::Write as _;

use prost::Message as _;
use twinvpn_env::MonotonicInstant;
use twinvpn_types::{AddressFamily, PerFamily};

use crate::redact::Pseudonymizer;
use crate::resolve::{render, Binding, PlatformContext, Resolved};
use crate::ring::{Ledger, LedgerEntry, Record};
use crate::tier::Tier;

/// A Tier-1 diagnostic bundle, ready for the user to inspect and then share.
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    /// S-46, encoded. *"Every diagnostic bundle embeds it."*
    pub build_identity: Vec<u8>,
    /// The monotonic window the bundle covers, inclusive.
    pub window: (MonotonicInstant, MonotonicInstant),
    /// Encoded `SessionEvent` / `ErrorEnvelope` records, already redacted for
    /// [`Tier::Bundle`].
    pub records: Vec<Vec<u8>>,
    /// How many distinct values the per-bundle pseudonym mapping assigned. The
    /// mapping itself is **discarded** with the [`Pseudonymizer`]; only the count
    /// survives, so a reader can tell "one peer" from "forty" without being able
    /// to recover any of them.
    pub pseudonyms_assigned: usize,
    /// How many ledger entries the ring had dropped by assembly time.
    pub ledger_dropped: u64,
    /// Absolute expiry, in wall-clock milliseconds. `None` on a device whose
    /// wall clock is unset — an honest absence, never a zero.
    pub expires_at_ms: Option<u64>,
    /// The shell's signature over [`Bundle::signing_payload`], once attached.
    pub signature: Option<Vec<u8>>,
}

impl Bundle {
    /// Builds a bundle from a bounded window of the Tier-0 ledger.
    ///
    /// Every record is re-encoded **for [`Tier::Bundle`]**, which is what applies
    /// §11.4's pseudonymization. Nothing is copied verbatim out of the ledger:
    /// the ledger is Tier 0 and holds `SENSITIVE` values in the clear, and a
    /// bundle that shipped a Tier-0 record unchanged would be the privacy
    /// regression §11.1's tier table exists to prevent.
    #[must_use]
    pub fn assemble(
        ledger: &Ledger,
        window: (MonotonicInstant, MonotonicInstant),
        build_identity: Vec<u8>,
        expires_at_ms: Option<u64>,
        pseudonyms: &mut Pseudonymizer,
    ) -> Self {
        let mut records = Vec::new();
        for entry in ledger.window(window.0, window.1) {
            if let Some(bytes) = encode_for_bundle(entry, pseudonyms) {
                records.push(bytes);
            }
        }
        Self {
            build_identity,
            window,
            records,
            pseudonyms_assigned: pseudonyms.len(),
            ledger_dropped: ledger.dropped(),
            expires_at_ms,
            signature: None,
        }
    }

    /// The exact bytes the shell signs (§11.9 step 4).
    ///
    /// Domain-separated with a fixed prefix so a bundle signature can never be
    /// replayed as a signature over anything else this device signs.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.build_identity.len());
        out.extend_from_slice(b"TwinVPN/diag-bundle/v1");
        out.extend_from_slice(&self.window.0.as_micros().to_be_bytes());
        out.extend_from_slice(&self.window.1.as_micros().to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&(self.build_identity.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.build_identity);
        out.extend_from_slice(&(self.records.len() as u64).to_be_bytes());
        for r in &self.records {
            out.extend_from_slice(&(r.len() as u64).to_be_bytes());
            out.extend_from_slice(r);
        }
        out
    }

    /// Attaches a signature produced over [`Bundle::signing_payload`].
    pub fn attach_signature(&mut self, signature: Vec<u8>) {
        self.signature = Some(signature);
    }

    /// Whether this bundle has been signed.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

fn encode_for_bundle(entry: &LedgerEntry, pseudonyms: &mut Pseudonymizer) -> Option<Vec<u8>> {
    let emitter = crate::event::Emitter::new(twinvpn_types::Component::Diagnostics, Tier::Bundle);
    match &entry.record {
        Record::Diagnostic(d) => {
            let envelope = emitter.error_envelope(d, Some(pseudonyms));
            let mut buf = Vec::with_capacity(envelope.encoded_len());
            envelope.encode(&mut buf).ok()?;
            Some(buf)
        }
        // A transition and a session event are already in their frozen form and
        // were built by an emitter at the tier they were recorded at. Rebuilding
        // them here would need the typed originals, which the ledger deliberately
        // does not keep twice; instead the identifier fields are re-mapped so the
        // bundle carries tokens rather than identities.
        Record::Transition(t) => {
            let mut t = (**t).clone();
            t.session_id = remap(&t.session_id, "session", pseudonyms);
            t.path_id = remap(&t.path_id, "path", pseudonyms);
            if let Some(d) = t.diagnostic.as_mut() {
                d.correlation_id = Vec::new();
            }
            let mut buf = Vec::with_capacity(t.encoded_len());
            t.encode(&mut buf).ok()?;
            Some(buf)
        }
        Record::SessionEvent(e) => {
            let mut e = (**e).clone();
            e.session_id = remap(&e.session_id, "session", pseudonyms);
            if let Some(ctx) = e.context.as_mut() {
                ctx.tier = Tier::Bundle.to_wire();
                ctx.session_id = remap(&ctx.session_id, "session", pseudonyms);
                ctx.path_id = remap(&ctx.path_id, "path", pseudonyms);
                ctx.correlation_id = Vec::new();
                ctx.causation_id = Vec::new();
            }
            let mut buf = Vec::with_capacity(e.encoded_len());
            e.encode(&mut buf).ok()?;
            Some(buf)
        }
    }
}

fn remap(bytes: &[u8], kind: &'static str, pseudonyms: &mut Pseudonymizer) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(hex, "{b:02x}");
    }
    pseudonyms.token(kind, &hex).into_bytes()
}

// ---------------------------------------------------------------------------
// §11.8 — the connectivity report
// ---------------------------------------------------------------------------

/// One address family's half of §11.8 item 2.
///
/// Both halves are **always** present: `PerFamily<T>` makes forgetting the v6
/// half a compile error, which is ADR-0010 R1's rule applied to the report.
/// `InterfaceHealth`'s own comment says why — *"a report that shows v4 and omits
/// v6 cannot distinguish 'v6 is fine' from 'we never looked'"*.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FamilyReport {
    /// Whether a default route exists for this family.
    pub has_default_route: bool,
    /// Whether resolvers are configured for it.
    pub resolvers_configured: bool,
    /// Local addresses observed, as text the caller has already rendered from
    /// typed values.
    pub local_addresses: Vec<String>,
    /// The leak-canary verdict for this family (§11.6 rule 4), as a registered
    /// code or `None` where no probe has run.
    pub leak_probe: Option<String>,
}

/// The eight parts of §11.8, as data.
///
/// Rendering is the shell's (CB-4); this is the resolved, structured answer.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectivityReport {
    /// Part 1 — environment.
    pub os_name: Option<String>,
    /// Part 1 — OS version.
    pub os_version: Option<String>,
    /// Part 1 — whether the platform adapter is available.
    pub adapter_available: bool,
    /// Part 1 — detected conflicting virtual interfaces.
    pub conflicting_interfaces: Vec<String>,
    /// Part 1 — detected third-party filtering products (R-17, R-18).
    pub third_party_filters: Vec<String>,
    /// Part 2 — both families, side by side, always both.
    pub families: PerFamily<FamilyReport>,
    /// Part 3 — active resolvers and the effective DNS policy tag.
    pub dns_policy_mode: Option<String>,
    /// Part 4 — the candidate ledger: one row per candidate.
    pub candidates: Vec<CandidateRow>,
    /// Part 5 — the transport ladder's per-rung outcome.
    pub transport_ladder: Vec<LadderRung>,
    /// Part 6 — relays considered.
    pub relays: Vec<RelayRow>,
    /// Part 7 — the single code that best explains the failure.
    pub verdict: Option<String>,
    /// Part 8 — the enforcement snapshot, per family.
    pub enforcement: PerFamily<Option<String>>,
    /// How many catalogue lookups fell below the first rung while rendering, so
    /// copy and translation gaps are measurable (ADR-0019 §11.5).
    pub fallbacks_taken: usize,
}

/// One row of §11.8 item 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow {
    /// `host`, `server-reflexive`, `relay`.
    pub kind: String,
    /// Which family it was gathered for.
    pub family: AddressFamily,
    /// How long the attempt took.
    pub elapsed_ms: u64,
    /// The registered code for the failure, or `None` on success.
    pub reason_code: Option<String>,
}

/// One rung of §11.8 item 5's fallback ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderRung {
    /// `udp`, `udp-443`, `tcp-tls`, `https-shaped`.
    pub rung: String,
    /// Whether it succeeded.
    pub succeeded: bool,
    /// The registered code where it did not.
    pub reason_code: Option<String>,
}

/// One row of §11.8 item 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRow {
    /// The relay's region.
    pub region: String,
    /// Measured RTT, where one was measured.
    pub measured_rtt_ms: Option<u64>,
    /// Whether it was selected.
    pub selected: bool,
    /// The registered code where it was rejected.
    pub reason_code: Option<String>,
}

impl Default for ConnectivityReport {
    /// An empty report.
    ///
    /// Hand-written rather than derived because `PerFamily<T>` deliberately has
    /// no `Default`: a default per-family value is exactly the "we filled the v6
    /// half in for you" that ADR-0010 R1 refuses. Writing both halves out here
    /// is the point.
    fn default() -> Self {
        Self {
            os_name: None,
            os_version: None,
            adapter_available: false,
            conflicting_interfaces: Vec::new(),
            third_party_filters: Vec::new(),
            families: PerFamily::new(FamilyReport::default(), FamilyReport::default()),
            dns_policy_mode: None,
            candidates: Vec::new(),
            transport_ladder: Vec::new(),
            relays: Vec::new(),
            verdict: None,
            enforcement: PerFamily::new(None, None),
            fallbacks_taken: 0,
        }
    }
}

impl ConnectivityReport {
    /// Resolves part 7's verdict for one locale and platform.
    ///
    /// A pure call into [`render`], so the CLI and the GUI on one host produce
    /// the same sentence (ADR-0019 HP-3).
    #[must_use]
    pub fn resolve_verdict(
        &self,
        evidence: &[Binding],
        locale: &str,
        platform: &PlatformContext,
    ) -> Option<Resolved> {
        self.verdict
            .as_deref()
            .map(|code| render(code, evidence, locale, platform))
    }

    /// Whether both families were actually examined.
    ///
    /// §11.8 item 2's whole point: a report that looked at one family is
    /// misleading, and the difference has to be visible.
    #[must_use]
    pub fn both_families_examined(&self) -> bool {
        [AddressFamily::V4, AddressFamily::V6]
            .into_iter()
            .all(|f| self.families.get(f).leak_probe.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, IpAddr, SessionId, V4Addr};

    fn ledger_with_sensitive() -> Ledger {
        let mut l = Ledger::new(64);
        let d = Diagnostic::builder(codes::ROUTE_ADDRESS_COLLISION, Component::RoutingEngine)
            .evidence(
                "address",
                EvidenceValue::Address(IpAddr::V4(
                    V4Addr::from_slice(&[198, 51, 100, 9]).expect("v4"),
                )),
            )
            .build();
        l.push(
            MonotonicInstant::from_micros(10),
            Some(SessionId::from_slice(&[1u8; 16]).expect("16")),
            Record::Diagnostic(Box::new(d)),
        );
        l
    }

    #[test]
    fn a_bundle_never_carries_a_verbatim_address() {
        let l = ledger_with_sensitive();
        let mut p = Pseudonymizer::with_salt([1; 16]);
        let b = Bundle::assemble(
            &l,
            (
                MonotonicInstant::from_micros(0),
                MonotonicInstant::from_micros(100),
            ),
            Vec::new(),
            Some(1_700_000_000_000),
            &mut p,
        );
        assert_eq!(b.records.len(), 1);
        let raw = &b.records[0];
        // 198.51.100.9 as raw octets must not appear anywhere in the bundle.
        assert!(
            !raw.windows(4).any(|w| w == [198, 51, 100, 9]),
            "a SENSITIVE address reached a Tier-1 bundle verbatim"
        );
        assert_eq!(b.pseudonyms_assigned, 1);
    }

    #[test]
    fn the_bundle_embeds_the_build_identity_and_the_signature_covers_it() {
        let l = ledger_with_sensitive();
        let mut p = Pseudonymizer::with_salt([1; 16]);
        let mut b = Bundle::assemble(
            &l,
            (
                MonotonicInstant::from_micros(0),
                MonotonicInstant::from_micros(100),
            ),
            b"build-identity".to_vec(),
            None,
            &mut p,
        );
        let payload = b.signing_payload();
        assert!(payload.starts_with(b"TwinVPN/diag-bundle/v1"));
        assert!(payload
            .windows(b"build-identity".len())
            .any(|w| w == b"build-identity"));
        assert!(!b.is_signed());
        b.attach_signature(vec![7; 64]);
        assert!(b.is_signed());
    }

    #[test]
    fn a_device_with_no_wall_clock_gets_no_expiry_rather_than_1970() {
        let l = ledger_with_sensitive();
        let mut p = Pseudonymizer::with_salt([1; 16]);
        let b = Bundle::assemble(
            &l,
            (
                MonotonicInstant::from_micros(0),
                MonotonicInstant::from_micros(100),
            ),
            Vec::new(),
            None,
            &mut p,
        );
        assert_eq!(b.expires_at_ms, None);
    }

    #[test]
    fn the_report_knows_when_it_only_looked_at_one_family() {
        let mut r = ConnectivityReport::default();
        assert!(!r.both_families_examined());
        r.families.v4.leak_probe = Some("POLICY.LEAK.NONE".to_owned());
        assert!(!r.both_families_examined());
        r.families.v6.leak_probe = Some("POLICY.LEAK.NONE".to_owned());
        assert!(r.both_families_examined());
    }

    #[test]
    fn the_verdict_resolves_through_the_same_pure_renderer() {
        let r = ConnectivityReport {
            verdict: Some("NET.NO_ROUTE".to_owned()),
            ..ConnectivityReport::default()
        };
        let resolved = r
            .resolve_verdict(&[], "en", &PlatformContext::neutral())
            .expect("a verdict resolves");
        assert!(!resolved.summary.is_empty());
        assert!(resolved.registered);
    }
}
