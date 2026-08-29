//! F-6 — the hand-mirrored contract enums, mechanically linked to `contracts/gen`.
//!
//! **Authority:** ADR-0018 §11.7 (the dependency arrows), §11.8 CD-3 ("a
//! violation fails the merge"), `docs/architecture.md` §5.2 R-DET-1a ("a
//! requirement of this kind without a mechanical check is an aspiration"),
//! `ownership.md` §10.8 M-5 (a dev-dependency is not a shipped edge).
//!
//! # The finding
//!
//! Eleven enums in this crate restate a frozen `twinvpn.v1` enum by hand, each
//! with its own `= N` discriminants. Nothing connected them to
//! `contracts/gen/rust/src/twinvpn.v1.rs`, so renumbering a contract value would
//! have regenerated the bindings, left every mirror silently wrong, and been
//! caught — if at all — by a reviewer comparing two files by eye. W-20 is the
//! record of what that costs: three hand-written copies of `HealthState` grew
//! across two workspaces and **every one of them was missing a variant**.
//!
//! # Why a test rather than deleting the mirrors
//!
//! Deleting them is not available. ADR-0018 §11.7 puts `twinvpn-types` at the
//! root of the dependency arrows, and the generated bindings are not a crate of
//! their own: they are `include!`d by `twinvpn-schema`, which depends on
//! `twinvpn-types`. A normal dependency in the other direction is therefore not
//! merely a layering violation but a cycle Cargo will not build.
//!
//! A **dev**-dependency is the exception the workspace has already ruled on.
//! `xtask::manifest::Package::non_dev_dependencies` documents it: CD-I5 is
//! computed over non-dev edges precisely because "a dev-dependency is not a path
//! between the planes in any shipped artifact — it exists only while a test
//! binary is being built", and M-5 records that reading the undifferentiated
//! list made the architecture's own falsification tests unwritable. This file is
//! the same shape of test: it exists only to falsify, and it links no shipped
//! artifact to anything.
//!
//! # What fails, and when
//!
//! Three independent failure modes, deliberately:
//!
//! 1. **Renumbering** a contract value fails an `assert_eq!` on the
//!    discriminant, in both the raw-cast and the `to_wire`/`from_wire`
//!    directions.
//! 2. **Adding or removing** a contract variant fails to *compile*: each enum is
//!    matched exhaustively on the generated side and on the domain side, so a
//!    new variant leaves the match non-exhaustive and a deleted one leaves an
//!    arm naming a variant that no longer exists.
//! 3. **Adding a twelfth mirror** without linking it is caught by
//!    [`every_discriminant_bearing_enum_is_linked`], which reads this crate's own
//!    source. That is the F-6 recurrence guard: the finding is not "these eleven
//!    drifted", it is "nothing stopped them".
//!
//! The numeric sweep in each codec test is the belt to that braces: it asserts
//! the *accepted set* of wire values matches the contract's, so a mirror cannot
//! pass by having its variant list edited to agree with a mistake.

use std::collections::BTreeSet;

use twinvpn_schema::v1 as wire;
use twinvpn_types as domain;

/// The wire values swept by the codec tests.
///
/// Comfortably past the largest discriminant any frozen `twinvpn.v1` enum
/// carries (`Component::RELAY_SERVER` = 22) and into the negatives, because a
/// decoder is handed an `i32` and proto3 does not promise a non-negative one.
const SWEEP: std::ops::RangeInclusive<i32> = -4..=64;

/// Asserts one domain enum against its frozen `twinvpn.v1` counterpart.
///
/// `shared` are the variants both types carry, in wire order. `wire_only` are
/// the contract's variants this crate deliberately does not model — in practice
/// the proto3 zero value, for the types whose domain form refuses to hold it.
/// Splitting the two lists is what lets the `codec: yes` arm assert that
/// `from_wire` *rejects* the ones we chose not to model rather than quietly
/// mapping them somewhere.
macro_rules! mirrored_enum {
    (@discriminants $proto:literal, $name:ident, [$($v:ident),+], [$($w:ident),*]) => {
        $(
            assert_eq!(
                domain::$name::$v as i32,
                wire::$name::$v as i32,
                "{}: `{}` is {} in twinvpn-types but {} in contracts/gen. The frozen \
                 contract and its hand-written mirror disagree; regenerating the bindings \
                 does not fix the mirror.",
                $proto,
                stringify!($v),
                domain::$name::$v as i32,
                wire::$name::$v as i32,
            );
        )+

        // Exhaustive over the GENERATED enum. A variant added to the contract
        // leaves this match non-exhaustive; a variant removed leaves an arm
        // naming something that no longer exists. Either way the test crate
        // fails to compile, which is the point: an added variant is a change no
        // value comparison can see.
        let contract_side = |value: wire::$name| -> i32 {
            match value {
                $( wire::$name::$v => wire::$name::$v as i32, )+
                $( wire::$name::$w => wire::$name::$w as i32, )*
            }
        };

        // And exhaustive over the DOMAIN enum, so a variant invented here
        // without a contract change is equally a compile failure.
        let domain_side = |value: domain::$name| -> i32 {
            match value {
                $( domain::$name::$v => domain::$name::$v as i32, )+
            }
        };

        $(
            assert_eq!(
                contract_side(wire::$name::$v),
                domain_side(domain::$name::$v),
                "{}: `{}` does not round-trip", $proto, stringify!($v),
            );
        )+
        $(
            assert_eq!(
                contract_side(wire::$name::$w),
                wire::$name::$w as i32,
                "{}: `{}` is unaccounted for", $proto, stringify!($w),
            );
        )*
    };

    (
        $test:ident,
        proto: $proto:literal,
        name: $name:ident,
        shared: [$($v:ident),+ $(,)?],
        wire_only: [$($w:ident),* $(,)?],
        codec: no $(,)?
    ) => {
        #[test]
        fn $test() {
            mirrored_enum!(@discriminants $proto, $name, [$($v),+], [$($w),*]);
        }
    };

    (
        $test:ident,
        proto: $proto:literal,
        name: $name:ident,
        shared: [$($v:ident),+ $(,)?],
        wire_only: [$($w:ident),* $(,)?],
        codec: yes $(,)?
    ) => {
        #[test]
        fn $test() {
            mirrored_enum!(@discriminants $proto, $name, [$($v),+], [$($w),*]);

            $(
                assert_eq!(
                    domain::$name::$v.to_wire(),
                    wire::$name::$v as i32,
                    "{}: `{}::to_wire()` disagrees with contracts/gen",
                    $proto,
                    stringify!($v),
                );
                assert_eq!(
                    domain::$name::from_wire(wire::$name::$v as i32),
                    Ok(domain::$name::$v),
                    "{}: `from_wire({})` does not decode to `{}`",
                    $proto,
                    wire::$name::$v as i32,
                    stringify!($v),
                );
            )+
            $(
                assert!(
                    domain::$name::from_wire(wire::$name::$w as i32).is_err(),
                    "{}: `from_wire` accepted `{}`, a contract variant this crate \
                     deliberately does not model",
                    $proto,
                    stringify!($w),
                );
            )*

            // The accepted SET, not just the listed variants. This is what
            // catches a renumbering that someone "fixed" by editing the mirror
            // to match a mistake, and a contract variant added at a value the
            // mirror happens not to reject.
            let unmodelled: &[i32] = &[$(wire::$name::$w as i32),*];
            for value in SWEEP {
                let accepted = domain::$name::from_wire(value).is_ok();
                let in_contract =
                    wire::$name::try_from(value).is_ok() && !unmodelled.contains(&value);
                assert_eq!(
                    accepted,
                    in_contract,
                    "{}: `from_wire({})` {} but the frozen contract says it {}",
                    $proto,
                    value,
                    if accepted { "succeeds" } else { "fails" },
                    if in_contract { "should succeed" } else { "should fail" },
                );
            }
        }
    };
}

// ---------------------------------------------------------------------------
// connection.proto
// ---------------------------------------------------------------------------

mirrored_enum! {
    connection_state,
    proto: "twinvpn.v1.ConnectionState",
    name: ConnectionState,
    // `Unspecified` is SHARED, not wire-only: `docs/reliability.md` §4 has this
    // type decode the proto3 zero successfully and reject it separately in
    // `specified()`, so that "malformed enum value 47" and "a state was required
    // and none was supplied" stay two distinct reports. Moving it to `wire_only`
    // would assert the opposite, and the test would fail — correctly.
    shared: [
        Unspecified, Disconnected, Discovering, Negotiating, Connecting, LocalDirect,
        WanDirect, Relayed, Migrating, Degraded, Reconnecting, Blocked, Failed,
    ],
    wire_only: [],
    codec: yes,
}

mirrored_enum! {
    path_class,
    proto: "twinvpn.v1.PathClass",
    name: PathClass,
    shared: [LocalDirect, WanDirect, Relayed],
    wire_only: [Unspecified],
    codec: yes,
}

mirrored_enum! {
    traffic_disposition,
    proto: "twinvpn.v1.TrafficDisposition",
    name: TrafficDisposition,
    shared: [
        TunneledLocalDirect, TunneledWanDirect, TunneledRelay, TunneledDual, QueuedBounded,
        DroppedFailClosed, DroppedNoRoute, UnprotectedAnnounced,
    ],
    wire_only: [Unspecified],
    codec: yes,
}

mirrored_enum! {
    health_state,
    proto: "twinvpn.v1.HealthState",
    name: HealthState,
    // W-20: every hand-written copy of this enum omitted the proto3 zero and had
    // to invent an answer for "the sender did not say" — the convenient
    // invention being HEALTHY. `Unspecified` is modelled here for that reason,
    // so it belongs in `shared` and this test now says so mechanically.
    shared: [Unspecified, Healthy, Degraded, Unhealthy, Unknown],
    wire_only: [],
    codec: yes,
}

// ---------------------------------------------------------------------------
// errors.proto
// ---------------------------------------------------------------------------

mirrored_enum! {
    component,
    proto: "twinvpn.v1.Component",
    name: Component,
    shared: [
        TunnelEngine, RoutingEngine, PlatformAdapter, DeviceIdentity, Pairing,
        ControlPlaneClient, RendezvousClient, NatTraversal, RelayClient, RelaySelection,
        Presence, PolicyEngine, Dns, KillSwitch, LanDiscovery, ExitNode, Diagnostics,
        Store, Update, ManagementInterface, CoordinationService, RelayServer,
    ],
    wire_only: [Unspecified],
    codec: yes,
}

// The four registry-attribute enums carry no wire codec of their own: they are
// read from the frozen reason-code registry, never decoded from an untrusted
// `i32`. Their discriminants still have to match, because `ResolvedAttributes`
// is serialised with them.
mirrored_enum! {
    error_class,
    proto: "twinvpn.v1.ErrorClass",
    name: ErrorClass,
    shared: [Transient, Persistent, Policy, Fatal],
    wire_only: [Unspecified],
    codec: no,
}

mirrored_enum! {
    error_severity,
    proto: "twinvpn.v1.ErrorSeverity",
    name: ErrorSeverity,
    shared: [Info, Warn, Error, Critical],
    wire_only: [Unspecified],
    codec: no,
}

mirrored_enum! {
    remediation_class,
    proto: "twinvpn.v1.RemediationClass",
    name: RemediationClass,
    shared: [
        None, Wait, LocalAction, PeerAction, PolicyChange, UpdateRequired, NetworkChange,
        PermissionGrant, ReportDefect,
    ],
    wire_only: [Unspecified],
    codec: no,
}

mirrored_enum! {
    diagnostic_scope,
    proto: "twinvpn.v1.DiagnosticScope",
    name: DiagnosticScope,
    shared: [Session, Twinnet, Device, Path, Relay],
    wire_only: [Unspecified],
    codec: no,
}

// ---------------------------------------------------------------------------
// common.proto / identifiers.proto
// ---------------------------------------------------------------------------

mirrored_enum! {
    address_family,
    proto: "twinvpn.v1.AddressFamily",
    name: AddressFamily,
    shared: [V4, V6],
    wire_only: [Unspecified],
    codec: no,
}

mirrored_enum! {
    field_classification,
    proto: "twinvpn.v1.FieldClassification",
    name: FieldClassification,
    shared: [Public, Operational, Sensitive],
    wire_only: [Unspecified],
    codec: no,
}

// ---------------------------------------------------------------------------
// The recurrence guard
// ---------------------------------------------------------------------------

/// Every enum in this crate that assigns explicit discriminants is linked above.
///
/// F-6's substance is not that eleven mirrors drifted — none had — but that
/// nothing would have told anyone if they did, and nothing would tell anyone
/// about a twelfth. An explicit `= N` on a variant in this crate means exactly
/// one thing: the value is a wire value copied from `contracts/proto`. So the
/// rule is mechanical and needs no list to maintain — if a mirror exists, it is
/// named in a `mirrored_enum!` invocation in this file, or this test fails and
/// says which one is missing.
///
/// The scan is deliberately crude — a line-oriented pass, not a parse — because
/// the alternative is a `syn` dependency in a crate ADR-0018 §11.7 keeps to
/// three. Crude in the safe direction: it over-reports rather than under-reports,
/// and an over-report is fixed by writing the linkage the finding asks for.
#[test]
fn every_discriminant_bearing_enum_is_linked() {
    let linkage = include_str!("contract_enum_equivalence.rs");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut unlinked = BTreeSet::new();
    let mut found = BTreeSet::new();

    // Recursive, deliberately. `twinvpn-types/src` is flat today, so a
    // `read_dir` at the top level happened to be complete — but the whole point
    // of this check is to notice a mirror nobody thought to link, and the most
    // likely place for a future one is a new subdirectory. A guard that goes
    // blind exactly when the crate grows is a guard that fails when it is first
    // needed.
    let mut stack = vec![src.clone()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("twinvpn-types/src is readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }

    for path in files {
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).expect("a readable source file");
        let mut current: Option<&str> = None;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("pub enum ") {
                current = rest.split_whitespace().next();
                continue;
            }
            if line == "}" {
                current = None;
                continue;
            }
            let Some(name) = current else { continue };
            // `Variant = 7,` — the only shape a discriminant takes in this crate.
            let trimmed = line.trim();
            let Some((_, value)) = trimmed.split_once(" = ") else {
                continue;
            };
            if value
                .strip_suffix(',')
                .is_none_or(|v| v.parse::<i32>().is_err())
            {
                continue;
            }
            found.insert(name.to_owned());
            if !linkage.contains(&format!("name: {name},")) {
                unlinked.insert(name.to_owned());
            }
        }
    }

    assert!(
        unlinked.is_empty(),
        "F-6: {unlinked:?} assign explicit wire discriminants but are not linked to \
         contracts/gen. Add a `mirrored_enum!` invocation for each in \
         tests/contract_enum_equivalence.rs, or the mirror can be renumbered with \
         nothing to notice."
    );

    // The scan itself must not silently stop finding anything — an edit to the
    // source layout that broke the parser would otherwise turn this guard into a
    // test that always passes.
    assert_eq!(
        found.len(),
        11,
        "the scan found {} discriminant-bearing enums, not the 11 this file links: {found:?}. \
         Either a mirror was added or removed (update this count), or the scan stopped \
         working (fix the scan).",
        found.len(),
    );
}
