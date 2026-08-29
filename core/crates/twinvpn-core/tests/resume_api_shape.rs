//! **F-1B/F-1C.** The two downgrades the resumption seam used to permit are not
//! expressible, and RS-6's bound is still the rekey deadline.
//!
//! **Authority:** ADR-0001 §7.3.2 RS-1 (the resumption secrets come from the
//! completed handshake), RS-6 (bounded by the rekey schedule); §7.3 D2 (the
//! handshake hash is a *disclosed* confirmation value).
//!
//! # Why some of these read source instead of calling something
//!
//! The properties under test are **absences**: there is no public constructor,
//! there is no role parameter, there is no `&[u8]` secret. An absence has no
//! call to make. The compiler enforces two of them already — a
//! `SessionRuntime::arm_resumption(&[0u8; 32], Role::Initiator, …)` does not
//! build, and that is the real gate — but "does not build" is invisible to a
//! test run and silently stops being true the day someone adds an overload or a
//! `From<&[u8]>`.
//!
//! So the shape is asserted against the source, in the style
//! `tests/core_lite_profile.rs` uses for the `core-lite` manifest and
//! `twinvpn-session`'s `no_silent_failure.rs` uses for `reliability.md`. A
//! `trybuild` compile-fail suite would be the other way; it costs a
//! dev-dependency `twinvpn-core`'s manifest does not carry and this domain does
//! not own, and it would prove the same thing.
//!
//! These tests read the source of the **workspace as checked out**, so they fail
//! on the change rather than on a stale expectation.

const CARRIAGE: &str = include_str!("../src/execute/carriage.rs");
const DATAPATH: &str = include_str!("../src/datapath/mod.rs");
const ESTABLISHMENT: &str = include_str!("../src/execute/establishment.rs");
const HANDSHAKE: &str = include_str!("../src/execute/handshake.rs");
const BIND: &str = include_str!("../../twinvpn-tunnel/src/bind.rs");
const DRIVER: &str = include_str!("../src/resume/driver.rs");
const KEYS: &str = include_str!("../src/resume/keys.rs");
const RESUME_MOD: &str = include_str!("../src/resume/mod.rs");
const ESTABLISHED: &str = include_str!("../../twinvpn-crypto/src/established.rs");
const NOISE: &str = include_str!("../../twinvpn-crypto/src/noise.rs");

/// The body of the `fn <name>(` declaration in `source`, up to its closing `)`.
///
/// Crude on purpose: a parser would be a second implementation of Rust in a
/// test. What is needed is the parameter list, and the first `)` at depth zero
/// after the opening `(` is exactly that for every signature in these files.
fn signature_of(source: &str, name: &str) -> String {
    let needle = format!("fn {name}(");
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("`fn {name}(` is not declared in this source"))
        + needle.len();
    let mut depth = 1usize;
    let mut out = String::new();
    for ch in source[start..].chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return out;
                }
            }
            _ => {}
        }
        out.push(ch);
    }
    panic!("`fn {name}(` has no closing parenthesis");
}

// ---------------------------------------------------------------------------
// 11. The caller cannot substitute `local_role`
// ---------------------------------------------------------------------------

/// **11.** There is no public API path that sets the handshake role.
///
/// # The downgrade this forbids
///
/// `arm_resumption` used to take `local_role: Role` beside the secret. Arming
/// **both** peers with the same `Role` compiled, and silently collapsed the two
/// direction labels `ResumptionKeys::tag` derives under into one — which removes
/// the reflection defence entirely, while
/// `a_resume_reflected_back_at_its_sender_does_not_authenticate` continued to
/// pass, because that harness assigned the roles correctly by hand.
///
/// The role now travels **inside** `EstablishedHandshake`, which
/// `noise::Handshake::split` takes from the handshake it consumes. Four
/// absences make that airtight, and each is asserted:
#[test]
fn the_caller_cannot_independently_substitute_the_handshake_role() {
    // (a) `arm_resumption` and `ResumeState::armed` take no role at all.
    for (label, source, name) in [
        ("arm_resumption", DRIVER, "arm_resumption"),
        ("ResumeState::armed", RESUME_MOD, "armed"),
        ("ResumptionKeys::derive", KEYS, "derive"),
    ] {
        let signature = signature_of(source, name);
        assert!(
            !signature.contains("Role"),
            "{label} must not take a role from its caller; got ({signature})"
        );
    }

    // (b) `EstablishedHandshake` exposes no setter for it. `local_role` is
    //     `&self -> Role` and there is no `&mut self` method on the type at all,
    //     so there is nothing to set through.
    assert!(
        ESTABLISHED.contains("pub const fn local_role(&self) -> Role"),
        "the role must be readable off the authenticated result"
    );
    assert!(
        !ESTABLISHED.contains("&mut self"),
        "EstablishedHandshake exposes no mutating method, so no field of it can be replaced"
    );
    assert!(
        !ESTABLISHED.contains("set_local_role") && !ESTABLISHED.contains("with_role"),
        "no setter, under any of the names one would reach for"
    );

    // (c) The one place the role is chosen is `Handshake::split`, and it takes
    //     it from `self`.
    assert!(
        NOISE.contains("let role = self.role;"),
        "split must read the role off the handshake it consumes"
    );

    // (d) And that is the only mint. If a second one is ever added, this fails.
    let mints = ESTABLISHED.matches("pub(crate) const fn new(").count()
        + ESTABLISHED.matches("pub fn new(").count();
    assert_eq!(
        mints, 1,
        "EstablishedHandshake must have exactly one constructor, and it must not be public"
    );
    assert!(
        !ESTABLISHED.contains("pub fn new("),
        "EstablishedHandshake must have NO public constructor"
    );
    assert_eq!(
        NOISE.matches("EstablishedHandshake::new(").count(),
        1,
        "exactly one call site mints an EstablishedHandshake, and it is Handshake::split"
    );
}

// ---------------------------------------------------------------------------
// 12. Arbitrary byte slices cannot be a handshake secret
// ---------------------------------------------------------------------------

/// **12.** No arbitrary byte slice can be passed as a handshake secret.
///
/// # The downgrade this forbids
///
/// The parameter used to be `handshake_secret: &[u8]`. Passing
/// `Handshake::handshake_hash()` compiled — and ADR-0001 §7.3 D2 makes that
/// value a confirmation that "may be transmitted and compared in the clear",
/// which is exactly what a key must not be derived from.
///
/// It is now `&EstablishedHandshake`, and the secret inside it is a
/// `HandshakeSecret` with no constructor reachable from outside
/// `twinvpn-crypto`.
#[test]
fn arbitrary_byte_slices_cannot_be_passed_as_handshake_secrets() {
    // (a) The three functions on the derivation path take no byte slice.
    for (label, source, name) in [
        ("arm_resumption", DRIVER, "arm_resumption"),
        ("ResumeState::armed", RESUME_MOD, "armed"),
        ("ResumptionKeys::derive", KEYS, "derive"),
    ] {
        let signature = signature_of(source, name);
        assert!(
            !signature.contains("&[u8]") && !signature.contains("Vec<u8>"),
            "{label} must not accept raw secret material; got ({signature})"
        );
        assert!(
            signature.contains("EstablishedHandshake"),
            "{label} must take the authenticated handshake result; got ({signature})"
        );
    }

    // (b) `HandshakeSecret` can be read but not written: `expose` exists,
    //     nothing that takes bytes does.
    assert!(
        ESTABLISHED.contains("pub fn expose(&self) -> &[u8]"),
        "a consumer must be able to key a KDF from the secret"
    );
    for forbidden in [
        "pub fn new(",
        "pub fn from_bytes",
        "pub fn from_slice",
        "impl From<&[u8]> for HandshakeSecret",
        "pub fn adopt",
    ] {
        assert!(
            !ESTABLISHED.contains(forbidden),
            "`{forbidden}` would re-open the inbound direction this type closes"
        );
    }

    // (c) The only way in is `extract`, it is crate-private, and its inputs are
    //     two fixed-width arrays rather than a slice a caller could shape.
    let extract = signature_of(ESTABLISHED, "extract");
    assert!(
        extract.contains("&[u8; 32]") && !extract.contains("&[u8]"),
        "extract takes Noise's two 32-byte split outputs and nothing else; got ({extract})"
    );
    assert!(
        ESTABLISHED.contains("pub(crate) fn extract("),
        "extract must not be reachable from outside twinvpn-crypto"
    );

    // (d) The derivation is the one the ADR and the module docs name.
    assert!(
        ESTABLISHED.contains(r#"pub const RESUMPTION_SALT: &[u8] = b"TwinVPN/resumption/v1";"#),
        "the HKDF-Extract salt is fixed and versioned"
    );
}

// ---------------------------------------------------------------------------
// F-1A. The production establishment path arms resumption
// ---------------------------------------------------------------------------

/// **F-1A.** `arm_resumption` has a real, non-test caller, and it is on the path
/// a completed production handshake takes.
///
/// # Why this is asserted against the source rather than driven
///
/// The runtime chain is
/// `Core::submit -> execute::connect -> establishment::carry -> direct ->
/// handshake::drive -> NoiseBinding -> Handshake::split`, and the honest
/// statement is that **a test in this crate cannot drive it end to end today**:
/// `direct` refuses with `AUTH.KEY_UNAVAILABLE` unless the `SessionEntry`
/// carries a `TunnelKeying`, and `Core` exposes no public way to install one
/// (`Core::sessions` is `pub(crate)`). `tests/falsification.rs` records the same
/// limit from the other side — its `Session` reaches a steady state without a
/// handshake for exactly that reason.
///
/// So the link that *can* be checked is checked: the call exists, it is in a
/// production function, and it is not inside a `#[cfg(test)]` module. The
/// cryptographic half of the chain **is** driven for real, by
/// `tests/crypto_carriage.rs`, through the same `NoiseBinding` this path uses.
#[test]
fn the_production_establishment_path_arms_resumption() {
    // (a) `establishment.rs` calls it, and `establishment.rs` has no test module
    //     at all, so the call cannot be a test's.
    assert!(
        ESTABLISHMENT.contains("arm_resumption("),
        "the production establishment path must arm resumption"
    );
    assert!(
        !ESTABLISHMENT.contains("#[cfg(test)]"),
        "establishment.rs carries no test module, so its arm_resumption call is production code"
    );

    // (b) It arms from the handshake's own result, not from anything a caller
    //     could have shaped.
    assert!(
        ESTABLISHMENT.contains("&handshaken.established"),
        "arming must use the EstablishedHandshake the handshake produced"
    );

    // (c) `Handshaken` carries that result out of `drive`, and `drive` takes it
    //     from the production binding rather than constructing one.
    assert!(
        HANDSHAKE.contains("pub established: EstablishedHandshake"),
        "the completed handshake must carry its authenticated result to the caller"
    );
    assert!(
        HANDSHAKE.contains("binding.take_established()"),
        "drive must take the result out of NoiseBinding, once"
    );

    // (d) `NoiseBinding::finish` produces it by splitting the real handshake,
    //     and hands it out by MOVING it — a second caller must get `None`, so
    //     RS-1's "for the life of the Session" has one owner and not two.
    assert!(
        BIND.contains("handshake.split()"),
        "the production binding must mint the result from the handshake it consumes"
    );
    assert!(
        BIND.contains("self.established.take()"),
        "take_established must move the material out rather than clone or lend it"
    );
    assert!(
        !BIND.contains("self.established.clone()") && !BIND.contains("established.as_ref()"),
        "no path may hand out a second copy of the resumption material"
    );
}

// ---------------------------------------------------------------------------
// F-1A. The inbound consumer is reachable from a socket
// ---------------------------------------------------------------------------

/// **F-1A, consumer half.** `resume_on_wire` has a non-test caller, and a
/// datagram arriving on the shared socket can reach it.
///
/// # The defect this closes
///
/// `accept_resume_offer` read as wired only because `resume_on_wire` called it
/// inside `src/`; nothing called `resume_on_wire`, so the entire inbound
/// consumer was dead in production. Worse, it was **unreachable**: a
/// `ResumeSession` is not a `DataHeader` frame, so the inbound pump refused one
/// as malformed before it could be routed anywhere.
///
/// Both halves are asserted, because either alone is still a dead path.
#[test]
fn an_inbound_resume_datagram_can_reach_the_state_machine() {
    // (a) The pump recognises the frame and sets it aside.
    assert!(
        DATAPATH.contains("return self.divert_resume("),
        "the inbound step must demux a resume before the data path sees it"
    );
    assert!(
        DATAPATH.contains("pub fn take_resume(&self)"),
        "the session layer must be able to collect what the pump set aside"
    );

    // (b) The layer that owns the `Core` collects it and dispatches.
    assert!(
        CARRIAGE.contains("resume_on_wire("),
        "the production carriage must hand an inbound resume to the state machine"
    );
    assert!(
        CARRIAGE.contains("pump.take_resume()"),
        "and it must take it from the pump rather than read the socket itself"
    );
    assert!(
        !CARRIAGE.contains("#[cfg(test)]"),
        "carriage.rs carries no test module, so its resume_on_wire call is production code"
    );

    // (c) The dispatch is narrowed to the one state §4.5 T35 acts on, so a
    //     forged datagram cannot provoke a state change on a healthy `Session`.
    assert!(
        CARRIAGE.contains("SessionState::Reconnecting { parked: true }"),
        "a resume must be dropped outside the state that has something to do with it"
    );

    // (d) Nothing on the divert path opens a record under the transport keys,
    //     so a forged resume cannot advance the L-DATA replay window. The
    //     runtime proof is `crypto_carriage.rs`; this is the shape of it.
    let divert = signature_of(DATAPATH, "divert_resume");
    assert!(
        divert.contains("&self") && divert.contains("datagram: &[u8]"),
        "divert_resume takes the datagram and the pump, and nothing keyed; got ({divert})"
    );
}

// ---------------------------------------------------------------------------
// 13. RS-6 is still the rekey deadline
// ---------------------------------------------------------------------------

/// **13.** `RESUMPTION_LIFETIME` is still `REKEY_AFTER_TIME`, not
/// `REJECT_AFTER_TIME`.
///
/// # This is a companion to the existing regression test, not a replacement
///
/// `tests/resume_lifecycle.rs::the_resumption_bound_is_the_rekey_deadline_and_not_the_key_death_deadline`
/// is untouched and still fails if the constant is reverted — it compares the
/// two `twinvpn-crypto` durations at runtime and drives a real expiry across the
/// boundary. What it *cannot* catch is a change that moves the constant **and**
/// rewrites that test to match, which is the ordinary shape of a regression
/// reintroduced by someone who believed the test was wrong.
///
/// This one asserts the same rule a second way — off the source of the
/// declaration, and off the ADR text quoted beside it — so reverting RS-6 takes
/// two edits in two files that do not look like each other.
///
/// **RS-6:** "Resumption provides no new forward secrecy. It is bounded by the
/// rekey schedule of §7.2: a `Tunnel` that would rekey MUST rekey rather than
/// resume indefinitely." A `Tunnel` between `REKEY_AFTER_TIME` (120 s, "the
/// initiator begins a new handshake") and `REJECT_AFTER_TIME` (180 s, where the
/// keys are zeroed) is *precisely* one that would rekey.
#[test]
fn rs6_binds_resumption_to_the_rekey_deadline_and_not_the_key_death_deadline() {
    use core::time::Duration;
    use twinvpn_core::resume::RESUMPTION_LIFETIME;
    use twinvpn_crypto::noise::{REJECT_AFTER_TIME, REKEY_AFTER_TIME};

    // The declaration names the right constant, in the source.
    assert!(
        RESUME_MOD.contains("pub const RESUMPTION_LIFETIME: Duration = REKEY_AFTER_TIME;"),
        "RESUMPTION_LIFETIME must be declared as REKEY_AFTER_TIME"
    );
    assert!(
        !RESUME_MOD.contains("RESUMPTION_LIFETIME: Duration = REJECT_AFTER_TIME"),
        "the key-death deadline admits a resume across the whole rekey window"
    );

    // And the values agree at runtime, with the ADR's own numbers spelled out so
    // a change to either constant is visible here too.
    assert_eq!(RESUMPTION_LIFETIME, REKEY_AFTER_TIME);
    assert_eq!(REKEY_AFTER_TIME, Duration::from_secs(120));
    assert_eq!(REJECT_AFTER_TIME, Duration::from_secs(180));
    assert!(
        RESUMPTION_LIFETIME < REJECT_AFTER_TIME,
        "RS-6's bound is strictly inside the interval where the keys are still alive"
    );
}
