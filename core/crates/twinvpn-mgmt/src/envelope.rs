//! **The MI envelope and its framing.** One contract, three carriages.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.3 (the envelope and the 1 MiB cap), §11.3.1 (MI-14, MI-15), §11.3.2
//! (MI-16), §11.7 (`Hello`/`HelloAck`, and the mismatch table), MI-2, MI-3,
//! MI-6, MI-18, MI-19, MI-20, MI-21; ADR-0018 §11.16 (b), F-8;
//! `contracts/docs/phase1-conflicts.md` OQ-2; `ownership.md` §9.6 **X-4**.
//!
//! # Why this is here and not in three shells
//!
//! X-4, reported by `desktop-macos` and confirmed by the integration lead:
//!
//! > **The MI envelope is declared three times.** It is in no contract, so each
//! > shell declares its own — MI-20's *"one contract, two carriages, never two
//! > contracts"* failing one level up, with three carriages.
//!
//! And they had already drifted. `shells/linux` and `shells/windows` carried
//! byte-identical copies; `shells/macos` carried a **third dialect**: a
//! `Diagnostic` with four fields the other two lacked and one they had, a
//! `Compacted` that had lost `up_to_seq` — MI-19's ordered gap boundary — and a
//! `FrameError` with different variants and a different return type. A client
//! built against one shell's `Reject` would have failed to parse another's,
//! from the same build of the same product.
//!
//! MI-20 is the rule that settles where it belongs: *"the MI catalogue is
//! **derived from the core's command/event set**, not specified beside it"*, and
//! ADR-0018 §11.7 puts this crate above the composition root, so this is the one
//! place all three carriages can share. The **transport** stays with each shell —
//! the Unix socket, the named pipe, XPC — because that genuinely differs.
//!
//! # A reported gap that this move does not close
//!
//! ADR-0017 §11.3 specifies the envelope as **B1 protobuf** and prints its
//! `.proto`. That message appears **nowhere in `contracts/`** — there is no
//! `mgmt.proto`, and `contracts/docs/phase1-conflicts.md` OQ-2 deliberately
//! excluded an MI transport schema from Phase 2 so the MI could not acquire an
//! independent vocabulary.
//!
//! The exclusion achieved its purpose — the vocabulary here *is* the core's —
//! and it left the **carriage** unspecified in the frozen set. This module
//! carries §11.3's field list over **B5 JSON**, which ADR-0017 §11.6 already
//! names as the format the CLI renders in, with a 4-byte big-endian length
//! prefix — the same shape as §11.2's own `SOCK_STREAM` fallback. Moving it here
//! makes it *one* unspecified carriage instead of three, which is strictly
//! better and is not the same as specifying it. The field names below are
//! ADR-0017 §11.3's verbatim, so a later `mgmt.proto` is a re-encoding rather
//! than a redesign.
//!
//! # One vocabulary, carried — never redeclared
//!
//! Every operation on this wire is named by [`crate::CoreCommand::name`], and
//! the four transport-layer operations are [`crate::TransportOp`]'s. **There is
//! no operation enum in this file.**
//!
//! # Framing, and where it stops
//!
//! A 4-byte big-endian length prefix, and a 1 MiB cap **enforced before parse**.
//! [`declared_length`] checks the prefix before a byte is reserved, which is
//! `ownership.md` §6 rule 9. Everything above that line — accepting a
//! connection, reading bytes, deciding what a clean close means — is the
//! transport's, and each shell keeps its own: `SOCK_STREAM` on Linux, a
//! message-mode named pipe on Windows, `AF_UNIX` (and later XPC) on macOS.

use serde::{Deserialize, Serialize};
use twinvpn_types::ReasonCode;

/// §11.3's cap, enforced **before parse**.
///
/// > Max envelope 1 MiB, enforced before parse (`MGMT.PAYLOAD_TOO_LARGE`).
///
/// `ownership.md` §6 rule 9: a declared length is validated before any
/// allocation proportional to it. [`decode_frame`] checks the prefix against
/// this constant before it reserves a byte.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// The length prefix's width.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// The MI version this build speaks. ADR-0017 §11.7's V-4 axis — its **own**
/// `uint32` number space, deliberately not `ProtocolEpoch`.
pub const MI_VERSION: u32 = 1;

/// The oldest MI version this build serves.
///
/// MI-5 requires N and N-1. At `MI_VERSION == 1` there is no N-1, so the window
/// is `1..=1` and will widen with the second version rather than being
/// pre-declared wider than it is.
pub const MI_VERSION_MIN: u32 = 1;

/// One MI message. ADR-0017 §11.3's field list, verbatim.
///
/// `request_id`, `correlation_id` and `idempotency_key` are byte strings in the
/// ADR and are carried here as byte arrays: JSON has no byte type, and hex would
/// add an encoding the ADR does not name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgmtEnvelope {
    /// Fixed for the life of a connection (§11.7).
    pub mi_version: u32,
    /// Unique **per emission**. MI-2: a retry reuses `idempotency_key`, never
    /// this.
    pub request_id: Vec<u8>,
    /// The `request_id` this responds to; empty on a pushed event.
    #[serde(default)]
    pub correlation_id: Vec<u8>,
    /// Per-connection, strictly increasing, **events only**.
    #[serde(default)]
    pub seq: u64,
    /// ADR-0008's `CEREMONY` key, where the catalogue requires one.
    #[serde(default)]
    pub idempotency_key: Vec<u8>,
    /// **MI-16.** Agent-stamped, on the **boot-time monotonic** clock
    /// (`CLOCK_BOOTTIME`, ADR-0022 LC-8's `ElapsedClock`).
    ///
    /// > A contiguous `seq` proves **no event was lost**; it does not prove
    /// > **any event was recent**.
    #[serde(default)]
    pub as_of_ms: u64,
    /// The body.
    pub body: Body,
}

/// §11.3's `oneof body`.
///
/// **MI-3: the agent MUST NOT initiate a request.** There is no `Request`
/// variant the agent can send, because the direction is enforced by
/// [`Body::is_client_originated`] and asserted in this module's tests — no
/// daemon→client RPC exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    /// Client → agent, first message.
    Hello(Hello),
    /// Agent → client.
    HelloAck(Box<HelloAck>),
    /// Agent → client, then close. **Never a silent close**: §11.7's mismatch
    /// table makes a silent close indistinguishable from "the agent is not
    /// running", which sends the user to reinstall rather than to update.
    Reject(Diagnostic),
    /// Client → agent.
    Request(Request),
    /// Agent → client.
    Response(Response),
    /// Agent → client, unsolicited.
    Event(Event),
    /// Agent → client: an **ordered** marker announcing a delivery gap (MI-19).
    Compacted(Compacted),
    /// Either direction.
    Goodbye,
}

impl Body {
    /// Whether this body may travel client → agent.
    ///
    /// MI-3's direction rule, as a function rather than a convention.
    #[must_use]
    pub const fn is_client_originated(&self) -> bool {
        matches!(self, Body::Hello(_) | Body::Request(_) | Body::Goodbye)
    }
}

/// §11.7's `Hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The lowest MI version the client can speak.
    pub mi_version_min: u32,
    /// The highest.
    pub mi_version_max: u32,
    /// `"cli"`, `"gui"`, `"automation"`. Diagnostic only.
    pub client_kind: String,
    /// The client's own version string.
    pub client_version: String,
    /// **MI-S1: a reduction request only.** The granted set is
    /// `policy(principal) ∩ requested`; a client can drop capabilities it does
    /// not need and can never add one.
    pub requested_scopes: Vec<String>,
    /// Topics to subscribe to.
    #[serde(default)]
    pub subscribe_topics: Vec<String>,
}

/// §11.7's `HelloAck`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// The selected version: `min(client.max, agent.max)`, fixed for the life of
    /// the connection.
    pub mi_version: u32,
    /// The agent's own version.
    pub agent_version: String,
    /// The build profile. §11.7: "**Build profile is not version.**"
    pub build_profile: String,
    /// `policy(principal) ∩ requested`.
    pub granted_scopes: Vec<String>,
    /// What was asked for and withheld. A status-only client should still work,
    /// so a scope it does not hold is **withheld and named**, never a rejection.
    pub withheld_scopes: Vec<String>,
    /// §11.7: "**The catalogue, not the version, is the capability contract.**"
    ///
    /// From [`crate::catalogue_digest`], so it cannot disagree with the
    /// catalogue the agent would actually serve.
    pub catalogue_digest: String,
    /// Where the event stream stands.
    pub event_cursor: u64,
    /// The `ProtocolEpoch` range, as `[min, max]`.
    pub protocol_epoch_range: [u32; 2],
    /// **MI-C3.** Supplied by the agent and used by every client **verbatim**:
    /// a CLI and a GUI that each derived their own could disagree on one host
    /// and render different next actions for the same diagnostic.
    pub platform_ctx: PlatformCtx,
}

/// The `{platform, os_version}` MI-C3 carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCtx {
    /// e.g. `"linux"`.
    pub platform: String,
    /// e.g. `"6.18.33"`.
    pub os_version: String,
}

/// §11.3's `Request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The operation's **wire name** — a `CoreCommand` or a `TransportOp` name.
    /// A string rather than an enum because the catalogue is the contract and an
    /// unknown name must produce a typed `MGMT.OP_UNKNOWN` rather than a parse
    /// failure (§11.7: "Never a parse error, never a hang, never a generic
    /// failure").
    pub operation: String,
    /// Encoded parameters (ADR-0018 F-8: structured data crosses as bytes).
    #[serde(default)]
    pub params: Vec<u8>,
    /// The `if_version` precondition, where the catalogue requires one.
    #[serde(default)]
    pub if_version: Option<u64>,
}

/// §11.3's `Response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// The encoded result.
    #[serde(default)]
    pub result: Vec<u8>,
    /// **MI-15: codes and typed evidence, never rendered human text.**
    #[serde(default)]
    pub diagnostic: Option<Diagnostic>,
    /// **MI-6.** The C2 cursor a mutating operation committed at. A client MUST
    /// NOT report the operation complete to a human until it has observed an
    /// event at or past this.
    #[serde(default)]
    pub committed_at_net_seq: Option<u64>,
}

/// A diagnostic on the wire.
///
/// **MI-14: the resolved attributes travel with the code.**
///
/// > "Every `Diagnostic` crossing MI MUST carry the **resolved** attribute set
/// > inline, not by registry lookup: `reason_code`, `class`, `severity`,
/// > `terminal`, `user_actionable`, `remediation_class`, `scope`, and
/// > `doc_anchor` — for **every** code, including codes the receiving client
/// > does not recognize. The **agent** resolves them from **its own** registry
/// > at emission time."
///
/// `shells/linux` and `shells/windows` carried four of those eight and
/// `shells/macos` carried all eight; the union is what MI-14 requires and is
/// what this type is. A client that met the shorter shape had to look the
/// missing four up in a registry that may be **older than the agent's**, which
/// is the exact failure MI-14 forbids.
///
/// **MI-15, made structural.** There is no `summary`, `message`, `title`,
/// `description` or per-code user message field — in this version or any
/// version. `summary_key` and `next_action_key` are the registry's own
/// identifiers, never resolved strings. Rendering happens at the surface that
/// has a locale and a viewport, from `(reason_code, class, evidence)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The registered code, e.g. `"MGMT.UNAVAILABLE"`.
    ///
    /// A **string**, never an enum: ADR-0015 §11.2, and the concrete reason
    /// ADR-0017 §6 gives for rejecting gRPC status enums.
    pub reason_code: String,
    /// Its class: `TRANSIENT` / `PERSISTENT` / `POLICY` / `FATAL`.
    ///
    /// **EM-37**: "automation switches on `class`, not on the exit code", so it
    /// travels with the code rather than being re-derived by each client from a
    /// registry that may be older than the agent's.
    pub class: String,
    /// Its severity.
    pub severity: String,
    /// Whether it is terminal. **MI-14**, and not `serde(default)`: a receiver
    /// that defaulted this to `false` would retry something that will never
    /// succeed.
    pub terminal: bool,
    /// Whether a user can act on it.
    pub user_actionable: bool,
    /// The remediation class: `user-action` / `wait` / `automatic` /
    /// `network-operator` / `unsupported`. **MI-14.**
    #[serde(default)]
    pub remediation_class: String,
    /// The registry's scope: `session` / `device` / `relay` / `region` /
    /// `twinnet`. **MI-14.**
    #[serde(default)]
    pub scope: String,
    /// The documentation anchor. **MI-14.**
    #[serde(default)]
    pub doc_anchor: String,
    /// The registry's i18n **key**, never a sentence.
    #[serde(default)]
    pub summary_key: Option<String>,
    /// The next-action **key**, never a sentence.
    #[serde(default)]
    pub next_action_key: Option<String>,
    /// Typed evidence, already restricted to the code's declared fields and
    /// **already redacted** (ADR-0018 F-4).
    ///
    /// JSON rather than `Vec<(String, String)>`, which is what two of the three
    /// shells carried: MI-15 says *typed* evidence, and stringifying an integer
    /// or a boolean at the wire makes a consumer re-parse it and guess the type
    /// back. A JSON value carries the type the registry declared.
    #[serde(default)]
    pub evidence: serde_json::Value,
}

impl Diagnostic {
    /// Resolves every MI-14 attribute for `code` from **this agent's own**
    /// registry.
    ///
    /// The one constructor, so no carriage can emit a diagnostic with a code and
    /// a set of attributes that disagree — which is what "resolved by the agent
    /// at emission time" is protecting.
    #[must_use]
    pub fn of(code: ReasonCode) -> Self {
        Self {
            reason_code: code.as_str().to_owned(),
            class: format!("{:?}", code.class()).to_uppercase(),
            severity: format!("{:?}", code.severity()).to_uppercase(),
            terminal: code.terminal(),
            user_actionable: code.user_actionable(),
            remediation_class: format!("{:?}", code.remediation_class()).to_uppercase(),
            scope: format!("{:?}", code.scope()).to_uppercase(),
            doc_anchor: code.doc_anchor().to_owned(),
            summary_key: None,
            next_action_key: code.next_action_key().map(str::to_owned),
            evidence: serde_json::Value::Null,
        }
    }
}

/// §11.3's `Event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The topic, from ADR-0017 §11.10's list.
    pub topic: String,
    /// The encoded event.
    #[serde(default)]
    pub payload: Vec<u8>,
    /// **MI-18.** The OS principal whose call produced this, or `None` for an
    /// agent-internal or peer-initiated cause.
    ///
    /// > "the tunnel went down" and "Dana took the tunnel down" are different
    /// > facts.
    #[serde(default)]
    pub actor_principal: Option<String>,
}

/// §11.3's `Compacted` — MI-19's **ordered** gap marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    /// The sequence number up to which bodies were dropped.
    pub up_to_seq: u64,
    /// Per-topic counts, so a UI can say "12 transitions not shown".
    pub dropped_by_topic: Vec<(String, u64)>,
}

/// Why a frame could not be **decoded**.
///
/// # The codec's errors, and not the transport's
///
/// Three shells carried three different `FrameError`s: `shells/linux` and
/// `shells/windows` had `TooLarge`/`Closed`/`Malformed`/`Transport(io::Error)`
/// and returned a `&'static str` code; `shells/macos` had
/// `TooLarge`/`Empty`/`Malformed`/`Truncated` and returned a typed
/// [`ReasonCode`]. They disagreed about what a zero-length frame means and about
/// whether a clean close is an error.
///
/// This type is the **codec's** half and stops where the bytes stop: a peer
/// closing a socket is not a framing fault, it is a transport event, and each
/// shell answers it in its own transport (`Err(Closed)` on Linux, `Ok(None)` on
/// macOS — both defensible, and neither belongs here). What *is* shared is every
/// judgement about the bytes themselves, and that judgement is now made once.
///
/// `Copy` on purpose: it carries no allocation and no `io::Error`, so a caller
/// can compare two and can report one twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The declared length exceeds [`MAX_ENVELOPE_BYTES`].
    ///
    /// Detected **before** any allocation, which is the whole point of checking
    /// the prefix rather than reading first and measuring after.
    #[error("the declared envelope length exceeds the 1 MiB cap")]
    TooLarge {
        /// What the peer declared.
        declared: usize,
    },
    /// A zero-length frame.
    ///
    /// `shells/macos` was right to name this and the other two were wrong to
    /// fold it into "malformed": a declared length of zero is a **desynchronised
    /// stream**, not a keepalive and not a body that failed to parse, and the
    /// remediation differs.
    #[error("a zero-length frame: the stream is desynchronised")]
    Empty,
    /// The bytes did not decode.
    #[error("the envelope did not decode")]
    Malformed,
    /// The buffer ended inside a frame.
    ///
    /// Distinct from [`FrameError::Malformed`]: an incomplete frame may become
    /// complete when more bytes arrive, and a malformed one never will.
    #[error("the buffer ended inside a frame")]
    Truncated,
}

impl FrameError {
    /// The registered `reason_code`.
    ///
    /// **Every one is a substitution**, because ADR-0017 owns the `MGMT` domain
    /// and `contracts/registry/reason_codes.json` registers four of its
    /// thirty-eight codes (`ownership.md` §9.6 X-1). The substitution table is
    /// [`crate::codes::SUBSTITUTIONS`] and there is deliberately **no second
    /// mapping here**: two shells previously hard-coded the string literals
    /// beside it, which is how a substitution's cost stops being recorded.
    ///
    /// Typed rather than `&'static str`, which is what two of the three shells
    /// returned: a `ReasonCode` cannot be a code the registry does not have.
    #[must_use]
    pub fn reason_code(self) -> ReasonCode {
        match self {
            // ADR-0017 spells this `MGMT.PAYLOAD_TOO_LARGE`; the registry has
            // `PROTO.SIZE_EXCEEDED`, which carries the bound and the class
            // exactly and loses only the MGMT domain.
            FrameError::TooLarge { .. } => crate::codes::substituted("MGMT.PAYLOAD_TOO_LARGE")
                .unwrap_or(twinvpn_types::codes::PROTO_SIZE_EXCEEDED),
            FrameError::Empty | FrameError::Malformed => {
                twinvpn_types::codes::PROTO_UNPARSEABLE_ENVELOPE
            }
            FrameError::Truncated => twinvpn_types::codes::PROTO_MALFORMED_MESSAGE,
        }
    }
}

/// Encodes one envelope as a length-prefixed frame.
///
/// # Errors
///
/// [`FrameError::TooLarge`] if the encoded envelope exceeds the cap — checked on
/// the **send** side too, so this agent cannot emit a frame it would itself
/// refuse.
pub fn encode_frame(envelope: &MgmtEnvelope) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(envelope).map_err(|_| FrameError::Malformed)?;
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(FrameError::TooLarge {
            declared: body.len(),
        });
    }
    let mut out = Vec::with_capacity(body.len() + LENGTH_PREFIX_BYTES);
    let len = u32::try_from(body.len()).map_err(|_| FrameError::Malformed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reads the declared length from a prefix, **refusing an over-cap value before
/// anything is allocated**.
///
/// # Errors
///
/// [`FrameError::TooLarge`]. `ownership.md` §6 rule 9: "A violation is a typed
/// reject with a `PROTO.*` code — never a truncation, never a pad, never a
/// silent accept."
pub fn declared_length(prefix: [u8; LENGTH_PREFIX_BYTES]) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        // `shells/macos`' reading, adopted: a zero-length frame is a
        // desynchronised stream, and calling it that is more useful than reading
        // zero bytes and then reporting the empty body as malformed.
        return Err(FrameError::Empty);
    }
    if declared > MAX_ENVELOPE_BYTES {
        return Err(FrameError::TooLarge { declared });
    }
    Ok(declared)
}

/// Decodes a whole frame — prefix and body — from one buffer.
///
/// For a carriage that already has the complete frame in hand (a message-mode
/// pipe, an XPC message, a test), where reading the prefix and the body as two
/// steps would be an invented ceremony.
///
/// # Errors
///
/// [`FrameError::Truncated`] if the buffer is shorter than the frame it
/// declares, and [`declared_length`]'s errors for the prefix itself. The bound
/// is still checked **before** the body is sliced.
pub fn decode_frame(bytes: &[u8]) -> Result<MgmtEnvelope, FrameError> {
    let prefix: [u8; LENGTH_PREFIX_BYTES] = bytes
        .get(..LENGTH_PREFIX_BYTES)
        .and_then(|s| s.try_into().ok())
        .ok_or(FrameError::Truncated)?;
    let declared = declared_length(prefix)?;
    let body = bytes
        .get(LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + declared)
        .ok_or(FrameError::Truncated)?;
    decode_body(body)
}

/// Decodes an envelope body.
///
/// # Errors
///
/// [`FrameError::Malformed`] — a typed reject, never a panic (ADR-0018 F-3).
pub fn decode_body(bytes: &[u8]) -> Result<MgmtEnvelope, FrameError> {
    serde_json::from_slice(bytes).map_err(|_| FrameError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(body: Body) -> MgmtEnvelope {
        MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![1; 16],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 42,
            body,
        }
    }

    #[test]
    fn an_envelope_round_trips() {
        let original = envelope(Body::Request(Request {
            operation: "status.get".to_owned(),
            params: vec![1, 2, 3],
            if_version: None,
        }));
        let frame = encode_frame(&original).expect("encodes");
        let declared = declared_length([frame[0], frame[1], frame[2], frame[3]]).expect("length");
        assert_eq!(declared, frame.len() - LENGTH_PREFIX_BYTES);
        let decoded = decode_body(&frame[LENGTH_PREFIX_BYTES..]).expect("decodes");
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_over_cap_length_is_refused_before_a_byte_is_allocated() {
        // §11.3: enforced BEFORE parse. `ownership.md` §6 rule 9: never a
        // truncation, never a pad, never a silent accept.
        let huge = u32::try_from(MAX_ENVELOPE_BYTES + 1).expect("fits");
        let err = declared_length(huge.to_be_bytes()).expect_err("refused");
        assert!(matches!(err, FrameError::TooLarge { .. }));
        // MGMT.PAYLOAD_TOO_LARGE, not PROTO.SIZE_EXCEEDED. ADR-0017 §11.3's own
        // code was unregistered before `registry_version` 2, so a MANAGEMENT
        // framing refusal degraded on an older client to "the peer protocol is
        // wrong" — a different diagnosis with a different next action.
        assert_eq!(err.reason_code().as_str(), "MGMT.PAYLOAD_TOO_LARGE");
        // And exactly at the cap is accepted.
        let exact = u32::try_from(MAX_ENVELOPE_BYTES).expect("fits");
        assert_eq!(
            declared_length(exact.to_be_bytes()).expect("at the cap"),
            MAX_ENVELOPE_BYTES
        );
    }

    #[test]
    fn malformed_bytes_are_a_typed_reject_never_a_panic() {
        // ADR-0018 F-3: "invalid UTF-8 is a typed error, never a panic".
        for bytes in [b"".as_slice(), b"{", b"\xff\xfe", b"[1,2,3]"] {
            let err = decode_body(bytes).expect_err("refused");
            assert!(matches!(err, FrameError::Malformed));
            assert_eq!(err.reason_code().as_str(), "PROTO.UNPARSEABLE_ENVELOPE");
        }
    }

    #[test]
    fn mi3_the_agent_cannot_originate_a_request() {
        // "No daemon→client RPC exists." Asserted as a property of the body
        // type rather than as a convention the server is trusted to keep.
        assert!(Body::Request(Request {
            operation: "status.get".to_owned(),
            params: Vec::new(),
            if_version: None,
        })
        .is_client_originated());
        assert!(Body::Hello(Hello {
            mi_version_min: 1,
            mi_version_max: 1,
            client_kind: "cli".to_owned(),
            client_version: "0.1.0".to_owned(),
            requested_scopes: Vec::new(),
            subscribe_topics: Vec::new(),
        })
        .is_client_originated());
        for agent_only in [
            Body::Reject(diagnostic()),
            Body::Response(Response {
                ok: true,
                result: Vec::new(),
                diagnostic: None,
                committed_at_net_seq: None,
            }),
            Body::Event(Event {
                topic: "session.state".to_owned(),
                payload: Vec::new(),
                actor_principal: None,
            }),
            Body::Compacted(Compacted {
                up_to_seq: 1,
                dropped_by_topic: Vec::new(),
            }),
        ] {
            assert!(!agent_only.is_client_originated(), "{agent_only:?}");
        }
    }

    fn diagnostic() -> Diagnostic {
        Diagnostic {
            summary_key: Some("reason.mgmt_unavailable.summary".to_owned()),
            ..Diagnostic::of(twinvpn_types::codes::MGMT_UNAVAILABLE)
        }
    }

    #[test]
    fn mi15_no_rendered_human_text_exists_anywhere_on_the_wire() {
        // The mechanism is that there is no FIELD for one. Serialising a
        // diagnostic and searching the JSON for a sentence is what makes that
        // checkable rather than asserted.
        let json =
            serde_json::to_string(&envelope(Body::Reject(diagnostic()))).expect("serialises");
        for forbidden in ["\"summary\"", "\"message\"", "\"title\"", "\"description\""] {
            assert!(
                !json.contains(forbidden),
                "MI-15 forbids {forbidden} in any MI message, in any version"
            );
        }
        // The KEYS are present; the sentences are not.
        assert!(json.contains("summary_key"));
    }

    #[test]
    fn an_operation_is_a_name_not_an_enum_so_an_unknown_one_is_typed() {
        // §11.7: an operation absent from the catalogue is `MGMT.OP_UNKNOWN`,
        // "never a parse error, never a hang, never a generic failure". That is
        // only possible if the wire carries a NAME.
        let frame = encode_frame(&envelope(Body::Request(Request {
            operation: "status.gett".to_owned(),
            params: Vec::new(),
            if_version: None,
        })))
        .expect("encodes");
        let decoded = decode_body(&frame[LENGTH_PREFIX_BYTES..]).expect("decodes");
        match decoded.body {
            Body::Request(r) => {
                assert_eq!(r.operation, "status.gett");
                assert_eq!(crate::CoreCommand::from_name(&r.operation), None);
            }
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn every_operation_name_this_wire_can_carry_comes_from_the_one_vocabulary() {
        // MI-20: there is no operation list in this file. This asserts it by
        // enumerating the ONLY two sources a name may come from.
        let mut names: Vec<&str> = crate::CoreCommand::ALL.iter().map(|c| c.name()).collect();
        names.extend(crate::TransportOp::ALL.iter().map(|t| t.name()));
        assert!(names.contains(&"status.get"));
        assert!(names.contains(&"mi.catalogue.get"));
        crate::assert_closed().expect("MI-21 holds");
    }

    /// **`shells/macos`' reading, adopted: a zero-length frame is a
    /// desynchronised stream and not a keepalive.**
    ///
    /// The other two shells folded it into "malformed" by reading zero bytes and
    /// then failing to parse them. Both refuse; only one says what happened.
    #[test]
    fn a_zero_length_frame_is_a_desynchronised_stream_and_not_a_keepalive() {
        let err = declared_length([0, 0, 0, 0]).expect_err("refused");
        assert_eq!(err, FrameError::Empty);
        assert_eq!(err.reason_code().as_str(), "PROTO.UNPARSEABLE_ENVELOPE");
    }

    #[test]
    fn a_whole_frame_decodes_and_a_short_one_is_truncated_rather_than_malformed() {
        // An incomplete frame may become complete when more bytes arrive; a
        // malformed one never will. Two facts, two variants.
        let original = envelope(Body::Goodbye);
        let frame = encode_frame(&original).expect("encodes");
        assert_eq!(decode_frame(&frame).expect("decodes"), original);

        assert_eq!(
            decode_frame(&frame[..frame.len() - 1]).expect_err("short"),
            FrameError::Truncated
        );
        assert_eq!(
            decode_frame(&[0, 0]).expect_err("no prefix"),
            FrameError::Truncated
        );
    }

    /// **MI-14: every resolved attribute travels with the code.**
    ///
    /// Two of the three shells carried four of the eight, so a client had to
    /// look the rest up in a registry that may be older than the agent's —
    /// exactly what MI-14 forbids.
    #[test]
    fn mi14s_whole_resolved_attribute_set_is_on_the_wire() {
        let json = serde_json::to_string(&Diagnostic::of(
            twinvpn_types::codes::PLATFORM_ADAPTER_UNAVAILABLE,
        ))
        .expect("serialises");
        for required in [
            "reason_code",
            "class",
            "severity",
            "terminal",
            "user_actionable",
            "remediation_class",
            "scope",
            "doc_anchor",
        ] {
            assert!(
                json.contains(required),
                "MI-14 requires {required} to travel with the code"
            );
        }
    }

    #[test]
    fn a_diagnostics_attributes_come_from_the_registry_and_are_never_authored() {
        // "The agent resolves them from its OWN registry at emission time." A
        // constructor that took them as parameters would let a carriage emit a
        // code and a set of attributes that disagree.
        let code = twinvpn_types::codes::PLATFORM_VPN_PERMISSION_DENIED;
        let d = Diagnostic::of(code);
        assert_eq!(d.reason_code, code.as_str());
        assert_eq!(d.terminal, code.terminal());
        assert_eq!(d.user_actionable, code.user_actionable());
        assert_eq!(d.doc_anchor, code.doc_anchor());
    }

    /// **MI-19's gap boundary is not optional.**
    ///
    /// `shells/macos`' `Compacted` had lost `up_to_seq` and carried only the
    /// per-topic counts, so a client could learn that events were dropped and
    /// not where the gap ended — which is the one thing an ordered marker exists
    /// to say.
    #[test]
    fn a_compacted_marker_names_where_the_gap_ends() {
        let marker = Compacted {
            up_to_seq: 128,
            dropped_by_topic: vec![("transition".to_owned(), 12)],
        };
        let json = serde_json::to_string(&marker).expect("serialises");
        assert!(json.contains("up_to_seq"));
        assert_eq!(
            serde_json::from_str::<Compacted>(&json).expect("round trips"),
            marker
        );
    }

    /// MI-5 requires N and N-1. At version 1 there is no N-1, and declaring a
    /// wider window than the build serves is how a client is told it can speak
    /// a version that will then be refused.
    ///
    /// `const` rather than a runtime assertion, because these are constants: a
    /// runtime `assert!` on two `const`s is optimised out and never runs.
    const _WINDOW: () = {
        assert!(MI_VERSION_MIN <= MI_VERSION);
        assert!(MI_VERSION_MIN == 1);
    };
}
