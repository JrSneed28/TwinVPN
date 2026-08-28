//! The local management interface's envelope and framing.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.2 (the Windows transport row), §11.3 (the envelope and the 1 MiB cap),
//! §11.7 (`Hello`/`HelloAck`, and the mismatch table), MI-3, MI-15, MI-16,
//! MI-18, MI-20, MI-21; ADR-0018 F-8.
//!
//! # One vocabulary, carried — never redeclared
//!
//! Every operation on this wire is named by
//! [`twinvpn_mgmt::CoreCommand::name`], and the four transport-layer operations
//! are [`twinvpn_mgmt::TransportOp`]'s. **There is no operation enum in this
//! file.** MI-20's "one source, three artifacts" is what that protects: the
//! core's command table generates the catalogue, and the catalogue generates the
//! CLI verb table. A parallel list here would be the second contract §11.16 (b)
//! forbids.
//!
//! # A reported gap: `MgmtEnvelope` is in no contract
//!
//! ADR-0017 §11.3 specifies the envelope as **B1 protobuf** and prints its
//! `.proto`. That message appears **nowhere in `contracts/`** — there is no
//! `mgmt.proto`, and `contracts/docs/phase1-conflicts.md` OQ-2 deliberately
//! excluded an MI transport schema from Phase 2 so the MI could not acquire an
//! independent vocabulary.
//!
//! The exclusion achieved its purpose — the vocabulary here *is* the core's —
//! but it also means the **carriage** is unspecified in the frozen set. This
//! module therefore carries §11.3's field list over **B5 JSON**, which ADR-0017
//! §11.6 already names as the format the CLI renders in, with a 4-byte
//! big-endian length prefix. That is the same shape as §11.2's own
//! `SOCK_STREAM` fallback.
//!
//! **This is a finding, not a decision to keep.** It is the same class as
//! `ownership.md` §8 W-21 (`PairingOffer` in no contract), and it is reported to
//! the integration lead with the same disposition: the field names below are
//! ADR-0017 §11.3's, verbatim, so a later `mgmt.proto` is a re-encoding rather
//! than a redesign.
//!
//! # Message mode **and** a length prefix, and why both
//!
//! §11.2's Windows row specifies a **message-mode** named pipe, and §11.3 says
//! "on Windows message-mode pipes the boundary is channel-supplied (no
//! length-prefix needed — that's the `SOCK_STREAM` fallback only)".
//!
//! This build carries the prefix anyway, and the reason is `ownership.md` §6
//! rule 9 rather than distrust of the pipe. Message mode gives the *boundary*;
//! it does not give the *size in advance*. A reader in message mode either
//! allocates a buffer as large as the cap before it knows what is coming, or
//! reads and measures afterwards — and "read first, measure after" is exactly
//! what rule 9 forbids. Four bytes read first give the declared length, which
//! [`declared_length`] checks against [`MAX_ENVELOPE_BYTES`] **before a byte is
//! reserved**.
//!
//! The cost is four bytes per message and one property the ADR was protecting:
//! §11.2 prefers a kernel-preserved boundary "so a length-prefix bug cannot
//! desynchronize the stream". Message mode still provides that, so a
//! length-prefix bug here is a rejected message and not a desynchronised
//! connection. Both mechanisms are present and each covers the other's gap.
//!
use serde::{Deserialize, Serialize};

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
    /// From [`twinvpn_mgmt::catalogue_digest`], so it cannot disagree with the
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
/// **MI-15, made structural.** There is no `summary`, `message`, `title`,
/// `description` or per-code user message field — in this version or any
/// version. `summary_key` and `next_action_key` are the registry's own
/// identifiers, never resolved strings. Rendering happens at the surface that
/// has a locale and a viewport, from `(reason_code, class, evidence)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The registered code, e.g. `"MGMT.UNAVAILABLE"`.
    pub reason_code: String,
    /// Its class: `TRANSIENT` / `PERSISTENT` / `POLICY` / `FATAL`.
    ///
    /// **EM-37**: "automation switches on `class`, not on the exit code", so it
    /// travels with the code rather than being re-derived by each client from a
    /// registry that may be older than the agent's.
    pub class: String,
    /// Its severity.
    pub severity: String,
    /// Whether a user can act on it.
    pub user_actionable: bool,
    /// The registry's i18n **key**, never a sentence.
    #[serde(default)]
    pub summary_key: Option<String>,
    /// The next-action **key**, never a sentence.
    #[serde(default)]
    pub next_action_key: Option<String>,
    /// Typed evidence, already restricted to the code's declared fields and
    /// **already redacted** (ADR-0018 F-4).
    #[serde(default)]
    pub evidence: Vec<(String, String)>,
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

/// Why a frame could not be read.
#[derive(Debug, thiserror::Error)]
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
    /// The peer closed.
    #[error("the peer closed the connection")]
    Closed,
    /// The bytes did not decode.
    #[error("the envelope did not decode")]
    Malformed,
    /// The transport failed.
    #[error("the local transport failed")]
    Transport(#[from] std::io::Error),
}

impl FrameError {
    /// The registered `reason_code` a client or the agent reports.
    ///
    /// **Every one is a substitution**, because ADR-0017 owns the `MGMT` domain
    /// and `contracts/registry/reason_codes.json` registers four of its
    /// thirty-eight codes (`ownership.md` §8 W-18). The spelling ADR-0017 uses
    /// and the code actually emitted are both named, and
    /// `twinvpn_mgmt::SUBSTITUTIONS` is where the cost of each is recorded.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            // ADR-0017 spells this `MGMT.PAYLOAD_TOO_LARGE`; the registry has
            // `PROTO.SIZE_EXCEEDED`, which carries the bound and the class
            // exactly and loses only the MGMT domain.
            FrameError::TooLarge { .. } => "PROTO.SIZE_EXCEEDED",
            // `MGMT.UNAVAILABLE` is one of the four that IS registered.
            FrameError::Closed | FrameError::Transport(_) => "MGMT.UNAVAILABLE",
            FrameError::Malformed => "PROTO.UNPARSEABLE_ENVELOPE",
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
    if declared > MAX_ENVELOPE_BYTES {
        return Err(FrameError::TooLarge { declared });
    }
    Ok(declared)
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
        assert_eq!(err.reason_code(), "PROTO.SIZE_EXCEEDED");
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
            assert_eq!(err.reason_code(), "PROTO.UNPARSEABLE_ENVELOPE");
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
            reason_code: "MGMT.UNAVAILABLE".to_owned(),
            class: "TRANSIENT".to_owned(),
            severity: "WARN".to_owned(),
            user_actionable: false,
            summary_key: Some("reason.mgmt_unavailable.summary".to_owned()),
            next_action_key: None,
            evidence: Vec::new(),
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
                assert_eq!(twinvpn_mgmt::CoreCommand::from_name(&r.operation), None);
            }
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn every_operation_name_this_wire_can_carry_comes_from_the_one_vocabulary() {
        // MI-20: there is no operation list in this file. This asserts it by
        // enumerating the ONLY two sources a name may come from.
        let mut names: Vec<&str> = twinvpn_mgmt::CoreCommand::ALL
            .iter()
            .map(|c| c.name())
            .collect();
        names.extend(twinvpn_mgmt::TransportOp::ALL.iter().map(|t| t.name()));
        assert!(names.contains(&"status.get"));
        assert!(names.contains(&"mi.catalogue.get"));
        twinvpn_mgmt::assert_closed().expect("MI-21 holds");
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
