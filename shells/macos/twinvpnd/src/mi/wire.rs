//! The local management interface's envelope.
//!
//! **Authority:** ADR-0017 §11.3 (the envelope and the 1 MiB cap), §11.7
//! (`Hello`/`HelloAck` and the mismatch table), MI-3, MI-15, MI-16, MI-18,
//! MI-20, MI-21, MI-C3; ADR-0018 F-8.
//!
//! # One vocabulary, carried — never redeclared
//!
//! Every operation on this wire is named by [`twinvpn_mgmt::CoreCommand::name`],
//! and the four transport-layer operations are [`twinvpn_mgmt::TransportOp`]'s.
//! **There is no operation enum in this file.** MI-20's "one source, three
//! artifacts" is what that protects: the core's command table generates the
//! catalogue, and the catalogue generates the CLI verb table. A parallel list
//! here would be the second contract §11.16 (b) forbids.
//!
//! See [`super`] for why this module exists at all rather than living in
//! `twinvpn-mgmt`, and why that is reported as a request.
//!
//! # `SOCK_STREAM` with a length prefix, and why
//!
//! §11.2 prefers `SOCK_SEQPACKET` "so message boundaries are kernel-preserved: a
//! length-prefix bug cannot desynchronize the stream", and names "`SOCK_STREAM` +
//! length prefix" as the fallback. This build takes the fallback for the same
//! reason the Linux shell does — `tokio`'s `UnixListener` is `SOCK_STREAM` only,
//! and a hand-rolled `SOCK_SEQPACKET` accept loop would put a second `unsafe`
//! surface in a crate that forbids it. The cost is exactly the one §11.2 names,
//! and it is bounded by [`MAX_ENVELOPE_BYTES`] being enforced **before any
//! allocation**.

use serde::{Deserialize, Serialize};

/// §11.3's cap, enforced **before parse**.
///
/// > Max envelope 1 MiB, enforced before parse (`MGMT.PAYLOAD_TOO_LARGE`).
///
/// `ownership.md` §6 rule 9: a declared length is validated before any allocation
/// proportional to it. [`super::codec::decode_frame`] checks the prefix against
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
    /// **MI-16.** Agent-stamped, on the **boot-time monotonic** clock — on this
    /// platform `mach_continuous_time`, ADR-0022 LC-8's `ElapsedClock`, supplied
    /// by `twinvpn_platform_macos::clock::ContinuousElapsedClock`.
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
/// **MI-3: the agent MUST NOT initiate a request.** There is no `Request` variant
/// the agent can send, because the direction is enforced by
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
    /// **MI-C3.** Supplied by the agent and used by every client **verbatim**: a
    /// CLI and a GUI that each derived their own could disagree on one host and
    /// render different next actions for the same diagnostic.
    pub platform_ctx: PlatformCtx,
}

/// The `{platform, os_version}` MI-C3 carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCtx {
    /// `"macos"`.
    pub platform: String,
    /// e.g. `"15.1"`.
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
/// `description` or per-code user message field — in this version or any version.
/// `summary_key` and `next_action_key` are the registry's own identifiers, never
/// resolved strings. Rendering happens at the surface that has a locale and a
/// viewport, from `(reason_code, class, evidence)`.
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
    /// Whether it is terminal.
    pub terminal: bool,
    /// The remediation class.
    #[serde(default)]
    pub remediation_class: String,
    /// The registry's scope.
    #[serde(default)]
    pub scope: String,
    /// The documentation anchor.
    #[serde(default)]
    pub doc_anchor: String,
    /// The registry's `next_action` **key**, never a rendered sentence.
    #[serde(default)]
    pub next_action_key: Option<String>,
    /// Typed evidence, as JSON.
    #[serde(default)]
    pub evidence: serde_json::Value,
}

impl Diagnostic {
    /// A diagnostic for a code the agent is emitting itself.
    ///
    /// Resolved from the agent's own registry at emission time (**MI-14**), so a
    /// client that has never seen the code can still render it.
    #[must_use]
    pub fn of(code: twinvpn_types::ReasonCode) -> Self {
        Self {
            reason_code: code.as_str().to_owned(),
            class: format!("{:?}", code.class()).to_uppercase(),
            severity: format!("{:?}", code.severity()).to_uppercase(),
            user_actionable: code.user_actionable(),
            terminal: code.terminal(),
            remediation_class: format!("{:?}", code.remediation_class()).to_uppercase(),
            scope: format!("{:?}", code.scope()).to_uppercase(),
            doc_anchor: code.doc_anchor().to_owned(),
            next_action_key: code.next_action_key().map(str::to_owned),
            evidence: serde_json::Value::Null,
        }
    }
}

/// An event pushed to a subscriber.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The topic.
    pub topic: String,
    /// The encoded payload.
    #[serde(default)]
    pub payload: Vec<u8>,
    /// **MI-18.** The principal whose action caused this, where one did.
    #[serde(default)]
    pub actor_principal: Option<String>,
}

/// **MI-19**: an ordered marker announcing a delivery gap.
///
/// "No state-changing event is discarded without a record." A silent gap and a
/// recorded gap look the same to a client that is not told; only the recorded one
/// lets it re-sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    /// Per-topic counts of what was dropped.
    pub per_topic: Vec<(String, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> MgmtEnvelope {
        MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![1, 2, 3],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Hello(Hello {
                mi_version_min: MI_VERSION_MIN,
                mi_version_max: MI_VERSION,
                client_kind: "cli".to_owned(),
                client_version: "0.1.0".to_owned(),
                requested_scopes: vec!["mgmt.status".to_owned()],
                subscribe_topics: Vec::new(),
            }),
        }
    }

    #[test]
    fn mi3_no_body_the_agent_sends_is_client_originated() {
        // The direction rule as a function. There is no daemon→client RPC.
        assert!(hello().body.is_client_originated());
        assert!(Body::Goodbye.is_client_originated());
        for body in [
            Body::HelloAck(Box::new(HelloAck {
                mi_version: 1,
                agent_version: String::new(),
                build_profile: String::new(),
                granted_scopes: Vec::new(),
                withheld_scopes: Vec::new(),
                catalogue_digest: String::new(),
                event_cursor: 0,
                protocol_epoch_range: [1, 1],
                platform_ctx: PlatformCtx {
                    platform: "macos".to_owned(),
                    os_version: String::new(),
                },
            })),
            Body::Response(Response {
                ok: true,
                result: Vec::new(),
                diagnostic: None,
                committed_at_net_seq: None,
            }),
            Body::Event(Event {
                topic: "status".to_owned(),
                payload: Vec::new(),
                actor_principal: None,
            }),
            Body::Compacted(Compacted {
                per_topic: Vec::new(),
            }),
        ] {
            assert!(!body.is_client_originated(), "{body:?}");
        }
    }

    #[test]
    fn mi15_no_field_on_this_wire_carries_rendered_human_text() {
        // Asserted over the SERIALISED form, because that is what a reviewer
        // greps and what a client sees. A `summary` field added in five years'
        // time fails here.
        let diagnostic = Diagnostic::of(twinvpn_types::codes::MGMT_UNAVAILABLE);
        let json = serde_json::to_string(&diagnostic).expect("serialises");
        for forbidden in [
            "\"summary\"",
            "\"message\"",
            "\"title\"",
            "\"description\"",
            "\"text\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "{forbidden} is on the wire: {json}"
            );
        }
        assert!(json.contains("\"reason_code\""));
        assert!(json.contains("\"next_action_key\""));
    }

    #[test]
    fn the_envelope_round_trips() {
        let encoded = serde_json::to_vec(&hello()).expect("serialises");
        let decoded: MgmtEnvelope = serde_json::from_slice(&encoded).expect("parses");
        assert_eq!(decoded, hello());
    }

    #[test]
    fn the_version_window_is_exactly_what_this_build_serves() {
        // MI-5 asks for N and N-1. At version 1 there is no N-1, and declaring a
        // wider window than the build has would make a client believe in a
        // version nothing speaks.
        assert_eq!(MI_VERSION, 1);
        assert_eq!(MI_VERSION_MIN, 1);
        // The window is a range, and a range whose floor is above its ceiling
        // would serve nothing at all. Expressed as the range's own emptiness so
        // it keeps meaning something when the two constants move.
        assert!(!(MI_VERSION_MIN..=MI_VERSION).is_empty());
    }
}
