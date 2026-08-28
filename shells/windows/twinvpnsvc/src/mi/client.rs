//! The MI client: connect, `Hello`, request, response.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7 (the negotiation and its mismatch table), MI-2, MI-3, MI-C3, MI-6;
//! ADR-0023 EM-37.
//!
//! # The catalogue is re-fetched on every attach
//!
//! §11.7's last row: on a reconnect a client "MUST re-`Hello`, and **re-fetch
//! the catalogue**. It **MUST NOT reuse a catalogue cached across a reconnect**."
//! [`Client::connect`] therefore returns a client whose catalogue digest came
//! from *this* connection's `HelloAck`, and there is nowhere in this type to
//! stash one across connections.
//!
//! # `platform_ctx` is taken, never built
//!
//! **MI-C3**: "Every MI client MUST use the `platform_ctx` the agent supplied in
//! `HelloAck`, **verbatim**, and MUST NOT construct one from its own build
//! constants or its own runtime probe." [`Client::platform_ctx`] returns what
//! arrived. There is no constructor for one in this crate outside the agent.

use tokio::io::{AsyncRead, AsyncWrite};

use super::codec::TransportError;
use super::codec::{read_frame, write_frame};
use super::scope::Scopes;
use super::wire::{
    Body, Diagnostic, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Request, Response, MI_VERSION,
    MI_VERSION_MIN,
};

/// Why a client call did not produce a response.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The endpoint is not there, or went away.
    ///
    /// ADR-0017 §11.12 gives this its own exit code (**3**), "distinct from 1",
    /// so a script can tell "the agent is not running" from "the agent said no".
    #[error("the management interface is unavailable")]
    Unavailable(#[source] TransportError),
    /// The agent refused the attach and said why. §11.7 forbids a silent close.
    #[error("the agent refused the connection")]
    Rejected(Box<Diagnostic>),
    /// The agent answered, and the answer was a failure.
    #[error("the operation failed")]
    Failed(Box<Diagnostic>),
    /// The agent broke the protocol — a response to nothing, a request from the
    /// agent (MI-3), or a body that cannot follow.
    #[error("the agent sent a message the protocol does not allow here")]
    Protocol,
}

impl ClientError {
    /// The registered `reason_code` to print on stderr.
    ///
    /// ADR-0017 §11.12: "Every non-zero exit prints to **stderr**, in every
    /// output mode", so a `set -e` script that does not parse JSON still gets
    /// the code.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        match self {
            ClientError::Unavailable(e) => e.reason_code().as_str(),
            ClientError::Rejected(d) | ClientError::Failed(d) => &d.reason_code,
            ClientError::Protocol => "PROTO.UNPARSEABLE_ENVELOPE",
        }
    }

    /// The `Diagnostic.class`, where there is one.
    ///
    /// **EM-37**: "automation switches on `class`, not on the exit code …
    /// Scripts MUST NOT infer retryability from the exit code alone."
    #[must_use]
    pub fn class(&self) -> Option<&str> {
        match self {
            ClientError::Rejected(d) | ClientError::Failed(d) => Some(&d.class),
            ClientError::Unavailable(_) | ClientError::Protocol => None,
        }
    }
}

/// An attached MI connection.
///
/// # Generic over the transport, and why that is not abstraction for its own sake
///
/// `tokio`'s named-pipe types exist only under `#[cfg(windows)]`, so a `Client`
/// that named one could not be compiled — let alone tested — on the host this
/// crate was written on. Making the transport a parameter costs one type
/// variable and buys the whole `Hello`/`HelloAck` negotiation, the request/
/// response loop and MI-3's direction rule as **host-runnable tests** over
/// `tokio::io::duplex`.
///
/// [`Client::connect`] is the production constructor and is `#[cfg(windows)]`;
/// [`Client::attach`] takes an already-open transport and is what a test uses.
pub struct Client<S> {
    stream: S,
    ack: HelloAck,
    next_request: u64,
}

/// The concrete client the CLI holds.
#[cfg(windows)]
pub type PipeClient = Client<tokio::net::windows::named_pipe::NamedPipeClient>;

#[cfg(windows)]
impl PipeClient {
    /// Opens the pipe and completes the negotiation.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unavailable`] when the endpoint is absent — which is a
    /// **different** condition from a refusal and carries its own exit code (3
    /// rather than 1) — and [`ClientError::Rejected`] when the agent refuses and
    /// says why.
    pub async fn connect(
        pipe_name: &str,
        client_kind: &str,
        client_version: &str,
        requested_scopes: &[String],
    ) -> Result<Self, ClientError> {
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(pipe_name)
            .map_err(|e| ClientError::Unavailable(TransportError::Transport(e)))?;
        Client::attach(stream, client_kind, client_version, requested_scopes).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Completes the `Hello`/`HelloAck` negotiation on an already-open
    /// transport.
    ///
    /// # Errors
    ///
    /// [`ClientError::Rejected`] when the agent refuses and says why —
    /// §11.7 forbids a silent close, because a silent close is
    /// indistinguishable from "the agent is not running" and sends the user to
    /// reinstall rather than to update.
    pub async fn attach(
        stream: S,
        client_kind: &str,
        client_version: &str,
        requested_scopes: &[String],
    ) -> Result<Self, ClientError> {
        Self::attach_subscribed(stream, client_kind, client_version, requested_scopes, &[]).await
    }

    /// [`Client::attach`], also asking for §11.10's event stream.
    ///
    /// An **empty** topic list is "no stream", not "every topic": §11.10 has no
    /// wildcard, and a client that wants events names them. Kept as a separate
    /// constructor so the common case reads unchanged and so a caller that does
    /// not want a stream cannot acquire one by forgetting an argument.
    ///
    /// # Errors
    ///
    /// [`Client::attach`]'s.
    pub async fn attach_subscribed(
        stream: S,
        client_kind: &str,
        client_version: &str,
        requested_scopes: &[String],
        subscribe_topics: &[String],
    ) -> Result<Self, ClientError> {
        let mut stream = stream;

        let hello = MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: request_id(0),
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            // A client does not stamp `as_of_ms`: MI-16 makes it the AGENT's
            // reading, on the agent's boot-time clock. A client-stamped value
            // would be a second clock the freshness gate could disagree with.
            as_of_ms: 0,
            body: Body::Hello(Hello {
                mi_version_min: MI_VERSION_MIN,
                mi_version_max: MI_VERSION,
                client_kind: client_kind.to_owned(),
                client_version: client_version.to_owned(),
                requested_scopes: requested_scopes.to_vec(),
                subscribe_topics: subscribe_topics.to_vec(),
            }),
        };
        write_frame(&mut stream, &hello)
            .await
            .map_err(ClientError::Unavailable)?;

        let reply = read_frame(&mut stream)
            .await
            .map_err(ClientError::Unavailable)?;
        match reply.body {
            Body::HelloAck(ack) => Ok(Self {
                stream,
                ack: *ack,
                next_request: 1,
            }),
            // §11.7: the agent completes enough of the attach to answer, then
            // closes. A silent close is prohibited, so a client that gets one
            // reports `Unavailable` and a client that gets this reports the
            // agent's own reason.
            Body::Reject(diagnostic) => Err(ClientError::Rejected(Box::new(diagnostic))),
            _ => Err(ClientError::Protocol),
        }
    }

    /// The scopes this connection was granted. **Immutable for its life**
    /// (MI-S2).
    #[must_use]
    pub fn granted(&self) -> Scopes {
        Scopes::from_scopes(
            super::scope::GRANTABLE
                .into_iter()
                .filter(|s| self.ack.granted_scopes.iter().any(|g| g == s.name())),
        )
    }

    /// The scopes that were asked for and withheld.
    #[must_use]
    pub fn withheld(&self) -> &[String] {
        &self.ack.withheld_scopes
    }

    /// **MI-C3.** The agent's own `platform_ctx`, used verbatim.
    #[must_use]
    pub const fn platform_ctx(&self) -> &PlatformCtx {
        &self.ack.platform_ctx
    }

    /// The catalogue digest **this connection** was told.
    #[must_use]
    pub fn catalogue_digest(&self) -> &str {
        &self.ack.catalogue_digest
    }

    /// The agent's version, for the `version.get` rendering.
    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.ack.agent_version
    }

    /// The negotiated MI version. Fixed for the life of the connection.
    #[must_use]
    pub const fn mi_version(&self) -> u32 {
        self.ack.mi_version
    }

    /// Submits one operation and waits for its response.
    ///
    /// # Errors
    ///
    /// [`ClientError::Failed`] carries the agent's own diagnostic — codes and
    /// typed evidence, never prose (MI-15). The caller renders it.
    pub async fn call(
        &mut self,
        operation: &str,
        params: Vec<u8>,
        if_version: Option<u64>,
        idempotency_key: Vec<u8>,
    ) -> Result<Response, ClientError> {
        // MI-2: `request_id` is unique PER EMISSION. A retry reuses
        // `idempotency_key` and never this, which is why the counter advances
        // here and the key is the caller's.
        let id = self.next_request;
        self.next_request += 1;

        let envelope = MgmtEnvelope {
            mi_version: self.ack.mi_version,
            request_id: request_id(id),
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key,
            as_of_ms: 0,
            body: Body::Request(Request {
                operation: operation.to_owned(),
                params,
                if_version,
            }),
        };
        write_frame(&mut self.stream, &envelope)
            .await
            .map_err(ClientError::Unavailable)?;

        loop {
            let reply = read_frame(&mut self.stream)
                .await
                .map_err(ClientError::Unavailable)?;
            match reply.body {
                Body::Response(response) => {
                    if response.ok {
                        return Ok(response);
                    }
                    let diagnostic = response.diagnostic.ok_or(ClientError::Protocol)?;
                    return Err(ClientError::Failed(Box::new(diagnostic)));
                }
                // An event may arrive between a request and its response: the
                // stream is one connection. Skipping it here rather than
                // failing is what makes a subscribed client able to also make
                // ordinary calls.
                Body::Event(_) | Body::Compacted(_) => {}
                Body::Goodbye => return Err(ClientError::Unavailable(TransportError::Closed)),
                Body::Reject(d) => return Err(ClientError::Rejected(Box::new(d))),
                // MI-3: the agent MUST NOT initiate a request. Receiving one is
                // a protocol violation, not something to answer.
                Body::Hello(_) | Body::HelloAck(_) | Body::Request(_) => {
                    return Err(ClientError::Protocol)
                }
            }
        }
    }

    /// Reads the next frame the **agent** pushed: §11.10's event, or MI-19's
    /// ordered gap marker.
    ///
    /// Returns the whole envelope rather than the body alone, because MI-16's
    /// `seq` and `as_of_ms` live on it and a client that wanted to prove it had
    /// missed nothing would otherwise have to be told them twice.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unavailable`] when the connection ends, and
    /// [`ClientError::Protocol`] for anything MI-3 forbids the agent to send.
    pub async fn next_event(&mut self) -> Result<MgmtEnvelope, ClientError> {
        loop {
            let frame = read_frame(&mut self.stream)
                .await
                .map_err(ClientError::Unavailable)?;
            match frame.body {
                Body::Event(_) | Body::Compacted(_) => return Ok(frame),
                // A response to a call this caller is not awaiting. Skipping it
                // keeps `next_event` usable on a connection that also makes
                // ordinary calls, which is the shape §11.10 assumes.
                Body::Response(_) => {}
                Body::Goodbye => return Err(ClientError::Unavailable(TransportError::Closed)),
                Body::Reject(d) => return Err(ClientError::Rejected(Box::new(d))),
                Body::Hello(_) | Body::HelloAck(_) | Body::Request(_) => {
                    return Err(ClientError::Protocol)
                }
            }
        }
    }
}

/// A 16-byte request id.
///
/// Sequential within a connection rather than random: `ownership.md` §6's
/// determinism rules put randomness behind `twinvpn_env::Env`, which the CLI
/// does not build, and MI-2 requires only that the value be **unique per
/// emission** — which a per-connection counter is. It is not a secret and
/// nothing authenticates on it.
fn request_id(n: u64) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    out[8..16].copy_from_slice(&n.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_id_is_sixteen_bytes_and_unique_per_emission() {
        assert_eq!(request_id(0).len(), 16);
        assert_ne!(request_id(1), request_id(2));
    }

    #[test]
    fn the_error_carries_a_registered_code_and_never_a_bare_message() {
        let unavailable = ClientError::Unavailable(TransportError::Closed);
        assert_eq!(unavailable.reason_code(), "MGMT.UNAVAILABLE");
        // EM-37: the class is what a script switches on, and it is absent for a
        // transport failure because the agent never got to name one.
        assert_eq!(unavailable.class(), None);

        let failed = ClientError::Failed(Box::new(Diagnostic::of(
            twinvpn_types::codes::POLICY_POLICY_DENIED,
        )));
        assert_eq!(failed.reason_code(), "POLICY.POLICY_DENIED");
        assert_eq!(failed.class(), Some("POLICY"));
    }

    #[test]
    fn a_missing_endpoint_is_a_different_condition_from_a_refusal() {
        // ADR-0017 §11.12 gives them different exit codes so a script can tell
        // "re-run with privilege" from "this will never work".
        let unavailable = ClientError::Unavailable(TransportError::Closed);
        let rejected = ClientError::Rejected(Box::new(Diagnostic::of(
            twinvpn_types::codes::MGMT_PRINCIPAL_UNVERIFIABLE,
        )));
        assert_ne!(unavailable.reason_code(), rejected.reason_code());
    }
}
