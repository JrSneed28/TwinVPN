//! The MI client — the half `twinvpnctl` links.
//!
//! **Authority:** ADR-0017 §11.7 (`Hello`/`HelloAck` and the mismatch table),
//! §11.12 (the exit codes), MI-2, MI-3, MI-5, MI-C3; ADR-0023 EM-37.
//!
//! # One contract, two carriages
//!
//! This is the second carriage. It speaks the envelope declared in
//! [`crate::wire`] and the framing in [`crate::codec`], and it declares nothing
//! of its own — which is MI-20's rule as a dependency edge rather than a
//! convention.
//!
//! # Every failure here is one a script can act on differently
//!
//! [`ClientError`] exists because ADR-0017 §11.12 makes four of them distinct
//! exit codes: "the service isn't running" and "the operation was refused" demand
//! different automation responses, and "this will never work" and "re-run with
//! privilege" are different again. So the type carries the distinction rather
//! than the caller re-deriving it from a message.

use std::path::Path;

use crate::codec::{self, FrameError};
use crate::wire::{
    Body, Diagnostic, Hello, HelloAck, MgmtEnvelope, Request, Response, MI_VERSION, MI_VERSION_MIN,
};

/// Why a client call did not produce a response.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientError {
    /// The endpoint could not be reached. **Exit 3.**
    ///
    /// Distinct from a refusal, "because 'the service isn't running' and 'the
    /// operation was refused' demand different automation responses".
    #[error("the management channel is unavailable")]
    Unavailable,
    /// The agent rejected the attach. **Exit 5** when it is a version mismatch,
    /// **exit 4** when it is an authorization refusal — the caller decides from
    /// the carried diagnostic, which is EM-37's "automation switches on `class`".
    #[error("the agent rejected the attach: {0:?}")]
    Rejected(Box<Diagnostic>),
    /// The framing failed.
    #[error("the management channel produced a malformed frame")]
    Frame(#[from] FrameError),
    /// The agent sent a body a client may not receive, or one out of order.
    ///
    /// **MI-3's direction rule, enforced on the receiving side too.** A client
    /// that accepted a `Request` from the agent would be implementing a
    /// daemon→client RPC that does not exist.
    #[error("the agent sent a body a client may not receive")]
    UnexpectedBody,
}

impl ClientError {
    /// ADR-0017 §11.12's exit code for this failure.
    ///
    /// **64+ is prohibited**, to avoid colliding with `sysexits.h` and with the
    /// shell's own 124/125/126/127 and 128+n conventions. Every value this
    /// function can return is in 1..=5, and the test below asserts it.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            ClientError::Unavailable => 3,
            ClientError::Rejected(diagnostic) => {
                // The agent named the condition; the client maps its *domain* to
                // an exit code rather than pattern-matching on individual codes,
                // so a code registered tomorrow lands in the right bucket without
                // a client change.
                match diagnostic.reason_code.split('.').next() {
                    Some("PROTO") => 5,
                    Some("PLATFORM") => 4,
                    _ => 1,
                }
            }
            ClientError::Frame(_) | ClientError::UnexpectedBody => 1,
        }
    }
}

/// A connected, attached MI client.
pub struct Client {
    stream: tokio::net::UnixStream,
    ack: HelloAck,
    next_request: u64,
}

impl Client {
    /// Connects and performs the `Hello` / `HelloAck` exchange.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unavailable`] if the endpoint is not there — which is the
    /// normal "the daemon is not running" case and is **not** an error message
    /// about a missing file. [`ClientError::Rejected`] if the agent refuses,
    /// which §11.7 requires it to do **explicitly**: "never a silent close",
    /// because a silent close is indistinguishable from the agent not running and
    /// sends the user to reinstall rather than to update.
    pub async fn attach(
        path: &Path,
        client_kind: &str,
        client_version: &str,
        requested_scopes: &[twinvpn_mgmt::Scope],
    ) -> Result<Self, ClientError> {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let mut client = Self {
            stream,
            ack: placeholder_ack(),
            next_request: 1,
        };
        let hello = Hello {
            mi_version_min: MI_VERSION_MIN,
            mi_version_max: MI_VERSION,
            client_kind: client_kind.to_owned(),
            client_version: client_version.to_owned(),
            requested_scopes: requested_scopes
                .iter()
                .map(|s| s.name().to_owned())
                .collect(),
            subscribe_topics: Vec::new(),
        };
        client.send(Body::Hello(hello)).await?;
        match client.receive().await? {
            Some(Body::HelloAck(ack)) => {
                client.ack = *ack;
                Ok(client)
            }
            Some(Body::Reject(diagnostic)) => Err(ClientError::Rejected(Box::new(diagnostic))),
            // A close with no `Reject` is the failure §11.7 forbids. Reported as
            // unavailable rather than as a protocol fault, because from the
            // caller's side it is indistinguishable and exit 3 is the honest
            // answer.
            None => Err(ClientError::Unavailable),
            Some(_) => Err(ClientError::UnexpectedBody),
        }
    }

    /// The agent's `HelloAck`. **MI-C3: used verbatim, never reconstructed.**
    #[must_use]
    pub const fn hello_ack(&self) -> &HelloAck {
        &self.ack
    }

    /// Runs one operation.
    ///
    /// # Errors
    ///
    /// [`ClientError`]. A `Response` carrying `ok == false` is **not** an error
    /// here: it is a successful round trip whose result is a refusal, and the
    /// caller renders the diagnostic and exits 1. Collapsing the two would make
    /// "the agent said no" indistinguishable from "the agent is not there".
    pub async fn request(
        &mut self,
        operation: &str,
        params: Vec<u8>,
    ) -> Result<Response, ClientError> {
        self.send(Body::Request(Request {
            operation: operation.to_owned(),
            params,
            if_version: None,
        }))
        .await?;
        loop {
            match self.receive().await? {
                Some(Body::Response(response)) => return Ok(response),
                // An event may arrive between the request and its response; it is
                // not this call's answer and it is not an error.
                Some(Body::Event(_) | Body::Compacted(_)) => {}
                Some(Body::Reject(diagnostic)) => {
                    return Err(ClientError::Rejected(Box::new(diagnostic)))
                }
                None => return Err(ClientError::Unavailable),
                Some(_) => return Err(ClientError::UnexpectedBody),
            }
        }
    }

    /// Closes the connection politely.
    ///
    /// # Errors
    ///
    /// [`ClientError`] if the goodbye could not be written, which the caller may
    /// ignore: the connection is going away either way.
    pub async fn goodbye(&mut self) -> Result<(), ClientError> {
        self.send(Body::Goodbye).await
    }

    async fn send(&mut self, body: Body) -> Result<(), ClientError> {
        use tokio::io::AsyncWriteExt as _;
        debug_assert!(
            body.is_client_originated(),
            "MI-3: a client may not send this body"
        );
        // **MI-2: unique per emission.** A retry of a logically identical request
        // is a new `request_id` and the SAME `idempotency_key`; conflating the two
        // is how a retried ceremony becomes a second ceremony.
        let request_id = self.next_request.to_be_bytes().to_vec();
        self.next_request += 1;
        let envelope = MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id,
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body,
        };
        let bytes = codec::encode_frame(&envelope)?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|_| ClientError::Unavailable)?;
        self.stream
            .flush()
            .await
            .map_err(|_| ClientError::Unavailable)
    }

    async fn receive(&mut self) -> Result<Option<Body>, ClientError> {
        Ok(codec::read_frame(&mut self.stream).await?.map(|e| e.body))
    }
}

/// The `HelloAck` a client holds before the real one arrives.
///
/// Never observable: [`Client::attach`] replaces it before it returns, and it
/// returns `Err` on every path that would leave it in place. Present because the
/// alternative is an `Option` every caller unwraps.
fn placeholder_ack() -> HelloAck {
    HelloAck {
        mi_version: MI_VERSION,
        agent_version: String::new(),
        build_profile: String::new(),
        granted_scopes: Vec::new(),
        withheld_scopes: Vec::new(),
        catalogue_digest: String::new(),
        event_cursor: 0,
        protocol_epoch_range: [1, 1],
        platform_ctx: crate::wire::PlatformCtx {
            platform: String::new(),
            os_version: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic(code: &str) -> Box<Diagnostic> {
        Box::new(Diagnostic {
            reason_code: code.to_owned(),
            class: "FATAL".to_owned(),
            severity: "ERROR".to_owned(),
            user_actionable: true,
            terminal: true,
            remediation_class: String::new(),
            scope: String::new(),
            doc_anchor: String::new(),
            summary_key: None,
            next_action_key: None,
            evidence: serde_json::Value::Null,
        })
    }

    #[test]
    fn every_exit_code_is_in_adr_0017_11_12s_range_and_never_64_or_above() {
        // 64+ is prohibited: it collides with `sysexits.h` and with the shell's
        // own 124/125/126/127 and 128+n.
        let cases = [
            ClientError::Unavailable,
            ClientError::Rejected(diagnostic("PROTO.VERSION_UNSUPPORTED")),
            ClientError::Rejected(diagnostic("PLATFORM.ADAPTER_UNAVAILABLE")),
            ClientError::Rejected(diagnostic("MGMT.UNAVAILABLE")),
            ClientError::Frame(FrameError::TooLarge { declared: 0 }),
            ClientError::UnexpectedBody,
        ];
        for case in &cases {
            let code = case.exit_code();
            assert!((1..=5).contains(&code), "{case:?} exited {code}");
        }
    }

    #[test]
    fn the_channel_being_absent_is_a_different_exit_code_from_a_refusal() {
        // §11.12: "'the service isn't running' and 'the operation was refused'
        // demand different automation responses."
        assert_eq!(ClientError::Unavailable.exit_code(), 3);
        assert_eq!(
            ClientError::Rejected(diagnostic("MGMT.UNAVAILABLE")).exit_code(),
            1
        );
    }

    #[test]
    fn a_version_mismatch_and_an_authorization_refusal_are_told_apart() {
        // "so a script can tell 're-run with privilege' from 'this will never
        // work'", and so an installer's post-install script can act on 5.
        assert_eq!(
            ClientError::Rejected(diagnostic("PROTO.VERSION_UNSUPPORTED")).exit_code(),
            5
        );
        assert_eq!(
            ClientError::Rejected(diagnostic("PLATFORM.PRIV_HELPER_UNTRUSTED")).exit_code(),
            4
        );
    }

    #[test]
    fn the_exit_code_is_derived_from_the_domain_so_a_new_code_lands_correctly() {
        // A code registered tomorrow must reach the right bucket without a client
        // change, which is why this switches on the DOMAIN and not on a list of
        // individual codes.
        assert_eq!(
            ClientError::Rejected(diagnostic("PLATFORM.SOMETHING_NEW")).exit_code(),
            4
        );
        assert_eq!(
            ClientError::Rejected(diagnostic("PROTO.SOMETHING_NEW")).exit_code(),
            5
        );
    }

    #[test]
    fn a_placeholder_ack_carries_nothing_a_caller_could_act_on() {
        // It must never be observable, and if it somehow were, it must grant
        // nothing and claim nothing.
        let ack = placeholder_ack();
        assert!(ack.granted_scopes.is_empty());
        assert!(ack.catalogue_digest.is_empty());
        assert!(ack.platform_ctx.platform.is_empty());
    }
}
