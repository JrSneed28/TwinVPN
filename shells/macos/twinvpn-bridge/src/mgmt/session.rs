//! One XPC management connection, as a value.
//!
//! **Authority:** ADR-0017 §11.2's macOS row (the XPC carriage), §11.3 (the
//! envelope, "the cap enforced before parse"), §11.7 (the version window),
//! MI-3, MI-S1, MI-S2, MI-A1, MI-A5, MI-20; ADR-0016 §11.14 (a), **PS-22**.
//!
//! # Why this is bytes in, bytes out
//!
//! The socket carriage owns its own stream: [`super::server::serve`] reads
//! frames off a `tokio::net::UnixStream` and writes them back. The XPC carriage
//! cannot, because **XPC's listener is an Objective-C block-based API and the
//! Swift side owns it**. So Swift accepts the connection, copies the
//! `audit_token_t` out of it, and hands this crate one message at a time
//! through the C ABI. This module is what those messages meet.
//!
//! **Swift marshals; it holds no decision (CB-2).** It does not read the
//! envelope, does not know what a scope is, does not decide whether a principal
//! may run an operation, and does not construct a reply. Every one of those is
//! below, in Rust, tested on the Linux host.
//!
//! # The framing is the socket's framing, deliberately
//!
//! XPC preserves message boundaries, so a length prefix inside an XPC message
//! is redundant. It is used anyway, because ADR-0017 §11.2 opens with *"uniform
//! framing means one `MgmtEnvelope` per message in every binding, so a message
//! that is valid on one channel is byte-identical on another"* — and a
//! redundant four bytes is a smaller cost than two carriages whose captures do
//! not compare. The 1 MiB cap is therefore enforced here too, from the prefix,
//! **before the body buffer exists**.
//!
//! # MI-S2, as the shape of the type
//!
//! [`Session`] computes its granted set exactly once, in [`Session::open`] and
//! the `Hello` that follows it, and has no method that widens one. A second
//! `Hello` on an attached session is a direction violation, not a
//! re-negotiation.

use twinvpn_mi::wire::{Body, Diagnostic, MI_VERSION, MI_VERSION_MIN};
use twinvpn_mi::Scopes;

use super::peer::PeerCredentials;
use super::server::{self, ServerContext};

/// Why a session ended, or refused a message.
///
/// The same vocabulary as [`server::Ending`] and deliberately so: a client
/// must not be able to tell which carriage it is on from the way a refusal is
/// spelled.
pub use super::server::Ending;

/// One XPC connection's state.
///
/// Held by the C ABI on behalf of one `xpc_connection_t`. Dropped when Swift
/// closes it.
#[derive(Debug)]
pub struct Session {
    credentials: PeerCredentials,
    granted: Scopes,
    attached: bool,
    /// Set once the session has produced an [`Exchange`] with an `ending`.
    ///
    /// **The latch matters because the ABI cannot close a connection.** Swift
    /// owns the `xpc_connection_t` and CB-2 forbids it deciding *when* to close
    /// one from a domain fact, so `tvb_mgmt_exchange` does not report the
    /// `ending` outward. Without this field a client whose `Hello` was rejected
    /// for a version mismatch could simply send another frame and be served, and
    /// §11.7's rejection would be advice rather than a refusal.
    ///
    /// So the refusal is enforced **here**: every later message on an ended
    /// session gets the same reject, and no path re-opens one. See
    /// `shells/macos/README.md` §7 for what is still missing — the socket
    /// carriage *does* close, and the XPC one leaks an idle connection until
    /// the peer goes away.
    ended: Option<Ending>,
}

/// What one exchange produced.
pub struct Exchange {
    /// The framed envelope to send back. **Always present**: §11.7 forbids a
    /// silent close, "because a silent close is indistinguishable from the
    /// agent not running and sends the user to reinstall rather than to
    /// update".
    pub reply: Vec<u8>,
    /// Whether the connection should be closed after this reply.
    pub ending: Option<Ending>,
}

impl Session {
    /// Opens a session for a principal the kernel named.
    ///
    /// **The credentials are established before the first byte is parsed**, on
    /// this carriage as on the socket: the caller obtains them from the
    /// `audit_token_t` and there is no constructor here that produces an
    /// anonymous principal.
    #[must_use]
    pub fn open(credentials: PeerCredentials) -> Self {
        Self {
            credentials,
            granted: Scopes::empty(),
            attached: false,
            ended: None,
        }
    }

    /// The principal on the other end. For a log line; never for a decision
    /// this module has not already made.
    #[must_use]
    pub const fn credentials(&self) -> &PeerCredentials {
        &self.credentials
    }

    /// Handles one framed envelope and produces the framed answer.
    ///
    /// The cap is applied to the prefix **before the body buffer exists** —
    /// `twinvpn_mgmt::envelope::decode_frame` is the one implementation of that
    /// rule and all three shells use it.
    pub fn exchange(&mut self, frame: &[u8], context: &ServerContext) -> Exchange {
        // An ended session answers the same refusal to everything, forever. It
        // does not re-parse the frame: a session that had already been closed
        // for a framing fault would otherwise let the next frame decide what
        // happened to it.
        if let Some(ending) = self.ended {
            return Exchange {
                reply: server::frame(
                    context,
                    Body::Reject(Diagnostic::of(twinvpn_mgmt::codes::unavailable())),
                ),
                ending: Some(ending),
            };
        }
        let envelope = match twinvpn_mi::codec::decode_frame(frame) {
            Ok(envelope) => envelope,
            Err(error) => {
                return self.close_with(
                    context,
                    Body::Reject(Diagnostic::of(error.reason_code())),
                    Ending::Framing(error),
                )
            }
        };

        match envelope.body {
            Body::Hello(hello) if !self.attached => {
                // §11.7's version negotiation. **Never a silent close**: a
                // rejection the client can read is what separates "update me"
                // from "reinstall me".
                if hello.mi_version_max < MI_VERSION_MIN || hello.mi_version_min > MI_VERSION {
                    let code = if hello.mi_version_max < MI_VERSION_MIN {
                        twinvpn_types::codes::PROTO_VERSION_UNSUPPORTED
                    } else {
                        twinvpn_types::codes::PROTO_VERSION_DEPRECATED
                    };
                    return self.close_with(
                        context,
                        Body::Reject(Diagnostic::of(code)),
                        Ending::VersionMismatch,
                    );
                }
                // **S-44: re-derived at every attach, never cached across
                // attaches.** There is no map from uid to scopes anywhere in
                // this process; the answer comes from the token a moment ago.
                let principal = super::peer::scopes_for(&self.credentials, context.policy);
                let (granted, withheld) = principal.grant(&hello.requested_scopes);
                let ack = server::hello_ack(&hello, &granted, withheld, context);
                self.granted = granted;
                self.attached = true;
                Self::reply(context, Body::HelloAck(Box::new(ack)))
            }
            Body::Request(request) if self.attached => {
                let response = server::handle(&request, &self.granted, &self.credentials, context);
                Self::reply(context, Body::Response(response))
            }
            Body::Goodbye => self.close_with(
                context,
                Body::Response(server::goodbye_response()),
                Ending::Closed,
            ),
            // MI-3, enforced on the receiving side, plus §11.7's ordering: a
            // `Request` before `Hello` and a second `Hello` after it are both
            // this. A client may never send a `Response`, an `Event` or a
            // `Reject` at all.
            _ => self.close_with(
                context,
                Body::Reject(Diagnostic::of(
                    twinvpn_types::codes::PROTO_MALFORMED_MESSAGE,
                )),
                Ending::DirectionViolation,
            ),
        }
    }

    fn reply(context: &ServerContext, body: Body) -> Exchange {
        Exchange {
            reply: server::frame(context, body),
            ending: None,
        }
    }

    /// Answers, and latches the session closed.
    fn close_with(&mut self, context: &ServerContext, body: Body, ending: Ending) -> Exchange {
        self.ended = Some(ending);
        Exchange {
            reply: server::frame(context, body),
            ending: Some(ending),
        }
    }
}

/// A [`Session`] behind a lock, for the C ABI to own.
///
/// The ABI hands out `*mut tvb_session` and the caller may — XPC being what it
/// is — deliver two messages on one connection from two queues. `exchange`
/// therefore takes `&self` and serialises: **one connection is one conversation
/// and its messages are ordered**, which is also what makes MI-S2's
/// "computed once at attach" true rather than racy.
#[derive(Debug)]
pub struct SessionHandle {
    inner: std::sync::Mutex<Session>,
}

impl SessionHandle {
    /// Opens a session for a principal the kernel named.
    #[must_use]
    pub fn new(credentials: PeerCredentials) -> Self {
        Self {
            inner: std::sync::Mutex::new(Session::open(credentials)),
        }
    }

    /// One message in, one framed answer out.
    ///
    /// A **poisoned** lock means a panic happened inside a previous exchange on
    /// this connection. The session's state is then unknowable, so the answer is
    /// a refusal rather than a best guess: `INTERNAL.CORE_PANIC` is what F-7
    /// already reports for the same event at the ABI boundary.
    pub fn exchange(&self, frame: &[u8], context: &ServerContext) -> Exchange {
        match self.inner.lock() {
            Ok(mut session) => session.exchange(frame, context),
            Err(_) => Exchange {
                reply: server::frame(
                    context,
                    Body::Reject(Diagnostic::of(twinvpn_types::codes::INTERNAL_CORE_PANIC)),
                ),
                ending: Some(Ending::Closed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_mi::wire::{Hello, MgmtEnvelope, Request};

    fn hello(scopes: &[&str]) -> Vec<u8> {
        framed(Body::Hello(Hello {
            mi_version_min: MI_VERSION_MIN,
            mi_version_max: MI_VERSION,
            client_kind: "app".to_owned(),
            client_version: "0.1.0".to_owned(),
            requested_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            subscribe_topics: Vec::new(),
        }))
    }

    fn request(operation: &str) -> Vec<u8> {
        framed(Body::Request(Request {
            operation: operation.to_owned(),
            params: Vec::new(),
            if_version: None,
        }))
    }

    fn framed(body: Body) -> Vec<u8> {
        twinvpn_mi::codec::encode_frame(&MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![1],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body,
        })
        .expect("encodes")
    }

    fn body_of(frame: &[u8]) -> Body {
        twinvpn_mi::codec::decode_frame(frame)
            .expect("decodes")
            .body
    }

    fn admin() -> PeerCredentials {
        PeerCredentials {
            uid: 503,
            groups: vec![402],
            groups_possibly_truncated: true,
        }
    }

    #[test]
    fn a_request_before_hello_is_a_direction_violation_and_never_answered() {
        // §11.7's ordering rule. A carriage that answered a request from an
        // unattached client would have granted a scope set nobody negotiated.
        let context = server::testing::context();
        let mut session = Session::open(admin());
        let exchange = session.exchange(&request("status.get"), &context);
        assert_eq!(exchange.ending, Some(Ending::DirectionViolation));
        assert!(matches!(body_of(&exchange.reply), Body::Reject(_)));
    }

    #[test]
    fn a_second_hello_is_a_direction_violation_and_not_a_renegotiation() {
        // MI-S2: the granted set is computed once, at attach, and there is no
        // scope-escalation message for a wider one to arrive on.
        let context = server::testing::context();
        let mut session = Session::open(admin());
        assert!(session
            .exchange(&hello(&["mgmt.status"]), &context)
            .ending
            .is_none());
        let second = session.exchange(&hello(&["mgmt.admin"]), &context);
        assert_eq!(second.ending, Some(Ending::DirectionViolation));
    }

    #[test]
    fn the_attach_grants_the_intersection_and_names_what_it_withheld() {
        let context = server::testing::context();
        let mut session = Session::open(PeerCredentials {
            uid: 501,
            groups: vec![400],
            groups_possibly_truncated: true,
        });
        let exchange = session.exchange(&hello(&["mgmt.status", "mgmt.admin"]), &context);
        assert_eq!(exchange.ending, None);
        let Body::HelloAck(ack) = body_of(&exchange.reply) else {
            panic!("an ack");
        };
        assert!(ack.granted_scopes.contains(&"mgmt.status".to_owned()));
        assert_eq!(ack.withheld_scopes, vec!["mgmt.admin".to_owned()]);
    }

    #[test]
    fn an_over_cap_prefix_is_refused_from_the_prefix_alone_on_this_carriage_too() {
        // The cap is §11.3's and it is enforced before the body buffer exists.
        // XPC preserving message boundaries does not make an unbounded
        // allocation safe: the LENGTH is still attacker-supplied.
        let context = server::testing::context();
        let mut session = Session::open(admin());
        let exchange = session.exchange(&u32::MAX.to_be_bytes(), &context);
        assert!(matches!(exchange.ending, Some(Ending::Framing(_))));
        assert!(matches!(body_of(&exchange.reply), Body::Reject(_)));
    }

    #[test]
    fn a_version_window_that_does_not_overlap_is_rejected_and_never_closed_silently() {
        let context = server::testing::context();
        let mut session = Session::open(admin());
        let stale = framed(Body::Hello(Hello {
            mi_version_min: 0,
            mi_version_max: MI_VERSION_MIN.saturating_sub(1),
            client_kind: "app".to_owned(),
            client_version: "0.0.1".to_owned(),
            requested_scopes: Vec::new(),
            subscribe_topics: Vec::new(),
        }));
        let exchange = session.exchange(&stale, &context);
        assert_eq!(exchange.ending, Some(Ending::VersionMismatch));
        let Body::Reject(diagnostic) = body_of(&exchange.reply) else {
            panic!("a reject the client can read");
        };
        assert_eq!(diagnostic.reason_code, "PROTO.VERSION_UNSUPPORTED");
    }

    #[test]
    fn an_attached_session_answers_a_request_the_catalogue_authorises() {
        let context = server::testing::context();
        let mut session = Session::open(PeerCredentials {
            uid: 501,
            groups: vec![400],
            groups_possibly_truncated: true,
        });
        let _ = session.exchange(&hello(&["mgmt.status"]), &context);
        let exchange = session.exchange(&request("status.get"), &context);
        assert_eq!(exchange.ending, None);
        let Body::Response(response) = body_of(&exchange.reply) else {
            panic!("a response");
        };
        assert!(response.ok);
    }

    #[test]
    fn an_ended_session_answers_nothing_else_however_many_times_it_is_asked() {
        // **The latch.** `tvb_mgmt_exchange` cannot close an `xpc_connection_t`
        // — Swift owns it, and CB-2 forbids Swift deciding when to close from a
        // domain fact — so a rejection that did not latch would be advice.
        // A client whose `Hello` was refused for a version mismatch must not be
        // able to follow it with a `Hello` that is accepted.
        let context = server::testing::context();
        let mut session = Session::open(admin());
        let stale = framed(Body::Hello(Hello {
            mi_version_min: 0,
            mi_version_max: MI_VERSION_MIN.saturating_sub(1),
            client_kind: "app".to_owned(),
            client_version: "0.0.1".to_owned(),
            requested_scopes: Vec::new(),
            subscribe_topics: Vec::new(),
        }));
        assert_eq!(
            session.exchange(&stale, &context).ending,
            Some(Ending::VersionMismatch)
        );

        for message in [hello(&["mgmt.status"]), request("status.get")] {
            let exchange = session.exchange(&message, &context);
            assert!(
                exchange.ending.is_some(),
                "an ended session must stay ended"
            );
            let Body::Reject(diagnostic) = body_of(&exchange.reply) else {
                panic!("an ended session answers only rejections");
            };
            assert_eq!(diagnostic.reason_code, "MGMT.UNAVAILABLE");
        }
    }

    #[test]
    fn every_refusal_still_produces_a_frame_the_client_can_read() {
        // §11.7: "**Never** a parse error, never a hang, never a generic
        // failure", and never a silent close. Asserted over every ending this
        // module can produce.
        let context = server::testing::context();
        for message in [
            request("status.get"),
            vec![0, 0, 0, 0],
            framed(Body::Goodbye),
        ] {
            let mut session = Session::open(admin());
            let exchange = session.exchange(&message, &context);
            assert!(
                !exchange.reply.is_empty(),
                "a refusal with no body is a silent close"
            );
            assert!(twinvpn_mi::codec::decode_frame(&exchange.reply).is_ok());
        }
    }
}
