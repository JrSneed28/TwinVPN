//! Rung 1 of the ADR-0002 §11.2 ladder: QUIC + TLS 1.3, mutual
//! raw-public-key authentication, **0-RTT unreachable**.
//!
//! **Authority:** ADR-0001 §11 item 3 (L-CONTROL is "QUIC + TLS 1.3 with mutual
//! raw-public-key auth and per-message `DeviceIdentityKey` signatures, **0-RTT
//! prohibited**"), ADR-0002 §11.2 and N-1/N-2, `ownership.md` §8 **W-12**,
//! RFC 7250 (raw public keys), RFC 9266 (`tls-exporter`), ADR-0010 R1.
//!
//! # What W-12 lets this crate declare, and what it does not
//!
//! W-12 splits the stack by what is actually cryptographic: **`rustls` — the
//! TLS implementation, the raw-public-key verifier, the cipher-suite policy, the
//! `CryptoProvider` — belongs to `twinvpn-crypto`**, and `quinn` is "a transport
//! protocol implementation … that takes its cryptography from rustls and
//! implements none itself".
//!
//! This server is a **separate artifact** with its own transport to terminate.
//! The integration lead's ruling scopes CD-I2 to the `/core` crate set, so these
//! server artifacts may terminate TLS; the resolution here is stated rather than
//! worked around:
//!
//! - `Cargo.toml` declares `quinn` and **not** `rustls`. `quinn` re-exports the
//!   `rustls` types its own feature selection compiled (`rustls-ring`), so this
//!   module names `quinn::rustls::…` and never introduces a second
//!   `CryptoProvider`. Naming `rustls` directly would activate its default
//!   `aws-lc-rs` feature alongside quinn's `ring` and give one artifact two
//!   providers — ADR-0018 **DP-8**'s bound violated through a feature flag
//!   rather than a dependency line, with no line to review.
//! - The **server's** TLS material and the **client's** raw-public-key verifier
//!   are supplied through [`TlsMaterial`] and [`PeerIdentityVerifier`], the same
//!   shape `twinvpn-cp-client` uses for its own binding. What this crate owns is
//!   the *policy*: TLS 1.3 only, ALPN, `max_early_data_size = 0`, the exporter
//!   label, and the refusal to serve without a client identity.
//!
//! # 0-RTT is unreachable, not merely off
//!
//! Three places, and each would have to be defeated separately:
//!
//! 1. [`ControlPlaneConfig::load`](crate::config::ControlPlaneConfig::load)
//!    refuses to start when `TWINVPN_CP_QUIC_ZERO_RTT` parses as `true`, and
//!    refuses a value that parses as neither.
//! 2. [`server_config`] sets `max_early_data_size = 0` on the rustls config.
//! 3. [`accept`] never calls `into_0rtt`. A replayed early-data C1 request is a
//!    **replayed ceremony**, and that is the whole reason ADR-0001 R8 forbids it.
//!
//! # IPv4, IPv6, dual stack, IPv6-only
//!
//! ADR-0010 R1: there is no "v4 story and a v6 story". [`bind`] binds `[::]` and
//! **does not** set `IPV6_V6ONLY`, so one socket serves both families on a
//! dual-stack host and the same code serves an IPv6-only host unchanged. A
//! v4-only host binds `0.0.0.0` and nothing else differs.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use quinn::rustls;
use twinvpn_service_common::ServiceError;

use crate::codes;

/// The ALPN identifier for the TwinVPN control channel.
///
/// ADR-0002 §11.2 puts rung 1 on UDP:443, where other protocols also live. ALPN
/// is what stops a QUIC client speaking something else from reaching this
/// handler at all.
pub const ALPN: &[u8] = b"twinvpn-c1/1";

/// The RFC 9266 exporter label. 32 bytes, empty context.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// `limits.json identifiers.channel_binding_bytes`.
pub const CHANNEL_BINDING_BYTES: usize = 32;

/// The server's TLS key material, supplied at construction.
///
/// **An integration item.** `README.md` §7 records what a composition root must
/// bind; this crate takes the finished `rustls` types so the key parsing and the
/// certified-key construction stay in one place rather than in six services.
pub struct TlsMaterial {
    /// The server's certificate chain, or a single raw-public-key certificate.
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// The matching private key.
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl std::fmt::Debug for TlsMaterial {
    /// The chain length only. A `Debug` that rendered the key would put private
    /// material in a log line, which `ownership.md` §6 rule 11 forbids
    /// absolutely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TlsMaterial({} certs, <key not rendered>)",
            self.chain.len()
        )
    }
}

/// Maps a client's presented key material to a `DeviceIdentity`.
///
/// **An integration item**, and the security-critical half of mutual
/// authentication. An implementation MUST:
///
/// - accept **only** RFC 7250 raw public keys or the pinned certificate profile
///   ADR-0007 fixes, never a general PKI chain;
/// - derive `device_id` as `identity.proto` defines it — the control plane
///   **echoes** a `device_id`, it never assigns one, so the value this returns
///   must be *derived from the key*, not looked up in this service's own tables;
/// - refuse a key it does not recognise with `CONTROL.HANDSHAKE_REJECTED`.
pub trait PeerIdentityVerifier: Send + Sync {
    /// The `device_id` this client's key belongs to.
    ///
    /// # Errors
    ///
    /// [`ServiceError`] with `CONTROL.HANDSHAKE_REJECTED` for an unknown or
    /// revoked key, or a pin mismatch.
    fn identify(
        &self,
        peer_key: &[rustls::pki_types::CertificateDer<'static>],
    ) -> Result<[u8; 32], ServiceError>;
}

/// The verifier this build ships: it identifies nobody.
///
/// Fail closed, for the same reason [`crate::verify::RefuseUnverifiable`] is:
/// a control plane that admitted an unidentified peer would be serving C1 to
/// anyone who could reach UDP:443, and every `ctx.caller` check in
/// [`crate::domain`] would be checking a value an attacker chose.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseUnidentified;

impl PeerIdentityVerifier for RefuseUnidentified {
    fn identify(
        &self,
        _peer_key: &[rustls::pki_types::CertificateDer<'static>],
    ) -> Result<[u8; 32], ServiceError> {
        Err(codes::bare(
            twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
        ))
    }
}

/// Builds the rung-1 server configuration.
///
/// # Errors
///
/// `CONTROL.HANDSHAKE_REJECTED` when the supplied material does not produce a
/// usable TLS configuration. The detail stays in `source_detail()` for a log
/// line and never reaches the wire (CF-4).
pub fn server_config(
    material: TlsMaterial,
    client_auth: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> Result<quinn::ServerConfig, ServiceError> {
    // TLS 1.3 ONLY. ADR-0001 L-CONTROL names 1.3; offering 1.2 as well would
    // make the version a negotiation an attacker participates in.
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_auth)
        .with_single_cert(material.chain, material.key)
        .map_err(|e| {
            ServiceError::new(
                twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
                crate::COMPONENT,
            )
            .source(e)
            .build()
        })?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    // 0-RTT, control 2 of 3. rustls only offers early data when this is
    // non-zero; setting it to zero means a resumed connection has no early-data
    // extension to replay into.
    tls.max_early_data_size = 0;
    tls.send_half_rtt_data = false;

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| {
        ServiceError::new(
            twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
            crate::COMPONENT,
        )
        .source(e)
        .build()
    })?;

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));

    // ADR-0002 §11.10's mobile note: max_idle_timeout 5 min with a PING at
    // 4 min, so the foreground keepalive joins the existing coalesced wake
    // window and adds no wake of its own.
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(300))
            .unwrap_or_else(|_| quinn::IdleTimeout::from(quinn::VarInt::from_u32(300_000))),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(240)));

    // §11.6: C2 gets its own stream so an event backlog cannot consume the RPC
    // window. The stream budget is what stops one device opening enough
    // concurrent C1 streams to do the same thing from the other side.
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(64));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(4));
    cfg.transport_config(Arc::new(transport));

    Ok(cfg)
}

/// Binds the rung-1 listener.
///
/// Binding `[::]` **without** `IPV6_V6ONLY` is what makes one socket serve IPv4,
/// IPv6, dual-stack and IPv6-only hosts with no per-family branch. ADR-0010 R1
/// forbids a design in which those are four code paths.
///
/// # Errors
///
/// `CONTROL.UNREACHABLE` carrying the OS error, when the socket cannot be bound.
pub fn bind(
    addr: SocketAddr,
    config: quinn::ServerConfig,
) -> Result<quinn::Endpoint, ServiceError> {
    let socket = UdpSocket::bind(addr).map_err(|e| {
        ServiceError::from_os_error(
            twinvpn_types::codes::CONTROL_UNREACHABLE,
            crate::COMPONENT,
            e,
        )
    })?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| {
        ServiceError::from_os_error(
            twinvpn_types::codes::CONTROL_UNREACHABLE,
            crate::COMPONENT,
            e,
        )
    })
}

/// Completes one handshake **without** 0-RTT.
///
/// 0-RTT, control 3 of 3: `quinn::Incoming` offers `into_0rtt()`, and this
/// function does not call it. Awaiting the `Connecting` future is the 1-RTT
/// path, and there is no configuration that turns it into the other one.
///
/// # Errors
///
/// `CONTROL.HANDSHAKE_REJECTED` when the handshake fails or the peer presented
/// no identity. **A connection with no client certificate is refused**: mutual
/// authentication is what makes `Auth`'s Rule A safe, and serving C1 to an
/// unauthenticated peer would make every `ctx.caller` check meaningless.
pub async fn accept(
    incoming: quinn::Incoming,
    identity: &dyn PeerIdentityVerifier,
) -> Result<(quinn::Connection, [u8; 32]), ServiceError> {
    let connection = incoming.await.map_err(|e| {
        ServiceError::new(
            twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
            crate::COMPONENT,
        )
        .source(e)
        .build()
    })?;

    let peer = connection
        .peer_identity()
        .and_then(|any| {
            any.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .ok_or_else(|| codes::bare(twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED))?;

    let device_id = identity.identify(&peer)?;
    Ok((connection, device_id))
}

/// The RFC 9266 `tls-exporter` value of this connection.
///
/// ADR-0002 N-2: `Auth.channel_binding` MUST be this value, and a receiver MUST
/// reject a mismatch with `CONTROL.CHANNEL_BINDING_MISMATCH`. Computing it from
/// the live connection — rather than trusting a value in the message — is what
/// makes the binding a binding.
///
/// # Errors
///
/// `CONTROL.CHANNEL_BINDING_MISMATCH` when the exporter cannot be read, which
/// means the connection is not in a state where a binding exists.
pub fn channel_binding(connection: &quinn::Connection) -> Result<[u8; 32], ServiceError> {
    let mut out = [0u8; CHANNEL_BINDING_BYTES];
    connection
        .export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| codes::channel_binding_mismatch())?;
    Ok(out)
}

/// Compares a presented `Auth.channel_binding` against this connection's.
///
/// # Errors
///
/// `CONTROL.CHANNEL_BINDING_MISMATCH` — `FATAL`/`CRITICAL`, a **security
/// event**.
pub fn check_channel_binding(expected: &[u8; 32], presented: &[u8]) -> Result<(), ServiceError> {
    // A length mismatch and a value mismatch are the same answer: the value is
    // not this connection's exporter. Reporting them differently would leak the
    // shape of what was expected.
    if presented.len() != CHANNEL_BINDING_BYTES {
        return Err(codes::channel_binding_mismatch());
    }
    // Constant-time-ish: fold every byte rather than short-circuit. `subtle` is
    // not a workspace dependency here (W-2 exempts it in `core/`, not in
    // `services/`), so the fold is written out.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(presented) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(codes::channel_binding_mismatch())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_channel_binding, PeerIdentityVerifier, RefuseUnidentified, ALPN,
        CHANNEL_BINDING_BYTES, EXPORTER_LABEL,
    };

    #[test]
    fn an_unbound_identity_verifier_refuses_every_peer() {
        let err = RefuseUnidentified.identify(&[]).expect_err("fail closed");
        assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
    }

    #[test]
    fn a_channel_binding_mismatch_is_a_critical_security_event() {
        // ADR-0002 N-2 / §11.11: FATAL, CRITICAL, terminal.
        let expected = [7u8; 32];
        assert!(check_channel_binding(&expected, &[7u8; 32]).is_ok());
        let err = check_channel_binding(&expected, &[8u8; 32]).expect_err("mismatch");
        assert_eq!(err.code().as_str(), "CONTROL.CHANNEL_BINDING_MISMATCH");
        assert!(err.code().terminal());
        assert_eq!(
            err.code().severity(),
            twinvpn_types::ErrorSeverity::Critical
        );
    }

    #[test]
    fn a_short_or_long_binding_is_refused_the_same_way() {
        let expected = [7u8; 32];
        for wrong in [vec![7u8; 31], vec![7u8; 33], Vec::new()] {
            let err = check_channel_binding(&expected, &wrong).expect_err("wrong width");
            assert_eq!(err.code().as_str(), "CONTROL.CHANNEL_BINDING_MISMATCH");
        }
    }

    #[test]
    fn the_binding_is_rfc_9266_shaped() {
        assert_eq!(CHANNEL_BINDING_BYTES, 32);
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-Channel-Binding");
        assert!(
            twinvpn_schema::limits::LIMITS_JSON.contains("\"channel_binding_bytes\": 32"),
            "the frozen width moved"
        );
    }

    #[test]
    fn the_alpn_names_this_protocol_and_nothing_else() {
        // Rung 1 shares UDP:443 with whatever else an operator runs there.
        assert_eq!(ALPN, b"twinvpn-c1/1");
    }

    #[test]
    fn nothing_in_this_module_calls_into_0rtt() {
        // Control 3 of 3, asserted rather than reviewed. `into_0rtt` is the ONE
        // quinn call that would turn the 1-RTT accept path into the replayable
        // one, and ADR-0001 R8 forbids it: a replayed early-data C1 request is a
        // replayed CEREMONY.
        // Only the shipped half of the file: this test names `into_0rtt` in
        // order to look for it, and would otherwise find itself.
        let source = include_str!("quic.rs");
        let shipped = source
            .split("#[cfg(test)]")
            .next()
            .expect("the module has a body");
        let calls: Vec<&str> = shipped
            .lines()
            .filter(|l| l.contains("into_0rtt") && !l.trim_start().starts_with("//"))
            .collect();
        assert!(calls.is_empty(), "0-RTT reachable from: {calls:?}");
    }
}
