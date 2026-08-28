//! **Rung 1 of the ADR-0002 §11.2 ladder, as a production binding**: QUIC +
//! TLS 1.3, mutual RFC 7250 raw-public-key authentication, server keys pinned,
//! **0-RTT unreachable**.
//!
//! **Authority:** ADR-0001 §11 item 3 (L-CONTROL is "QUIC + TLS 1.3 with mutual
//! raw-public-key auth and per-message `DeviceIdentityKey` signatures, **0-RTT
//! prohibited**") and **R8**, ADR-0002 §11.2 (the ladder), **N-1** (one
//! connection per device carrying both C1 and C2), **N-2** (the RFC 9266
//! `tls-exporter` channel binding), §11.7 (reconnect discipline), §11.10 (the
//! mobile rule), ADR-0010 **R1**, `docs/protocol.md` §4.1 (Happy Eyeballs v2
//! with a 250 ms IPv6 bias), `ownership.md` §8 **W-12**.
//!
//! # What this closes
//!
//! `twinvpn-core`'s `cp_binding.rs` states the blocker in terms: *"the composed
//! core has no L-CONTROL transport"*, and `shells/linux/twinvpnd`'s agent server
//! refuses all five C1-mapping operations because of it. No device could speak
//! to the control plane.
//!
//! W-12 is what makes this module legal here, and it is worth restating because
//! the manifest looks wrong otherwise. CD-I2 permits a cryptographic dependency
//! only in `twinvpn-crypto`. W-12 splits the stack by what is actually
//! cryptographic: `rustls` — the TLS implementation, the raw-public-key
//! verifier, the cipher-suite policy, the `CryptoProvider` — is `twinvpn-crypto`'s,
//! and `quinn` is "a transport protocol implementation … that takes its
//! cryptography from rustls and implements none itself", so this crate may
//! declare it. `Cargo.toml` therefore names `quinn` and **never** `rustls`, and
//! every rustls type below is spelled `quinn::rustls::…` — naming the crate
//! directly would activate its default `aws-lc-rs` alongside quinn's `ring` and
//! put two `CryptoProvider`s in one artifact, which is ADR-0018 DP-8's bound
//! broken through a feature flag rather than a dependency line.
//!
//! `twinvpn-crypto` ships no TLS module yet, so the half W-12 assigns to it is
//! present here as a **seam rather than an implementation**: the private key
//! never appears — [`DeviceIdentity`] holds a signer *capability* — and the
//! server side is byte-equality pinning, which is not cryptography. The day
//! `twinvpn-crypto` vends a configured provider, this module takes it instead of
//! building one, and nothing else moves.
//!
//! # 0-RTT is unreachable, not merely off
//!
//! Three independent controls, mirroring the three the server keeps:
//!
//! 1. **No configuration expresses it.** [`crate::transport::EarlyData`] has one
//!    variant and no `Permitted`; [`crate::transport::TransportConfig`] carries
//!    one and has no setter. [`QuicControlTransport::attach`] reads it and
//!    refuses anything else — a branch that is currently uninhabitable and
//!    exists so that widening the enum fails here rather than silently enabling
//!    early data.
//! 2. **The TLS config sets `enable_early_data = false` explicitly.** It is the
//!    rustls default; it is written anyway, because "we left the default alone"
//!    is not a property and a future rustls default is not ours to rely on. This
//!    is the client-side counterpart of the server's `max_early_data_size = 0`.
//! 3. **`into_0rtt` is never called.** Awaiting the `Connecting` future is the
//!    1-RTT path, and there is no configuration that turns it into the other
//!    one. `nothing_in_this_module_can_reach_0_rtt` asserts it over the source.
//!
//! ADR-0002 §S-5 says what this buys: it "removes the replayable-early-data
//! vector entirely", because a replayed early-data C1 request is a replayed
//! **ceremony**.
//!
//! # What a composition root must supply
//!
//! | Argument | Source |
//! |---|---|
//! | [`DeviceIdentity`] | the enrolled `DeviceIdentityKey` — its SPKI, and a signer the platform element backs (CB-5 / I4) |
//! | [`ServerPins`] | the **enrolment record** (ADR-0001 §7.2). There is no learn-on-first-use and no variant for one |
//! | [`ControlEndpoint`] | the bootstrap-scope resolution of each coordination name (ADR-0011 DN-0). Resolution is a platform call under CB-1 |
//! | [`Nat64Prefix`] | PREF64 / RFC 7050 discovery, where the host has one |
//! | [`twinvpn_env::Env`] | CD-2. Every timer here is [`twinvpn_env::Timer`]; nothing reads an ambient clock |

mod attach;
pub mod candidates;
pub mod connection;
pub mod identity;
mod verify;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use quinn::rustls;
use twinvpn_env::Env;

use crate::error::CpError;
use crate::transport::{
    ControlConnection, ControlTransport, EarlyData, Rung, TransportConfig, TransportError,
};

pub use candidates::{ControlEndpoint, Nat64Prefix};
pub use connection::{QuicConnection, QuicEventStream, C1_HEADER_BYTES, C2_HEADER_BYTES};
pub use identity::{DeviceIdentity, ServerPins};

/// The ALPN identifier for the TwinVPN control channel.
///
/// RFC 9001 §8.1 makes ALPN mandatory for QUIC, and rung 1 shares UDP:443 with
/// whatever else an operator runs there. Must equal the server's
/// `services/control-plane/src/quic.rs::ALPN`.
pub const ALPN: &[u8] = b"twinvpn-c1/1";

/// The RFC 9266 `tls-exporter` label. Must equal the server's.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The exporter context: **empty**, per RFC 9266 §3.
pub const EXPORTER_CONTEXT: &[u8] = b"";

/// The QUIC idle timeout, and the keepalive under it.
///
/// ADR-0002 §11.10's mobile note fixes both: `max_idle_timeout` 5 min with a
/// PING at 4 min, so a foreground keepalive joins the existing coalesced wake
/// window (`reliability.md` §6.6) and adds **no** wake of its own. The server
/// sets the same pair.
const IDLE_TIMEOUT_SECS: u64 = 300;
const KEEPALIVE_SECS: u64 = 240;

/// This crate's `CryptoProvider`: quinn's own `ring`, and no second one.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Post-handshake QUIC failures, as this crate reports them.
///
/// Everything here is "the connection went away mid-stream", which the cursor
/// resumes. The handshake's own failures are mapped separately in
/// [`map_handshake_error`], because a refusal and a black hole need different
/// responses from an operator and flattening them loses that.
fn map_connection_error(_err: &quinn::ConnectionError) -> TransportError {
    TransportError::Closed
}

/// The live connection this transport is holding, for ADR-0002 N-1.
struct Live {
    superseded: Arc<AtomicBool>,
    connection: quinn::Connection,
}

/// A production QUIC L-CONTROL transport.
///
/// Rung 1 only, and it says so rather than quietly serving rung-2 traffic over
/// QUIC — which would make a ladder test measure nothing. The composition root
/// stacks it under whatever it binds for rungs 2 to 4.
pub struct QuicControlTransport {
    env: Env,
    endpoints: Vec<ControlEndpoint>,
    nat64: Option<Nat64Prefix>,
    crypto: Arc<quinn::crypto::rustls::QuicClientConfig>,
    live: Mutex<Option<Live>>,
}

impl core::fmt::Debug for QuicControlTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicControlTransport")
            .field("rung", &Rung::Quic)
            .field("endpoints", &self.endpoints.len())
            .field("nat64", &self.nat64.is_some())
            .field("early_data", &EarlyData::Prohibited)
            // `crypto` holds the client certificate resolver, which holds the
            // signer. There is nothing to render there that is safe to log,
            // and `ownership.md` §6 rule 11 is absolute.
            .finish_non_exhaustive()
    }
}

impl QuicControlTransport {
    /// Builds the transport.
    ///
    /// # Errors
    ///
    /// [`CpError::HandshakeRejected`] when the identity or the pin set cannot
    /// produce a usable TLS configuration, and [`CpError::Unreachable`] when no
    /// endpoint was supplied. Both are decided here rather than once per
    /// attach: a configuration that can never complete a handshake should fail
    /// before a socket is bound.
    pub fn new(
        env: Env,
        identity: &DeviceIdentity,
        pins: ServerPins,
        endpoints: Vec<ControlEndpoint>,
        nat64: Option<Nat64Prefix>,
    ) -> Result<Self, CpError> {
        if endpoints.is_empty() {
            return Err(CpError::Unreachable);
        }
        let provider = provider();
        let verifier =
            verify::PinnedServerKey::new(pins, provider.signature_verification_algorithms);

        // TLS 1.3 ONLY. ADR-0001 names 1.3; offering 1.2 as well would make the
        // version a negotiation an attacker participates in — and the
        // `tls-exporter` binding N-2 depends on is a 1.3 property, so a 1.2
        // fallback would not weaken the channel binding, it would silently
        // REMOVE it.
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| CpError::HandshakeRejected)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(identity.certified_key()),
            ));
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // 0-RTT, control 2 of 3. See the module docs.
        tls.enable_early_data = false;

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|_| CpError::HandshakeRejected)?;

        Ok(Self {
            env,
            endpoints,
            nat64,
            crypto: Arc::new(crypto),
            live: Mutex::new(None),
        })
    }

    /// The QUIC transport parameters for one attach.
    ///
    /// The only thing `mobile_background` changes is the keepalive. ADR-0002
    /// §11.10: in background "the control connection is **allowed to die**;
    /// re-attach on wake is cheaper than holding it", so a PING every four
    /// minutes there would buy nothing and cost a radio wake per interval —
    /// the same honest conclusion `reliability.md` §6.6 reaches for NAT
    /// keepalives.
    fn quinn_transport(mobile_background: bool) -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            u32::try_from(IDLE_TIMEOUT_SECS * 1_000).unwrap_or(u32::MAX),
        ))));
        transport.keep_alive_interval(if mobile_background {
            None
        } else {
            Some(core::time::Duration::from_secs(KEEPALIVE_SECS))
        });
        // What the SERVER may open toward us. C2 is one unidirectional stream
        // (§11.6, and `serve.rs`'s `spawn_c2` calls `open_uni`); the control
        // plane opens no bidirectional stream at all, so a bound of zero makes
        // an unexpected one a visible failure rather than an unbounded
        // resource. Our own `open_bi` for C1 is unaffected — this limit is the
        // peer's, not ours.
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(4));
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(0));
        transport
    }

    fn client_config(&self, mobile_background: bool) -> quinn::ClientConfig {
        let mut config = quinn::ClientConfig::new(Arc::clone(&self.crypto) as _);
        config.transport_config(Arc::new(Self::quinn_transport(mobile_background)));
        config
    }
}

impl ControlTransport for QuicControlTransport {
    fn attach<'a>(
        &'a self,
        config: &'a TransportConfig,
    ) -> BoxFuture<'a, Result<Box<dyn ControlConnection>, TransportError>> {
        Box::pin(async move {
            let attached = self.attach_quic(config).await?;
            Ok(Box::new(attached) as Box<dyn ControlConnection>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ALPN, EXPORTER_CONTEXT, EXPORTER_LABEL, IDLE_TIMEOUT_SECS, KEEPALIVE_SECS};

    #[test]
    fn the_alpn_and_exporter_label_match_the_servers() {
        // Copied constants, asserted rather than trusted: they are duplicated
        // across an artifact boundary (`services/control-plane/src/quic.rs`),
        // and a mismatch is a handshake that fails with no diagnosis on either
        // side, or a channel binding that silently never matches.
        assert_eq!(ALPN, b"twinvpn-c1/1");
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-Channel-Binding");
        assert_eq!(EXPORTER_CONTEXT, b"", "RFC 9266 §3: an empty context");
        assert_eq!(
            twinvpn_types::ChannelBinding::WIDTH,
            32,
            "limits.json identifiers.channel_binding_bytes"
        );
    }

    #[test]
    fn the_keepalive_sits_under_the_idle_timeout() {
        // ADR-0002 §11.10: max_idle_timeout 5 min, PING at 4 min, so the
        // foreground keepalive joins the existing coalesced wake window.
        assert_eq!(IDLE_TIMEOUT_SECS, 300);
        assert_eq!(KEEPALIVE_SECS, 240);
        // A keepalive at or above the idle timeout never fires before the
        // connection is already gone, which is the shape of a keepalive that
        // silently does nothing.
        assert_eq!(KEEPALIVE_SECS.min(IDLE_TIMEOUT_SECS), KEEPALIVE_SECS);
    }

    #[test]
    fn nothing_in_this_module_can_reach_0_rtt() {
        // Control 3 of 3, asserted rather than reviewed, exactly as the server
        // asserts it. `into_0rtt` is the ONE quinn call that would turn the
        // 1-RTT connect path into the replayable one, and ADR-0001 R8 forbids
        // it: a replayed early-data C1 request is a replayed CEREMONY.
        //
        // Only the shipped half of each file: this test names `into_0rtt` in
        // order to look for it, and would otherwise find itself.
        for (name, source) in [
            ("quic/mod.rs", include_str!("mod.rs")),
            ("quic/attach.rs", include_str!("attach.rs")),
            ("quic/connection.rs", include_str!("connection.rs")),
            ("quic/identity.rs", include_str!("identity.rs")),
            ("quic/candidates.rs", include_str!("candidates.rs")),
            ("quic/verify.rs", include_str!("verify.rs")),
        ] {
            let shipped = source.split("#[cfg(test)]").next().unwrap_or(source);
            let calls: Vec<&str> = shipped
                .lines()
                .filter(|line| line.contains("into_0rtt") && !line.trim_start().starts_with("//"))
                .collect();
            assert!(calls.is_empty(), "0-RTT reachable from {name}: {calls:?}");
        }
    }

    #[test]
    fn no_file_in_this_module_names_rustls_directly() {
        // CD-I2 / W-12, asserted at the source as well as at the manifest. A
        // `use rustls::…` here would compile only if someone had also added the
        // dependency, and this fires first with the reason attached: naming it
        // activates its default `aws-lc-rs` alongside quinn's `ring` and puts
        // two `CryptoProvider`s in one artifact.
        for (name, source) in [
            ("quic/mod.rs", include_str!("mod.rs")),
            ("quic/attach.rs", include_str!("attach.rs")),
            ("quic/connection.rs", include_str!("connection.rs")),
            ("quic/identity.rs", include_str!("identity.rs")),
            ("quic/verify.rs", include_str!("verify.rs")),
        ] {
            let shipped = source.split("#[cfg(test)]").next().unwrap_or(source);
            for line in shipped.lines() {
                let code = line.trim_start();
                assert!(
                    !code.starts_with("use rustls") && !code.starts_with("extern crate rustls"),
                    "{name} imports rustls as a crate rather than through quinn: {code}"
                );
            }
        }
    }
}
