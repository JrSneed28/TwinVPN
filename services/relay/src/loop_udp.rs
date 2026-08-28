//! The `R-UDP` receive loop: the one place in this crate that `.await`s.
//!
//! **Authority:** ADR-0005 §11.1 (forwarding model), §11.5 (amplification).
//!
//! The loop holds **no policy**. It reads a datagram, calls the synchronous
//! [`Pump::step`], and writes at most one datagram. Every decision — parse, leg,
//! bind, MAC, counter, quota, shed — lives in that step, so all of it is testable
//! without a socket and none of it can acquire an `.await` by accident. That
//! split is the same I5 discipline `token::verify` and `RelayEngine` follow, at
//! the one boundary where I/O genuinely has to happen.
//!
//! `now_ms` comes from a caller-supplied `clock` rather than a clock read here
//! (`architecture.md` §5.2 R-DET-1), which is also what lets the loopback tests
//! drive timing deterministically.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::admit::LegSetup;
use crate::crypto::RelayCrypto;
use crate::drr::TwoTierDrr;
use crate::engine::RelayEngine;
use crate::leg::LegRegistry;
use crate::pump::{Action, Pump};

/// The largest datagram the loop reads: header plus the derived payload ceiling.
///
/// A fixed buffer sized from [`crate::frame::MAX_DATA_PAYLOAD_BYTES`] is the
/// allocation bound on the highest-rate path (`ownership.md` §6 rule 10).
/// Anything larger is truncated by the kernel and then fails to parse — a silent
/// drop, which is what ADR-0005 §11.5 wants for a malformed frame anyway.
pub const RECV_BUFFER_BYTES: usize =
    crate::frame::HEADER_LEN + crate::frame::MAX_DATA_PAYLOAD_BYTES;

/// The mutable state one socket loop drives.
///
/// Shared behind a `Mutex` rather than a channel because every operation is a
/// short, non-blocking state transition: [`Pump::step`] does no I/O and never
/// `.await`s, so the lock is never held across a yield point.
pub struct RelayRuntime {
    /// The tables, limits and drain.
    pub engine: RelayEngine,
    /// The established legs, populated by the `Noise_IK` responder in
    /// [`crate::admit`].
    pub legs: LegRegistry,
    /// The two-tier scheduler, on the forwarding path.
    pub scheduler: TwoTierDrr,
    /// The relay's static key, entropy and cookie secret.
    ///
    /// `None` is the fail-closed state of a relay with no static key: it serves,
    /// it reports, and it establishes no leg. Stated as an `Option` rather than
    /// discovered as a runtime error, so `main` can say so once at startup.
    pub setup: Option<Arc<LegSetup>>,
}

impl std::fmt::Debug for RelayRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayRuntime")
            .field("engine", &self.engine)
            .field("legs", &self.legs)
            .finish()
    }
}

/// Reads datagrams from `socket` and drives the pump until `shutdown` completes.
pub async fn serve_udp<F, S>(
    socket: Arc<UdpSocket>,
    runtime: Arc<Mutex<RelayRuntime>>,
    crypto: Arc<dyn RelayCrypto>,
    clock: F,
    shutdown: S,
) where
    F: Fn() -> u64 + Send + 'static,
    S: std::future::Future<Output = ()> + Send,
{
    let mut buf = vec![0_u8; RECV_BUFFER_BYTES];
    tokio::pin!(shutdown);
    loop {
        let received = tokio::select! {
            () = &mut shutdown => return,
            r = socket.recv_from(&mut buf) => r,
        };
        let Ok((len, from)) = received else {
            // A UDP read error is per-datagram (an ICMP error mapped back,
            // typically). It is not a reason to stop serving every other peer.
            continue;
        };

        let now_ms = clock();
        let (action, announcements) = {
            let Ok(mut rt) = runtime.lock() else {
                return;
            };
            let setup = rt.setup.clone();
            let RelayRuntime {
                engine,
                legs,
                scheduler,
                ..
            } = &mut *rt;
            let mut pump = Pump {
                engine,
                legs,
                scheduler,
                crypto: crypto.as_ref(),
                setup: setup.as_deref(),
                last_source: from,
                pending_announcements: Vec::new(),
            };
            let action = pump.step(from, Bytes::copy_from_slice(&buf[..len]), now_ms);
            // The `BOUND` owed to the half-flow that was already waiting
            // (§11.1(4)). Resolved while the lock is held and sent outside it, so
            // the lock is still never held across an `.await`.
            let pending_ttl = pump.engine.config().pending_slot_ttl_ms;
            let announcements: Vec<(SocketAddr, Bytes)> = pump
                .pending_announcements
                .clone()
                .into_iter()
                .filter_map(|(waiting, _)| pump.announcement_datagram(waiting, pending_ttl))
                .collect();
            (action, announcements)
        };

        // At most one datagram, to exactly one peer. `Action` cannot express more.
        if let Action::Send { to, datagram } = action {
            let _ = socket.send_to(&datagram, to).await;
        }
        // Announcements onto already-bound, authenticated flows — the class
        // ADR-0005 §11.5 permits the relay to originate, alongside `DRAIN` and
        // `RELAY_STATUS`. Never a reply to an unauthenticated datagram.
        for (to, datagram) in announcements {
            let _ = socket.send_to(&datagram, to).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::crypto::FailClosed;
    use crate::issuer::IssuerKeySet;
    use twinvpn_service_common::config::MapEnv;

    fn relay_config() -> RelayConfig {
        RelayConfig::load(
            &MapEnv::new()
                .with("TWINVPN_RELAY_ID", "0000000000000a01")
                .with("TWINVPN_RELAY_REGION", "local-1")
                .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
                .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
                .with(
                    "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                )
                .with(
                    "TWINVPN_RELAY_STATIC_KEY_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                ),
        )
        .expect("loads")
    }

    fn empty_issuers() -> IssuerKeySet {
        IssuerKeySet::parse(
            r#"{"operator_group_id":"local-operator","issuers":[]}"#,
            "local-operator",
            "x",
        )
        .expect("parses")
    }

    fn runtime() -> Arc<Mutex<RelayRuntime>> {
        Arc::new(Mutex::new(RelayRuntime {
            engine: RelayEngine::new(relay_config(), empty_issuers(), 0),
            legs: LegRegistry::new(1_024, 1_024, 900_000),
            scheduler: TwoTierDrr::with_default_quantum(),
            setup: None,
        }))
    }

    type Started = (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    );

    async fn start_on(bind: &str) -> Started {
        let socket = Arc::new(UdpSocket::bind(bind).await.expect("relay socket"));
        let addr = socket.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(serve_udp(
            socket,
            runtime(),
            Arc::new(FailClosed),
            || 0,
            async move {
                let _ = rx.await;
            },
        ));
        (addr, tx, handle)
    }

    /// Sends `datagram` to a running relay and waits briefly for any reply.
    async fn probe(bind: &str, relay: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
        let client = UdpSocket::bind(bind).await.expect("client socket");
        client.send_to(datagram, relay).await.expect("send");
        let mut buf = vec![0_u8; RECV_BUFFER_BYTES];
        match tokio::time::timeout(
            std::time::Duration::from_millis(150),
            client.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_real_relay_answers_unsolicited_input_with_zero_bytes() {
        // ADR-0005 §11.5's amplification claim, MEASURED over a real socket
        // rather than argued: the relay "emits ZERO BYTES in response to any
        // unauthenticated or unbound frame".
        let (addr, stop, handle) = start_on("[::1]:0").await;

        for datagram in [
            vec![],
            b"not a relay frame at all".to_vec(),
            // A well-formed DATA frame from a source with no leg.
            vec![
                0x01, 0x10, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3, 0xC3,
            ],
            // A well-formed leg PING from a source with no leg.
            vec![0x12, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // A BIND.
            vec![0x10, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // Oversized: over the derived payload ceiling.
            vec![0xFF; 2_000],
        ] {
            let reply = probe("[::1]:0", addr, &datagram).await;
            assert!(
                reply.is_none(),
                "the relay answered {} bytes of unsolicited input with {:?} bytes",
                datagram.len(),
                reply.map(|r| r.len())
            );
        }

        let _ = stop.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn the_loop_survives_a_flood_and_still_stops_cleanly() {
        let (addr, stop, handle) = start_on("[::1]:0").await;
        let client = UdpSocket::bind("[::1]:0").await.expect("client");
        for n in 0..200_u16 {
            let mut junk = vec![0_u8; 64];
            junk[0] = u8::try_from(n % 251).unwrap_or(0);
            let _ = client.send_to(&junk, addr).await;
        }
        let mut buf = [0_u8; 64];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                client.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "the relay answered a garbage flood"
        );

        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("the loop stops on its shutdown future")
            .expect("no panic");
    }

    #[tokio::test]
    async fn the_loop_runs_on_ipv4_as_well_as_ipv6() {
        let (addr, stop, handle) = start_on("127.0.0.1:0").await;
        assert!(addr.is_ipv4());
        assert!(probe("127.0.0.1:0", addr, b"garbage").await.is_none());
        let _ = stop.send(());
        let _ = handle.await;
    }

    /// A provider with **real cryptography on the forwarding path** and a stub
    /// only for admission.
    ///
    /// `verify_statement` needs an Ed25519 keypair and a canonical COSE_Sign1
    /// envelope, which this build cannot produce; that path is tested against the
    /// real `twinvpn-crypto` separately in `provider.rs`. Everything the
    /// *datapath* touches — the keyed BLAKE2s MAC, its truncation, the
    /// constant-time verify — is the genuine article here.
    struct RealMacProvider(crate::token::testkit::Doubles);

    impl RelayCrypto for RealMacProvider {
        fn verify_statement(
            &self,
            key: &crate::crypto::IssuerPublicKey,
            kind: crate::crypto::Statement,
            envelope: &[u8],
        ) -> Option<crate::claims::VerifiedClaims> {
            self.0.verify_statement(key, kind, envelope)
        }
        fn verify_frame_mac(&self, k: &crate::crypto::LegKey, input: &[u8], tag: [u8; 8]) -> bool {
            crate::provider::CryptoProvider::new().verify_frame_mac(k, input, tag)
        }
        fn frame_mac(&self, k: &crate::crypto::LegKey, input: &[u8]) -> Option<[u8; 8]> {
            crate::provider::CryptoProvider::new().frame_mac(k, input)
        }
        fn digest16(&self, domain: &[u8], input: &[u8]) -> Option<[u8; 16]> {
            crate::provider::CryptoProvider::new().digest16(domain, input)
        }
    }

    #[tokio::test]
    async fn a_real_frame_traverses_a_real_relay_between_two_real_sockets() {
        // The end-to-end datapath, unlocked by the frame-MAC binding: two client
        // sockets, a relay on a third, real UDP, and a real keyed BLAKE2s MAC at
        // every step. Before the binding this could not run at all — every frame
        // died at `MacInvalid`.
        use crate::crypto::LegKey;
        use crate::flow::PairTag;
        use crate::token::testkit::{claims, good_envelope, Doubles};
        use crate::RelaySub;
        use std::time::Instant;

        const LEG_A: [u8; 32] = [0xA1; 32];
        const LEG_B: [u8; 32] = [0xB2; 32];
        const LEG_KEY_CLAIM: &[u8] = b"RLK-cose-key";

        let alice = UdpSocket::bind("[::1]:0").await.expect("alice");
        let bob = UdpSocket::bind("[::1]:0").await.expect("bob");
        let (alice_addr, bob_addr) = (
            alice.local_addr().expect("addr"),
            bob.local_addr().expect("addr"),
        );

        // Admission, then two BINDs on one pair_tag — the second binds the pair.
        let issuers = IssuerKeySet::parse(
            r#"{"operator_group_id":"local-operator","issuers":[
               {"key_id":"k1","alg":"Ed25519","cose_key_hex":"0102"}]}"#,
            "local-operator",
            "x",
        )
        .expect("parses");
        let mut engine = RelayEngine::new(relay_config(), issuers, 3);
        let now = Instant::now();
        let mut c = claims();
        c.epoch = 3;
        c.not_before_ms = 0;
        c.not_after_ms = 86_400_000;
        let token = crate::token::PresentedToken::new("k1".into(), good_envelope());

        let first = RealMacProvider(Doubles::new(c.clone()));
        let v1 = engine
            .admit(&token, LEG_KEY_CLAIM, &first, 1_000)
            .expect("alice admitted");
        let tag = PairTag::from_wire(&[0x5A; 16]).expect("16");
        let crate::engine::BindResult::Pending(flow_a) =
            engine.bind(tag, alice_addr, &v1, now, 1_000)
        else {
            panic!("the first BIND pends");
        };
        let mut c2 = c;
        c2.jti = [2; 16];
        c2.subject = [8; 16];
        let second = RealMacProvider(Doubles::new(c2));
        let v2 = engine
            .admit(&token, LEG_KEY_CLAIM, &second, 1_000)
            .expect("bob admitted");
        let crate::engine::BindResult::Bound { .. } = engine.bind(tag, bob_addr, &v2, now, 1_000)
        else {
            panic!("the second BIND binds");
        };
        let _ = RelaySub::from_verified_claim([0; 16]);

        // The legs a handshake would have established.
        let mut legs = LegRegistry::new(16, 16, 900_000);
        assert!(legs.establish(
            alice_addr,
            LegKey::new(LEG_A),
            crate::token::testkit::verified([1; 16]),
            0
        ));
        assert!(legs.establish(
            bob_addr,
            LegKey::new(LEG_B),
            crate::token::testkit::verified([1; 16]),
            0
        ));

        let socket = Arc::new(UdpSocket::bind("[::1]:0").await.expect("relay"));
        let relay_addr = socket.local_addr().expect("addr");
        let runtime = Arc::new(Mutex::new(RelayRuntime {
            engine,
            legs,
            scheduler: TwoTierDrr::with_default_quantum(),
            setup: None,
        }));
        let (stop, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(serve_udp(
            socket,
            runtime,
            Arc::new(RealMacProvider(Doubles::new(claims()))),
            || 0,
            async move {
                let _ = rx.await;
            },
        ));

        // Alice builds a DATA frame and MACs it for real under her own K_leg.
        let payload: Vec<u8> = (0..=255_u8).collect();
        let counter: u64 = 1;
        let mut header = vec![0x01_u8, 1 << 4];
        #[allow(clippy::cast_possible_truncation)]
        header.extend_from_slice(&(counter as u16).to_be_bytes());
        header.extend_from_slice(&flow_a.get().to_be_bytes());
        let mut mac_input = vec![0x01_u8, 1 << 4];
        mac_input.extend_from_slice(&counter.to_be_bytes());
        mac_input.extend_from_slice(&flow_a.get().to_be_bytes());
        mac_input.extend_from_slice(&payload);
        header.extend_from_slice(&twinvpn_crypto::frame_mac(&LEG_A, &mac_input));
        header.extend_from_slice(&payload);
        alice.send_to(&header, relay_addr).await.expect("send");

        // Bob receives it.
        let mut buf = vec![0_u8; RECV_BUFFER_BYTES];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            bob.recv_from(&mut buf),
        )
        .await
        .expect("the relay forwarded within the timeout")
        .expect("recv");
        assert_eq!(from, relay_addr);
        let received = &buf[..n];

        // The payload arrived BYTE FOR BYTE, which is I1's observable half.
        assert_eq!(&received[crate::frame::HEADER_LEN..], &payload[..]);
        assert_eq!(n, crate::frame::HEADER_LEN + payload.len());
        assert_eq!(received[0], 0x01, "still a DATA frame");

        // The relay re-MACed for the EGRESS leg, so Bob can verify with his own
        // K_leg and could not have verified with Alice's.
        let out_flow = u32::from_be_bytes([received[4], received[5], received[6], received[7]]);
        let out_counter = u16::from_be_bytes([received[2], received[3]]);
        let mut out_input = vec![received[0], received[1]];
        out_input.extend_from_slice(&u64::from(out_counter).to_be_bytes());
        out_input.extend_from_slice(&out_flow.to_be_bytes());
        out_input.extend_from_slice(&payload);
        let out_tag: [u8; 8] = received[8..16].try_into().expect("8 bytes");
        assert!(
            twinvpn_crypto::verify_frame_mac(&LEG_B, &out_input, &out_tag),
            "the forwarded frame does not verify under the egress leg key"
        );
        assert!(
            !twinvpn_crypto::verify_frame_mac(&LEG_A, &out_input, &out_tag),
            "the relay reused the ingress key on egress"
        );
        assert_ne!(out_flow, flow_a.get(), "flow_id was rewritten for the peer");

        let _ = stop.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn a_frame_with_a_forged_mac_is_dropped_by_a_real_relay() {
        // The same path with a wrong tag: an off-path injector who knows the
        // flow_id but not K_leg gets zero bytes, over a real socket.
        use crate::crypto::LegKey;
        use crate::token::testkit::{claims, Doubles};

        let socket = Arc::new(UdpSocket::bind("[::1]:0").await.expect("relay"));
        let relay_addr = socket.local_addr().expect("addr");
        let mut legs = LegRegistry::new(4, 4, 900_000);
        let client = UdpSocket::bind("[::1]:0").await.expect("client");
        let client_addr = client.local_addr().expect("addr");
        legs.establish(
            client_addr,
            LegKey::new([0xA1; 32]),
            crate::token::testkit::verified([1; 16]),
            0,
        );

        let runtime = Arc::new(Mutex::new(RelayRuntime {
            engine: RelayEngine::new(relay_config(), empty_issuers(), 0),
            legs,
            scheduler: TwoTierDrr::with_default_quantum(),
            setup: None,
        }));
        let (stop, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(serve_udp(
            socket,
            runtime,
            Arc::new(RealMacProvider(Doubles::new(claims()))),
            || 0,
            async move {
                let _ = rx.await;
            },
        ));

        // A well-formed DATA frame with a garbage tag.
        let mut frame = vec![0x01_u8, 1 << 4, 0, 1];
        frame.extend_from_slice(&1_u32.to_be_bytes());
        frame.extend_from_slice(&[0xFF; 8]); // forged
        frame.extend_from_slice(&[0xC3; 64]);
        client.send_to(&frame, relay_addr).await.expect("send");

        let mut buf = [0_u8; 128];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                client.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "a forged frame drew a reply"
        );

        let _ = stop.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn the_receive_buffer_is_bounded_by_the_derived_payload_ceiling() {
        assert_eq!(
            RECV_BUFFER_BYTES,
            crate::frame::HEADER_LEN + crate::frame::MAX_DATA_PAYLOAD_BYTES
        );
        assert_eq!(RECV_BUFFER_BYTES, 1_472);
    }
}
