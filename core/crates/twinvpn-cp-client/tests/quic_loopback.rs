//! **The rung-1 binding, against a real QUIC listener.**
//!
//! **Authority:** ADR-0001 §11 item 3 (QUIC + TLS 1.3, mutual RFC 7250
//! raw-public-key auth, server keys pinned, 0-RTT prohibited) and **R8**,
//! ADR-0002 **N-1** / **N-2**, §11.6 (C2 on its own stream), ADR-0010 **R1**
//! (IPv4 and IPv6 equally), `ownership.md` §8 **W-12**.
//!
//! # Why a listener and not a mock
//!
//! `src/testing.rs`'s `RecordingTransport` proves the ladder *policy*, and it
//! proves nothing about the handshake: a scripted transport that returns
//! `Ok(ScriptedConnection)` would pass every test here while presenting no key,
//! pinning nothing, and deriving a channel binding of zeros. The properties
//! this file exists for — a mutually-authenticated handshake, a channel binding
//! both ends compute *from the connection*, a pin mismatch refused, C2 on its
//! own stream, and N-1's single connection — are only observable against
//! something that actually terminates TLS. `harness` is that something.

mod harness;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use harness::{
    drive, frame, listen, production_env, serve_one, transport_for, PROBE_CHANNEL_BINDING,
    PROBE_SUBSCRIBE, SERVER_NAME,
};
use twinvpn_cp_client::{AttachFamilies, ControlConnection, Rung, TransportConfig, TransportError};

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

#[test]
fn a_mutually_authenticated_attach_completes_over_loopback_quic() {
    let (env, _runtime) = production_env();
    drive(&env, async {
        let listener = listen(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"twinvpn/cp-client/server",
        );
        let addr = listener.endpoint.local_addr().expect("bound");
        let seen = Arc::clone(&listener.client_key_seen);
        let serving = listener.endpoint.clone();
        env.runtime()
            .spawn(Box::pin(serve_one(serving)))
            .expect("spawns the listener");

        let (transport, config) = transport_for(&env, addr, vec![listener.server_spki.clone()]);
        let connection = transport.attach_quic(&config).await.expect("attaches");

        assert_eq!(connection.rung(), Rung::Quic, "rung 1, undegraded");
        assert_eq!(connection.proto_version(), 1, "W-27: the launch epoch");
        assert_eq!(
            connection.server_key().as_ref(),
            Some(&listener.server_spki),
            "the pinned key is the one that was presented"
        );

        let echoed = connection
            .request(&frame(10, b"a C1 body"))
            .await
            .expect("one C1 round trip");
        assert_eq!(echoed.as_slice(), b"a C1 body");

        // The SERVER authenticated us too, and this is the half a mock cannot
        // reach: a key was presented, its possession was proved by a signature
        // over the handshake transcript, and the handshake completed.
        //
        // Asserted AFTER the round trip, not before. In TLS 1.3 the client is
        // done once it has sent its Finished, so `attach` can return before the
        // server has even looked at the client's certificate — a check placed
        // above would be a race that passes on a fast machine. An answered C1
        // request is proof the server got that far.
        let client_key = seen.lock().expect("not poisoned").clone();
        let expected =
            twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"twinvpn/cp-client/device")
                .spki_der();
        assert_eq!(client_key, Some(expected), "mutual RFC 7250 auth");
        connection.close().await;
    });
}

#[test]
fn the_channel_binding_matches_the_one_the_server_derives() {
    let (env, _runtime) = production_env();
    drive(&env, async {
        let listener = listen(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"twinvpn/cp-client/binding",
        );
        let addr = listener.endpoint.local_addr().expect("bound");
        let serving = listener.endpoint.clone();
        env.runtime()
            .spawn(Box::pin(serve_one(serving)))
            .expect("spawns the listener");

        let (transport, config) = transport_for(&env, addr, vec![listener.server_spki.clone()]);
        let connection = transport.attach_quic(&config).await.expect("attaches");

        let local = connection.channel_binding();
        assert!(
            !local.verify_against(&twinvpn_types::ChannelBinding::from_array([0u8; 32])),
            "an all-zero binding means the exporter was never read"
        );

        let theirs = connection
            .request(&frame(PROBE_CHANNEL_BINDING, b""))
            .await
            .expect("the probe round trip");
        let theirs = twinvpn_types::ChannelBinding::from_slice(theirs.as_slice())
            .expect("32 bytes, per limits.json identifiers.channel_binding_bytes");

        // ADR-0002 N-2: both ends compute this from the LIVE CONNECTION, and a
        // receiver rejects `Auth.channel_binding` that does not match. If these
        // two ever disagree, every signed C1 request is refused with
        // CONTROL.CHANNEL_BINDING_MISMATCH and nothing says why.
        assert!(
            theirs.verify_against(&local),
            "RFC 9266 tls-exporter, label EXPORTER-Channel-Binding, empty context"
        );
        connection.close().await;
    });
}

#[test]
fn a_server_key_that_is_not_pinned_is_refused() {
    let (env, _runtime) = production_env();
    drive(&env, async {
        let listener = listen(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"twinvpn/cp-client/genuine",
        );
        let addr = listener.endpoint.local_addr().expect("bound");
        let serving = listener.endpoint.clone();
        env.runtime()
            .spawn(Box::pin(serve_one(serving)))
            .expect("spawns the listener");

        // A different key, well-formed and correctly signed for — the listener
        // is not misbehaving. It is simply not the key the enrolment record
        // named, and that is the whole of the test.
        let impostor =
            twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"twinvpn/cp-client/impostor")
                .spki_der();
        assert_ne!(impostor, listener.server_spki);

        let (transport, config) = transport_for(&env, addr, vec![impostor]);
        let err = transport
            .attach_quic(&config)
            .await
            .expect_err("a pin mismatch must not attach");
        assert_eq!(
            err,
            TransportError::HandshakeRejected,
            "a pin mismatch is a rejected handshake, not an unreachable rung"
        );
        assert_eq!(
            twinvpn_cp_client::CpError::from(err).reason_code().as_str(),
            "CONTROL.HANDSHAKE_REJECTED"
        );
    });
}

#[test]
fn c2_arrives_on_its_own_stream_over_the_same_connection() {
    // ADR-0002 N-1: ONE connection per device carrying both C1 and C2; §11.6:
    // C2 gets its own stream so an event backlog cannot consume the RPC window.
    let (env, _runtime) = production_env();
    drive(&env, async {
        let listener = listen(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"twinvpn/cp-client/events",
        );
        let addr = listener.endpoint.local_addr().expect("bound");
        let serving = listener.endpoint.clone();
        env.runtime()
            .spawn(Box::pin(serve_one(serving)))
            .expect("spawns the listener");

        let (transport, config) = transport_for(&env, addr, vec![listener.server_spki.clone()]);
        let connection = transport.attach_quic(&config).await.expect("attaches");

        // The C1 half goes out through `request`, exactly as the transport's
        // documentation says it must: the metadata is the caller's.
        connection
            .request(&frame(PROBE_SUBSCRIBE, b""))
            .await
            .expect("the subscribe round trip");
        let mut events = connection.subscribe(0).await.expect("the C2 stream");
        let first = events
            .next()
            .await
            .expect("one record")
            .expect("a well-formed record");
        assert_eq!(first.as_slice(), b"a C2 record");
        connection.close().await;
    });
}

#[test]
fn both_address_families_attach_over_loopback() {
    // ADR-0010 R1: there is no "v4 later" and no "v6 later". The same code path
    // serves both, and the only difference is which loopback address the
    // resolver handed over — which is the point of `candidates::plan` being one
    // function over two lists.
    for bind in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    ] {
        let (env, _runtime) = production_env();
        drive(&env, async {
            let listener = listen(bind, b"twinvpn/cp-client/families");
            let addr = listener.endpoint.local_addr().expect("bound");
            let serving = listener.endpoint.clone();
            env.runtime()
                .spawn(Box::pin(serve_one(serving)))
                .expect("spawns the listener");

            let (transport, config) = transport_for(&env, addr, vec![listener.server_spki.clone()]);
            let connection = transport
                .attach_quic(&config)
                .await
                .unwrap_or_else(|err| panic!("attach over {bind} failed: {err}"));
            assert_eq!(connection.remote_address().is_ipv6(), bind.is_ipv6());
            connection.close().await;
        });
    }
}

#[test]
fn a_second_attach_supersedes_the_first() {
    // ADR-0002 N-1. The older handle is told `Superseded` rather than given a
    // generic close, because the two need different responses: a supersession
    // needs no reattach.
    let (env, _runtime) = production_env();
    drive(&env, async {
        let listener = listen(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"twinvpn/cp-client/n1",
        );
        let addr = listener.endpoint.local_addr().expect("bound");
        for _ in 0..2 {
            let serving = listener.endpoint.clone();
            env.runtime()
                .spawn(Box::pin(serve_one(serving)))
                .expect("spawns the listener");
        }

        let (transport, config) = transport_for(&env, addr, vec![listener.server_spki.clone()]);
        let first = transport.attach_quic(&config).await.expect("first attach");
        let second = transport.attach_quic(&config).await.expect("second attach");

        let err = first
            .request(&frame(10, b"late"))
            .await
            .expect_err("the older connection is superseded");
        assert_eq!(err, TransportError::Superseded);
        assert_eq!(
            twinvpn_cp_client::CpError::from(err).reason_code().as_str(),
            "CONTROL.SUPERSEDED_BY_NEW_ATTACH"
        );
        second.close().await;
    });
}

#[test]
fn a_zero_rtt_attach_is_not_something_a_caller_can_ask_for() {
    // ADR-0001 R8, asserted over the shipped source of the binding as well as
    // over its API. Three controls, and each would have to be defeated
    // separately:
    //
    //   1. no configuration expresses it — `EarlyData` has one variant and
    //      `TransportConfig` has no setter for it;
    //   2. the TLS config sets `enable_early_data = false` explicitly;
    //   3. `into_0rtt` is never called.
    //
    // A replayed early-data C1 request is a replayed CEREMONY (ADR-0002 S-5),
    // which is why "off by default" would not be enough.
    let config = TransportConfig::new(
        vec![SERVER_NAME.to_owned()],
        AttachFamilies {
            v4: true,
            v6: true,
            nat64: false,
        },
        Rung::Quic,
        false,
    );
    assert_eq!(
        config.early_data(),
        twinvpn_cp_client::EarlyData::Prohibited,
        "the only inhabitant of the type"
    );

    let transport = include_str!("../src/transport.rs");
    let shipped = transport.split("#[cfg(test)]").next().expect("a body");
    assert!(
        !shipped.contains("fn set_early_data"),
        "a setter would turn the prohibition back into a default"
    );
    let body = shipped
        .split("pub enum EarlyData {")
        .nth(1)
        .expect("the enum is declared")
        .split('}')
        .next()
        .expect("the enum is closed");
    let variants: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with('#'))
        .collect();
    assert_eq!(
        variants,
        vec!["Prohibited,"],
        "EarlyData must have exactly one inhabitant and it must not be `Permitted`"
    );

    for source in [
        include_str!("../src/quic/mod.rs"),
        include_str!("../src/quic/attach.rs"),
        include_str!("../src/quic/connection.rs"),
        include_str!("../src/quic/identity.rs"),
        include_str!("../src/quic/verify.rs"),
        include_str!("../src/quic/candidates.rs"),
    ] {
        let shipped = source.split("#[cfg(test)]").next().unwrap_or(source);
        for line in shipped.lines() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            assert!(!code.contains("into_0rtt"), "0-RTT reachable: {code}");
            assert!(
                !code.contains("enable_early_data = true"),
                "early data enabled: {code}"
            );
        }
    }
    assert!(
        include_str!("../src/quic/mod.rs").contains("tls.enable_early_data = false"),
        "control 2 of 3 must be written, not left to a default"
    );
}
