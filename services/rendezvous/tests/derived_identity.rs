//! RZ-10 at the service level: a device that can **prove** its `device_id` takes
//! that name back from an impostor, and an impostor cannot take it from a device
//! that proved it.
//!
//! `tls_binding.rs` covers the channel-pinned half — one channel, one subject,
//! and a refusal that is a security event. This file covers the half that pinning
//! alone cannot: **first contact**. An attacker who attaches as `D` before the
//! real `D` ever does holds a pinned binding, and under `ChannelPinned` it holds
//! it until the TTL lapses — it cannot read the `CALL`s (Rule-B signed, opaque)
//! but it can deny their delivery, which is the whole attack.
//!
//! `DerivedPreferred` closes it by deriving the `device_id` from the key the
//! peer presented on TLS (`contracts/docs/identifiers.md` §2). Both halves are
//! asserted, because either alone passes against an implementation that ignores
//! provenance entirely.
//!
//! The remaining hole is stated rather than tested away: a device that has
//! **rotated** its identity key presents a generation-N key that derives to
//! something that is not its `device_id` (ADR-0007 §11), so it cannot prove and
//! an impostor can still hold its name for a TTL. Closing that needs an
//! `IdentitySuccession` chain this service may not fetch per connection (I5).

mod common;

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use twinvpn_rendezvous as rz;
use twinvpn_rendezvous::testkit;

const LOCAL6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

#[tokio::test]
async fn a_device_takes_its_own_name_back_from_an_impostor_who_got_there_first() {
    let h = common::start(LOCAL6).await;

    // The victim's real identity. Its `device_id` is the derivation of its own
    // key, which is what makes its claim provable and the impostor's not.
    let victim_key = common::TestKey::generate();
    let victim_id = common::proven_device_id(&victim_key);

    // First contact goes to the attacker, holding a different key.
    let impostor_key = common::TestKey::generate();
    let mut impostor = h.client_as(&impostor_key).await;
    impostor
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    let ack = common::within(impostor.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(
        ack.is_empty(),
        "the pinned first claim is accepted — that is the gap, not a bug"
    );

    // The real device arrives second and proves the name.
    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    let ack = common::within(victim.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&ack),
        None,
        "a proven claim must displace a merely pinned holder"
    );
    assert_eq!(
        h.shared.bindings.lock().await.displacements(),
        1,
        "the displacement must be countable — every one is an impersonation \
         attempt that got as far as a binding"
    );

    // And the name now routes to its owner, which is the point of all of it.
    let payload = vec![0xf8, 0x01, 0x42];
    let mut caller = h.client().await;
    caller
        .write(&testkit::call_frame(victim_id, &payload))
        .await;
    let delivered = common::within(victim.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the CALL reaches the device that proved the name");
    assert_eq!(delivered, payload);
    h.stop().await;
}

#[tokio::test]
async fn an_impostor_cannot_take_a_name_from_the_device_that_proved_it() {
    // The converse, and the one that would silently not hold if displacement
    // were implemented as "the newest claim wins".
    let h = common::start(LOCAL6).await;

    let victim_key = common::TestKey::generate();
    let victim_id = common::proven_device_id(&victim_key);

    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the proven claim is accepted");

    let impostor_key = common::TestKey::generate();
    let mut impostor = h.client_as(&impostor_key).await;
    impostor
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    let ack = common::within(impostor.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered, never reset");
    assert_eq!(
        common::reason_code(&ack).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "a security event, never a parse error (trust-boundaries.md §4)"
    );
    assert_eq!(
        h.shared.bindings.lock().await.displacements(),
        0,
        "nothing was displaced"
    );

    // Delivery still goes to the owner.
    let payload = vec![0xf8, 0x01, 0x43];
    let mut caller = h.client().await;
    caller
        .write(&testkit::call_frame(victim_id, &payload))
        .await;
    let delivered = common::within(victim.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the owner still holds its name");
    assert_eq!(delivered, payload);
    h.stop().await;
}

#[tokio::test]
async fn a_device_id_no_key_derives_to_still_binds_by_first_claim() {
    // The reason this is derived-**preferred** and not derived-only. A rotated
    // device presents a generation-N key whose derivation is not its
    // `device_id`, and requiring the derivation would lock it out permanently —
    // an unbounded, fleet-wide-irreversible cost traded for a bounded,
    // first-contact-only window. Here the unprovable claim is a `device_id` that
    // is not the presented key's derivation, which is the same input shape.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let unrelated = [0x7eu8; 32];
    assert_ne!(unrelated, common::proven_device_id(&key));

    let mut c = h.client_as(&key).await;
    c.write(&rz::frame::encode(rz::frame::Opcode::Attach, &unrelated))
        .await;
    let ack = common::within(c.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(
        ack.is_empty(),
        "a device that cannot prove its name must still bind: {:?}",
        common::reason_code(&ack)
    );

    let payload = vec![0xf8, 0x01, 0x44];
    let mut caller = h.client().await;
    caller
        .write(&testkit::call_frame(unrelated, &payload))
        .await;
    let delivered = common::within(c.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("a pinned binding is a working binding");
    assert_eq!(delivered, payload);
    h.stop().await;
}

#[tokio::test]
async fn a_displaced_impostor_is_told_and_stops_receiving() {
    // The impostor must learn it lost the name rather than sitting on a socket
    // that silently stopped mattering — ADR-0002 N-1 and S-6: answered, never
    // dropped in silence.
    let h = common::start(LOCAL6).await;
    let victim_key = common::TestKey::generate();
    let victim_id = common::proven_device_id(&victim_key);

    let impostor_key = common::TestKey::generate();
    let mut impostor = h.client_as(&impostor_key).await;
    impostor
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    common::within(impostor.read_until(rz::frame::Opcode::Ack)).await;

    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &victim_id))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack)).await;

    let told = common::within(async {
        loop {
            let (op, body) = impostor.read_frame().await?;
            if op == rz::frame::Opcode::Ack.as_wire() {
                if let Some(code) = common::reason_code(&body) {
                    return Some(code);
                }
            }
        }
    })
    .await;
    assert_eq!(told.as_deref(), Some("CONTROL.SUPERSEDED_BY_NEW_ATTACH"));

    // Nothing more reaches it.
    let payload = vec![0xf8, 0x01, 0x45];
    let mut caller = h.client().await;
    caller
        .write(&testkit::call_frame(victim_id, &payload))
        .await;
    let leaked = tokio::time::timeout(
        Duration::from_millis(250),
        impostor.read_until(rz::frame::Opcode::Deliver),
    )
    .await;
    assert!(
        matches!(leaked, Err(_) | Ok(None)),
        "a displaced impostor must not keep receiving the victim's CALLs"
    );
    h.stop().await;
}
