# `twinvpn-cp-client` — the control-plane **client**

The device half of channels **C1** (request/response) and **C2** (the resumable
durable event stream). The **server** side is a different artifact owned by the
`control-plane` domain; nothing here is a service.

Architecture: [ADR-0002](../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md).
Ownership: [`docs/implementation/ownership.md`](../../../docs/implementation/ownership.md) §2.
Build, gate and debugging for the workspace as a whole: [`core/README.md`](../../README.md).

---

## 1. Environment configuration

**None.** This crate reads no environment variable, no configuration file and no
ambient setting — CD-2, restated in `core/README.md` §4. Every capability arrives
at construction:

| Capability | Arrives as | Supplied by |
|---|---|---|
| clocks, timers, randomness, the runtime | [`twinvpn_env::Env`] | the composition root |
| the QUIC/TLS binding | [`transport::ControlTransport`] | the composition root (**integration item**, §4) |
| signature verification | [`ports::StatementVerifier`] | `twinvpn-trust` (**integration item**) |
| durable cursor, high-water marks, cached peers | [`ports::ControlPlaneStore`] | `twinvpn-store` (**integration item**) |
| identity signing | `twinvpn_platform::custody::IdentityCustody` | the platform adapter |

There is no `Default`, no global and no partial constructor for any of them.

## 2. Features

| Feature | Default | Contents |
|---|---|---|
| `test-support` | off | [`testing`] — a virtual-clock `Env`, a scripted `ControlTransport`, a scripted verifier. **Never shipped**, exactly as `twinvpn-env`'s `test-support` and `twinvpn-platform`'s `mock` are never shipped. |

`cargo test --workspace` turns it on through this crate's dev-dependency on
itself.

## 3. Local startup and debugging

This is a library; there is nothing to start. To exercise it:

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-cp-client
RUST_LOG=twinvpn_cp_client=debug cargo test -p twinvpn-cp-client -- --nocapture
```

Every timer runs on the injected [`twinvpn_env::Timer`], so a reattach-storm or
a thirty-day-outage scenario costs no wall time:

```rust
let (env, clock) = twinvpn_cp_client::testing::test_env_with_clock();
clock.suspend(Duration::from_secs(31 * 24 * 3_600));   // elapsed + wall only
```

**Never logged**, per `ownership.md` §6 rule 11: auth tokens, signatures over
secrets, pairing secrets, private keys. The types help where they can —
`ChannelBinding`, `IdempotencyKey` and `DeviceId` all have a redacted `Debug`, and
[`octets::ReceivedOctets`] renders only its length.

## 4. What the composition root must bind, and what is still open

**`ControlTransport` has no production implementation in this crate.** The
`core/` workspace manifest declares no QUIC or TLS dependency, this crate may not
add one (`ownership.md` §3, and `rustls` is on the CD-I2 deny-list), and CB-1 puts
the socket at the platform seam. So the *policy* — which rung, in what order, with
which budget, emitting which code — lives here and is fully tested, and the
binding is supplied at construction.

An implementation MUST be, per ADR-0001 §11 item 3:

- QUIC + TLS 1.3 on rung 1, mutual RFC 7250 raw-public-key auth to
  `DeviceIdentityKey`, server auth against a **pinned** key set;
- **TLS 1.3 0-RTT disabled** — [`transport::TransportConfig`] cannot express
  anything else, but a binding still has to honour it;
- one connection per `Device` carrying both C1 and C2, with C2 on its own stream;
- exposing the RFC 9266 `tls-exporter` value as
  [`transport::ControlConnection::channel_binding`].

## 5. Reading a rejection

Every failure is a [`error::CpError`], and every variant maps to a code in the
frozen registry with that code's *declared* evidence attached:

```
CONTROL.EVENT_WRONG_PUBLISHER  event_type=device_revoked observed_publisher=originating_device
```

There is no `Other(String)` and no `#[from] std::io::Error`: an unregistered
failure has nowhere to go. `err.is_security_event()` distinguishes the three
conditions the corpus requires be reported as security events rather than as
parse or connection errors, and `err.permits_offline_reconnect()` distinguishes
*unavailability* (which I5 protects against) from *an authoritative instruction
that trust has ended* (which it does not).

## 6. Extending this crate

1. **Never re-encode anything you forward.** `prost` 0.13 drops unknown fields;
   forward [`octets::ReceivedOctets`]. See that module for the full argument.
2. **Never take a trust decision from `LogHead`.** It is signed by an online key
   with no delegated trust power; it proves liveness, never trust.
3. **Never make a monotone check conditional.** The rollback refusals in
   [`revocation`] hold even against a hostile control plane, which is the point.
4. **Never add a data-plane dependency.** CD-I5 denies the edge directly *and*
   transitively; `twinvpn-store` is the only bridge.
5. **Never make `baseline_reachability_permitted`, `permits_data_plane_reconnect`
   or `baseline_peer_connectivity` conditional.** Each returns `true`
   unconditionally and each has a test that says so.
