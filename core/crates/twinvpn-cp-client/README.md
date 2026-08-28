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
| the QUIC/TLS binding | [`transport::ControlTransport`] | [`quic::QuicControlTransport`] for rung 1; the composition root supplies its identity, pin set and endpoints (§4) |
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

**Rung 1 is implemented.** [`quic::QuicControlTransport`] is QUIC + TLS 1.3 with
mutual RFC 7250 raw-public-key authentication, server keys pinned, 0-RTT
unreachable, one connection per `Device` carrying both C1 and C2, and Happy
Eyeballs v2 across both address families. `ownership.md` §8 **W-12** is what
makes it legal here: `quinn` is a transport-protocol implementation that takes
its cryptography from rustls and implements none itself, so CD-I2 does not reach
it. This crate declares `quinn` and **never** `rustls`, and every rustls type is
spelled `quinn::rustls::…`.

Four arguments come from the composition root:

| Argument | Source |
|---|---|
| `DeviceIdentity` | the enrolled `DeviceIdentityKey`: a signer the platform element backs (CB-5 / I4). `DeviceIdentity::software_key` exists for targets with no element and is named for what it costs |
| `ServerPins` | the **enrolment record** (ADR-0001 §7.2). A non-empty set of exact SPKI octets; there is no learn-on-first-use and no variant for one |
| `ControlEndpoint` | the bootstrap-scope resolution of each coordination name (ADR-0011 DN-0). Resolution is a platform call under CB-1, so this crate chooses among addresses rather than discovering them |
| `Nat64Prefix` | PREF64 / RFC 7050 discovery, where the host has one. Only `/96` is accepted |

**Still open, and the ladder says so rather than the type system implying
otherwise:**

- **Rungs 2, 3 and 4 have no implementation anywhere.** A device that cannot
  reach UDP:443 still has no control channel.
- **`quinn` is pinned in this crate's own manifest, not in
  `core/Cargo.toml`.** The workspace manifest declares no `quinn` and is the
  integration lead's; hoisting it there is an integration item.
- **The TLS configuration is built here, not vended by `twinvpn-crypto`.** W-12
  assigns the `CryptoProvider` and the cipher policy to that crate and it ships
  no TLS module. The half that is genuinely cryptographic is a *seam* here — the
  private key never appears, and pinning is byte equality — so the day
  `twinvpn-crypto` vends a configured provider this module takes it instead of
  building one.
- **`StatementVerifier`** is still an integration item (`twinvpn-trust`).

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
