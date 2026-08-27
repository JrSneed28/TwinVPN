# ADR-0001: Tunnel Protocol and Cryptographic Foundation

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** SECURITY
- **Related:** [ADR-0004](ADR-0004-nat-traversal-strategy.md), [ADR-0005](ADR-0005-relay-architecture.md), [ADR-0006](ADR-0006-relay-discovery-and-failover.md), [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md), [docs/threat-model.md](../threat-model.md), [docs/reliability.md](../reliability.md)

This ADR selects the cryptographic protocol foundation for TwinVPN: what protects user
traffic between two `Device`s, what protects the control plane, what protects the
device-to-`Relay` leg, and how session keys, forward secrecy, replay protection, rekeying,
and key rotation are concretely specified. It is the root security decision on which
[ADR-0007](ADR-0007-device-identity-and-pairing.md) (identity) and
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) (fail-closed policy) depend. It does
not decide how paths are discovered ([ADR-0004](ADR-0004-nat-traversal-strategy.md)), how
relays are architected ([ADR-0005](ADR-0005-relay-architecture.md)), or how versions are
negotiated ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)) — it
states the security contract each of those must satisfy.

**Related documents:** [docs/threat-model.md](../threat-model.md) ·
[ADR-0007](ADR-0007-device-identity-and-pairing.md) ·
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) ·
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)

## 1. Context

TwinVPN carries a single `Owner`'s traffic between that Owner's own `Device`s, over three
kinds of `Path`: `LOCAL_DIRECT` (same L2/LAN), `WAN_DIRECT` (across the Internet), and
`RELAYED` (end-to-end encrypted through infrastructure that cannot decrypt). Devices act as
clients, `ExitNode`s, `LANGateway`s, and multi-client gateways (I7). The same
cryptographic session must be usable across all three path types and must survive migration
between them (`MIGRATING`) without renegotiating downward and without a plaintext window.

Four facts dominate the decision:

1. **Infrastructure is untrusted by construction (I1).** Relays and rendezvous services
   forward opaque ciphertext. Any design where infrastructure terminates the user tunnel is
   disqualified, no matter how convenient.
2. **We may not invent cryptography (I2).** The handshake, the AEAD construction, and the
   key schedule must come from an audited, formally-analysed, widely-deployed protocol.
3. **Mobile roaming is a first-class requirement, not a nice-to-have.** The failure list
   TwinVPN exists to fix is dominated by "random disconnects", "poor roaming", "no
   auto-reconnect". The protocol's own behaviour on address change is therefore a selection
   criterion, not an implementation detail.
4. **Some networks block UDP entirely.** A design that only works over UDP inherits a whole
   class of "it just doesn't connect" failures. But a design that runs everything over TCP
   inherits TCP-over-TCP meltdown. Both must be available, and choosing between them must
   not change the security properties of the user tunnel.

There is also an unavoidable tension between two things the brief demands simultaneously:
audited-protocol-only crypto (I2) and hardware-non-exportable device keys (I4). The
strongest hardware key stores (Secure Enclave, StrongBox, TPM 2.0) are, in practice,
NIST-curve engines: they do P-256 ECDSA/ECDH and will not do X25519 in hardware. The
strongest audited tunnel protocols in this space are Curve25519-based. This ADR resolves
that tension explicitly rather than pretending it does not exist (see §11 and §13).

## 2. Requirements


**Requirements discharged** ([docs/vision.md](../vision.md) §5): **R-07** (a `Session` survives rekey and endpoint change without re-authentication) and **R-15** (no cryptographic cost on the steady-state datapath; throughput is not degraded by the protection layer). It also supplies the handshake prologue on which **R-13**'s downgrade resistance depends ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)).
| # | Requirement | Source |
|---|---|---|
| R1 | User tunnel plaintext MUST NOT be recoverable by any relay, rendezvous, or control-plane component, and no such component may hold a key capable of decrypting it. | I1 |
| R2 | All primitives, handshakes, and AEAD constructions MUST come from an audited, published protocol. No novel construction. | I2 |
| R3 | Sessions MUST provide forward secrecy: compromise of a long-term `DeviceKey` MUST NOT decrypt previously recorded sessions. | Threat: key extraction |
| R4 | Sessions MUST provide replay protection at the packet level and at the handshake level. | Threat: replay |
| R5 | Peer identity MUST be cryptographically bound into the handshake such that an unknown or revoked `DeviceIdentity` cannot complete it. No trust-on-first-use at connect time. | I4, ADR-0007 |
| R6 | The protocol MUST be downgrade-resistant: an on-path adversary MUST NOT be able to force a weaker suite, an older `ProtocolVersion`, or a reduced `Capability` set. | ADR-0014 |
| R7 | A `Session` MUST survive `Endpoint` change (roaming, NAT rebinding, `WAN_DIRECT` ↔ `RELAYED` migration) without a plaintext window and without a fresh out-of-band step. | Roaming |
| R8 | Handshake cost MUST be at most 1-RTT to first protected data. Any 0-RTT capability MUST NOT create replayable application data. | Performance |
| R9 | The data plane MUST be able to use a kernel datapath where the platform offers one. | Throughput |
| R10 | The tunnel MUST be carryable over a transport that traverses UDP-blocked networks, without changing the security properties of the inner tunnel. | Censorship / hotel Wi-Fi |
| R11 | Idle cost MUST be low enough for continuous mobile operation; keepalive traffic MUST be emitted only where NAT/relay state genuinely requires it. | Mobile battery |
| R12 | Rekeying MUST be automatic, time- and volume-bounded, and MUST NOT produce a gap in carried traffic. | Reliability |
| R13 | Revocation of a `TrustedPeer` MUST be enforceable at the cryptographic layer, not only at a policy layer. | ADR-0007 |
| R14 | Every cryptographic failure MUST surface a stable machine-readable reason code and a human-actionable explanation, and MUST NOT leak key material through error detail. | I6 |
| R15 | Failure to establish or maintain a secure session MUST NOT result in untunneled carriage of protected traffic. | I3, ADR-0012 |
| R16 | The design MUST have a defined migration path to post-quantum key agreement that does not require inventing anything. | Longevity |

## 3. Constraints

- **C1** Platform hardware key stores are P-256-centric; Curve25519 private-key operations
  generally cannot be performed inside a secure element (see [ADR-0007](ADR-0007-device-identity-and-pairing.md) §3).
- **C2** iOS/macOS network extensions run in a memory-constrained, OS-managed process
  (`NEPacketTunnelProvider`); no kernel datapath is available to third parties on Apple
  platforms. Throughput there is userspace-bound.
- **C3** Android third-party VPNs are confined to `VpnService`; there is no third-party
  kernel datapath and no third-party global firewall.
- **C4** Some networks permit only TCP/443 egress, and some perform TLS SNI inspection.
- **C5** Relays must be able to perform abuse control and rate limiting without decrypting
  (I1), so the relay leg needs its own authenticated channel distinct from the peer tunnel.
- **C6** Control-plane outage MUST NOT tear down established tunnels (I5), so the data plane
  cannot depend on a live control-plane session for key continuity.
- **C7** Embedded targets (routers) may have no hardware key store and weak CPUs without
  AES-NI; the chosen AEAD should be fast in software.
- **C8** We are a small team; every additional bespoke protocol surface is a permanent audit
  liability.

## 4. Considered Alternatives

| ID | Alternative | One-line characterisation |
|---|---|---|
| **A1** | **WireGuard protocol, as-is, everywhere** | Adopt WireGuard (Noise_IKpsk2 / X25519 / ChaCha20-Poly1305 / BLAKE2s) as the entire transport, over plain UDP only. |
| **A2** | **Noise Protocol Framework directly** | Build a TwinVPN-specific protocol by instantiating a Noise pattern (e.g. `Noise_IK` or `Noise_XK`) over our own framing and our own transport. |
| **A3** | **QUIC + TLS 1.3 as the tunnel** | Carry IP inside QUIC DATAGRAM frames / MASQUE `CONNECT-IP` (RFC 9484), with mutual TLS 1.3 raw-public-key authentication. QUIC is both the crypto and the transport. |
| **A4** | **Platform-native secure channel and storage stacks** | Use each OS's own TLS/crypto stack (Network.framework + Secure Enclave, Conscrypt + Keystore/StrongBox, Schannel/CNG + TPM, kernel TLS + keyring) as the cryptographic foundation, with keys never leaving the platform store. |
| **A5** | **IPsec/IKEv2 with MOBIKE** | Standards-track, kernel-accelerated on every major OS, native client support, MOBIKE for roaming. |
| **A6** | **Layered: WireGuard data plane over a pluggable outer transport, QUIC/TLS 1.3 control and relay legs, platform-native storage for key material** | One audited protocol per layer, each doing what it is best at; composed so that no layer can weaken another. |

A6 is the selected option. A1–A5 are all genuinely viable products in the market today,
which is why each is analysed on its own terms below.

For completeness: **OpenVPN/DTLS** and **SSH tunnelling** were considered and eliminated
before this shortlist. OpenVPN's TLS-plus-custom-datachannel design has a large attack
surface, mediocre roaming, and poor performance relative to every option above; SSH
tunnelling has no useful roaming, no forward-secret rekey story for long-lived tunnels at
this scale, and TCP-over-TCP behaviour. Neither is a serious contender in 2026, and
carrying them through the full comparison would be padding.

## 5. Advantages of Each Alternative

### A1 — WireGuard as-is

- **Best-in-class cryptographic pedigree.** Noise_IKpsk2 has been formally verified
  (Tamarin, CryptoVerif, and independent symbolic analyses); the WireGuard protocol itself
  has been academically analysed as a whole, not just its primitives.
- **Tiny attack surface.** ~4k lines in the kernel implementation; one handshake, one
  packet type family, no negotiation, no crypto agility to attack.
- **Silence on unauthenticated input.** WireGuard does not respond to unauthenticated
  packets, which removes a large class of scanning and amplification behaviour.
- **Roaming is intrinsic.** A peer's `Endpoint` is updated on receipt of any correctly
  authenticated, non-replayed transport packet. Roaming works without a control channel,
  without renegotiation, and without a plaintext window. This directly attacks the
  "random disconnects / poor roaming" failure class.
- **Kernel datapath on Linux and Windows** (in-tree `wireguard`, WireGuardNT).
- **1-RTT, no 0-RTT data**, therefore no replayable early data by construction.
- **Cheap idle.** No traffic when idle unless a persistent keepalive is configured.
- **PSK slot (`psk2`)** gives a standards-blessed hook for an additional symmetric secret —
  useful both as a revocation lever and as a post-quantum hedge.

### A2 — Noise Protocol Framework directly

- Maximum design freedom: choose the exact pattern (`IK` for known-responder,
  `XK` for identity-hiding of the initiator), the exact transport framing, and in-band
  control multiplexing.
- Noise itself is audited and formally analysed as a framework; patterns come with published
  security properties.
- Can carry our own control messages in the same session as data, which is architecturally
  tidy.
- Not tied to WireGuard's fixed cipher choice; can select a suite that matches hardware
  (relevant to C1).
- Identity-hiding patterns (`XK`, `IK` with the initiator static encrypted) reduce metadata
  exposure of the initiator's public key to a passive observer.

### A3 — QUIC + TLS 1.3 tunnel

- **TLS 1.3 is the most-audited handshake in existence**, with mature formal analysis and
  an enormous implementation ecosystem.
- **Connection migration is a first-class protocol feature**, with connection IDs that
  decouple session identity from the 4-tuple and with mandatory path validation before
  committing to a new path — cryptographically cleaner than "update endpoint on
  authenticated packet".
- **Runs on 443 and looks like HTTP/3**, which is the single best answer to UDP-hostile and
  DPI-heavy networks.
- **Solves TCP-over-TCP** by being its own reliable/unreliable multiplexed transport;
  DATAGRAM frames (RFC 9221) carry unreliable inner packets correctly.
- **Loss recovery, congestion control, and MTU discovery are built in**, which matters a lot
  on the relay leg.
- MASQUE `CONNECT-IP` (RFC 9484) and `CONNECT-UDP` (RFC 9298) are standards-track ways to
  express exactly what a relay does.
- Certificate/raw-public-key mutual auth maps cleanly onto device identity.

### A4 — Platform-native stacks

- **Keys can genuinely never leave the secure element**, because the OS performs the
  handshake with a key handle rather than a key. This is the strongest possible reading of
  I4.
- Platform crypto is FIPS-validated where that matters, patched by the OS vendor, and
  hardware-accelerated.
- On Apple platforms, `Network.framework` + `NEPacketTunnelProvider` is the sanctioned,
  best-supported, most battery-efficient path.
- No third-party crypto library to audit, vendor, or CVE-track.
- Attestation of the key (Secure Enclave attestation, Android Key Attestation, TPM quote)
  is available natively.

### A5 — IPsec/IKEv2 + MOBIKE

- Standards-track since 2005, extensively deployed, extensively attacked, and hardened.
- **Kernel datapath on every major OS**, with hardware offload on many NICs.
- **Native OS clients** on iOS, macOS, Windows, and Android — no third-party datapath
  needed at all in the simplest configuration.
- MOBIKE (RFC 4555) provides address-change survival for exactly our roaming case.
- Mature multi-client concentrator behaviour (I7) with well-understood scaling.
- Suite-B/PQ profiles exist; RFC 9370 defines multiple key exchanges in IKEv2, giving a
  standards-track hybrid post-quantum path today.

### A6 — Layered (selected)

- Takes A1's audited, minimal, roaming-native, kernel-accelerated data plane and A3's
  transport strengths without letting either weaken the other.
- The user tunnel is *the same session* regardless of whether it rides plain UDP, a relay,
  or QUIC — so `MIGRATING` between `WAN_DIRECT` and `RELAYED` is a transport event, not a
  cryptographic event. This is a large, concrete reliability win and it is only available in
  a layered design.
- The relay leg gets its own authenticated channel (C5) so relays can rate-limit and
  authorise without ever being in a position to decrypt (I1).
- The control plane gets TLS 1.3 mutual auth *plus* per-message `DeviceKey` signatures, so a
  compromised control-plane TLS terminator still cannot forge device statements.
- Key storage uses the platform store (A4's strength) for the attestable identity key, while
  the tunnel key is hardware-*wrapped*; the gap between those two is stated openly rather
  than hidden.
- Every layer is an off-the-shelf audited protocol; the only thing TwinVPN designs is the
  composition, and the composition is arranged so that no layer's security depends on
  another layer's confidentiality.

## 6. Disadvantages of Each Alternative

### A1 — WireGuard as-is

- **UDP-only.** On a network that blocks UDP, it simply does not connect. That is one of the
  named failure modes TwinVPN exists to eliminate, so A1 alone cannot be the whole answer.
- **No in-protocol version or capability negotiation.** Combined with
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s requirements this
  means negotiation must live somewhere else, which A1 does not provide.
- **No crypto agility at all.** X25519/ChaCha20-Poly1305/BLAKE2s are hard-coded. This is a
  security virtue and an operational liability: a break in X25519 requires a new protocol
  version, not a config change. It also collides directly with C1.
- **Handshake identity exposure.** In `IK`, the initiator's static public key is encrypted
  to the responder's static, so a passive observer does not learn it — but an active
  adversary who knows a candidate responder static can confirm it. Peer identity is also
  linkable across sessions via the persistent `receiver_index`/endpoint correlation.
- **No congestion control, no MTU discovery, no loss recovery.** Over a relay this shows up
  as poor behaviour on lossy paths; MTU/PMTU handling becomes our problem.
- **No connection ID.** Session demux is by `receiver_index` (which does decouple from the
  4-tuple, adequately) but there is no path-validation step before endpoint update.
- **Fixed 25s keepalive granularity** when persistent keepalive is needed; not adaptive.
- **Trivially fingerprintable on the wire**: fixed handshake message sizes (148/92 bytes)
  and a distinctive first byte make WireGuard easy for DPI to classify and block.

### A2 — Noise Protocol Framework directly

- **This is the alternative that most tempts us into violating I2 in spirit.** Noise is
  audited *as a framework*; a specific instantiation with our own framing, our own rekey
  logic, our own replay window, our own fragmentation, and our own transport is a
  TwinVPN-specific protocol that nobody has audited. The primitives are safe; the protocol
  is ours, and protocol-level bugs are where VPNs actually fail.
- Loses the kernel datapath entirely: no OS ships our pattern.
- Loses WireGuard's decade of adversarial attention on exactly this construction.
- We would end up re-deriving WireGuard's timer state machine (rekey-after-time,
  reject-after-time, cookie replies, handshake rate limiting) from scratch, badly, and
  discovering its subtleties in production.
- More design freedom is a disadvantage here: every knob is a decision we must justify and
  defend forever.

### A3 — QUIC + TLS 1.3 tunnel

- **Larger attack surface by an order of magnitude.** TLS 1.3 has crypto agility, extension
  negotiation, session resumption, and a very large state machine; QUIC adds frame parsing,
  flow control, and connection-ID management. Every one of those is a place a VPN has been
  broken before.
- **0-RTT resumption is a replay hazard.** It can be disabled, but its presence in the stack
  is a permanent "make sure nobody turned this on" liability (R8).
- **No kernel datapath.** Every packet crosses userspace and takes a per-packet syscall
  path; QUIC tunnels are meaningfully slower and more CPU-hungry than kernel WireGuard,
  which matters on routers and on battery.
- **Certificate/PKI baggage.** Even with raw public keys (RFC 7250) we inherit TLS's
  identity machinery, and if we use certificates we inherit expiry, chains, and revocation.
- **Head-of-line and reliability mismatch.** Using QUIC streams for IP would be wrong;
  DATAGRAM frames are correct but are an extension with uneven implementation maturity in
  some stacks, and DATAGRAM has no fragmentation, so MTU handling is still ours.
- **Handshake cost.** TLS 1.3 mutual auth with certificates is heavier on the wire than
  WireGuard's 148/92 bytes, which matters on lossy mobile links.
- **CPU cost of ubiquity:** QUIC's obfuscation benefit only holds while we look like HTTP/3;
  the moment a DPI vendor fingerprints *our* QUIC parameters, the benefit degrades.

### A4 — Platform-native stacks

- **Fatal for a cross-platform tunnel:** the five platforms do not share a protocol, a
  cipher suite policy, a certificate model, or a session lifecycle. Making iOS's TLS stack
  interoperate with Windows Schannel and Linux kTLS for a *peer-to-peer mesh* is a
  compatibility project with no end.
- **We would still have to define the tunnel protocol on top.** Platform stacks give a
  secure channel, not a VPN; the framing, rekey, replay, and roaming semantics are still
  ours. So A4 does not actually remove the protocol design problem — it only removes the
  crypto library.
- **Constrained cipher and curve choice**, driven by C1: effectively P-256 everywhere.
- **Debuggability is poor**; opaque OS stacks make handshake failure diagnosis hard, which
  fights I6 directly.
- **Version skew across OS releases** becomes a compatibility matrix we do not control.
- However, A4's *storage* half is not really an alternative to the others — it is a
  component every alternative needs, and it is retained in the decision.

### A5 — IPsec/IKEv2 + MOBIKE

- **Enormous complexity.** IKEv2 has a large negotiation surface, and negotiation surface is
  where downgrade attacks live (R6). Historically, IKE has been the source of repeated
  implementation vulnerabilities, and IKEv1 aggressive mode remains a cautionary tale.
- **Poor NAT behaviour relative to our needs.** NAT-T over UDP/4500 works, but IPsec is
  notoriously badly handled by consumer CPE, and ESP is frequently dropped outright. For a
  product whose core promise is "connects through symmetric NAT and CGNAT", starting from a
  protocol that middleboxes dislike is a bad opening position.
- **Peer-to-peer mesh is not IPsec's shape.** IKEv2 is overwhelmingly deployed
  client-to-concentrator; a full mesh of peer SAs with dynamic endpoints is possible but
  swims against the ecosystem.
- **Native OS clients are a trap here**: they give us no control over the kill switch,
  roaming behaviour, diagnostics, or reason codes — every one of which is a named
  requirement (I3, I6). We would have to write our own datapath anyway, losing the main
  advantage.
- **MOBIKE is weaker than it sounds**: it is an authenticated address-update exchange
  requiring a round trip, not the transparent "authenticated packet from a new address just
  works" behaviour of A1 or QUIC's connection migration.
- Configuration surface is huge, which makes "cryptic error codes" the default experience —
  precisely the failure mode we are chartered to eliminate.

### A6 — Layered (selected)

- **Two protocols to understand, not one.** Engineers must hold both the WireGuard state
  machine and the QUIC/TLS state machine in their heads, and must understand where the
  boundary is. This is a real, permanent cost.
- **The composition itself is a design artefact** and must be reviewed as one, even though
  each layer is off-the-shelf. Layering bugs (e.g. an outer layer that silently retries in a
  weaker mode) are exactly the sort of thing that bites.
- **Encapsulation overhead** when running WireGuard inside QUIC DATAGRAM: roughly 1 + ~20–30
  bytes of QUIC framing on top of WireGuard's 32-byte data header, plus UDP/IP. MTU
  budgeting becomes non-trivial and is a real source of "it connects but big packets fail"
  bugs — this is the classic MTU black-hole failure and it must be actively managed
  ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md)).
- **Double congestion control risk**: QUIC has congestion control, the inner traffic often
  has TCP congestion control, and the tunnel becomes a nested-CC system. Well-understood,
  but it must be configured deliberately.
- **Two authentication systems to keep aligned**: the peer tunnel authenticates by X25519
  static, the control/relay legs authenticate by the P-256 identity key. They must be bound
  together or an attacker could try to use one identity with the other's credentials
  ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §11 defines that binding).
- A5 and A3 are each materially simpler as a *single* answer; A6 buys capability with
  complexity, and that is the trade being made.

## 7. Security Implications

### 7.1 What the selected design guarantees

| Property | Mechanism |
|---|---|
| Confidentiality and integrity of user traffic | ChaCha20-Poly1305 AEAD, keys known only to the two peer `Device`s |
| Forward secrecy | Ephemeral X25519 per handshake; rekey at least every 120 s |
| Peer authentication | `Noise_IKpsk2` binds both static public keys into the key schedule; an unknown static cannot complete the handshake |
| Replay protection (data) | 64-bit nonce counter + 8192-bit sliding receive window (RFC 6479 style) |
| Replay protection (handshake) | Monotonic TAI64N timestamp per peer; a handshake initiation with a non-increasing timestamp is dropped |
| Identity misbinding resistance | `IK` mixes both statics and the ephemeral into the chaining key; there is no unauthenticated key-confirmation window |
| Downgrade resistance | See §7.3 |
| Post-compromise recovery (partial) | PSK rotation + `DeviceCertificate` expiry ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) |
| Infrastructure blindness (I1) | Relay sees only the outer transport and an opaque payload; it holds no key in the peer key schedule |

### 7.2 Concrete cryptographic specification

**Layer L-DATA (peer ↔ peer, carries all user traffic).**

```
Protocol      : WireGuard (Noise_IKpsk2)
DH            : Curve25519 (X25519)
AEAD          : ChaCha20-Poly1305 (RFC 8439), 64-bit counter nonce
Hash / KDF    : BLAKE2s, HKDF-style chaining as specified by Noise
Handshake     : 1-RTT. initiation (148 B) -> response (92 B) -> transport data
Session keys  : one send key + one receive key per peer per handshake,
                derived from the final Noise chaining key; independent per direction
PSK slot      : psk2 = TwinNetPSK(peer, epoch)  -- see 7.5
Rekey         : REKEY_AFTER_TIME       = 120 s  (initiator begins a new handshake)
                REKEY_AFTER_MESSAGES   = 2^60   (whichever comes first)
                REJECT_AFTER_TIME      = 180 s  (keys are unusable and are zeroed)
                REJECT_AFTER_MESSAGES  = 2^64 - 2^13 - 1
                REKEY_ATTEMPT_TIME     = 90 s   (then the Session fails, see below)
Keepalive     : passive keepalive 10 s after receiving data with nothing to send;
                persistent keepalive 25 s ONLY when the peer is behind NAT or the
                path is RELAYED (R11)
DoS defence   : cookie reply (MAC1/MAC2) under load; no response to unauthenticated
                packets; per-source handshake rate limiting
```

**Layer L-TRANSPORT (carries L-DATA datagrams; interchangeable at runtime).**

| Mode | Carriage | When used | Security contribution |
|---|---|---|---|
| `T-UDP` | Raw UDP, IPv4 or IPv6 | `LOCAL_DIRECT`, `WAN_DIRECT` | none (L-DATA is self-protecting) |
| `T-RELAY` | L-DATA datagram inside an authenticated device↔relay session | `RELAYED` | authorises and rate-limits the device to the relay; hides nothing from L-DATA's perspective |
| `T-QUIC` | L-DATA datagram inside a QUIC DATAGRAM frame (RFC 9221) to :443 | UDP blocked / DPI hostile | traffic-shape and port camouflage only |

The transport mode is a property of the `Path`, not of the `Session`. Switching modes MUST
NOT re-run the L-DATA handshake, MUST NOT reset the L-DATA nonce counter or replay window,
and MUST NOT alter any L-DATA security property. This is the single most important
composition rule in this ADR.

**Layer L-CONTROL (device ↔ control plane).**

```
Transport     : QUIC + TLS 1.3, mutual authentication
Client auth   : RFC 7250 raw public key = DeviceIdentityKey (P-256 ECDSA)
Server auth   : pinned control-plane public key set, shipped in the build
Message auth  : per-message signatures are NOT used. Authentication is the
                mutually-authenticated channel plus the RFC 9266 `tls-exporter`
                binding carried in `Auth.channel_binding` (protocol.md S3 Rule A).
                Statements that are WAREHOUSED or FORWARDED by the coordination
                service (protocol.md S3 Rule B) carry a detached
                DeviceIdentityKey signature over deterministic CBOR, so a
                compromised TLS terminator cannot forge or replay them. Signing
                every message was considered and rejected: it is expensive on
                mobile and adds nothing inside an already mutually-authenticated
                channel (protocol.md S3).
0-RTT         : PROHIBITED (R8)
Resumption    : permitted, but resumed sessions MUST NOT carry early data
```

**Layer L-STORE (at rest).** Per
[ADR-0007](ADR-0007-device-identity-and-pairing.md): `DeviceIdentityKey` lives in the
platform secure element and is non-extractable; the L-DATA X25519 static private key is
sealed under a hardware-bound wrapping key and unwrapped only into locked, non-swappable,
non-dumpable memory.

### 7.3 Downgrade resistance (joint requirement with ADR-0014)

WireGuard has no negotiation to downgrade, which removes the classic attack surface
entirely for L-DATA. Negotiation exists only for `ProtocolVersion` and `Capability`, and it
lives inside the authenticated tunnel. The requirements TwinVPN imposes on
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) are:

| # | Requirement |
|---|---|
| D1 | No negotiated result may become **authoritative**, or cause any persistent state change, until it is confirmed **inside** the established L-DATA session ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-8). Advertisements MAY be exchanged pre-handshake — they are folded into `ConnectOffer`/`ConnectAnswer` to avoid a round trip ([docs/protocol.md](../protocol.md) §10.2) — but they are **claims, not decisions**, and are made binding only by being bound into the handshake prologue (§7.3.1) and confirmed afterwards. |
| D2 | A transcript hash covering the full negotiation MUST be confirmed by both peers; mismatch MUST tear down the `Session` with `PROTO.TRANSCRIPT_MISMATCH`. |
| D3 | Each `Device` MUST persist, per `TrustedPeer`, the highest `ProtocolVersion` epoch and the **`security_relevant` subset** of the `Capability` set ever successfully negotiated (a **monotonic floor**, state row S-37), and MUST refuse a strictly weaker offer. The floor covers the epoch and registry-flagged `security_relevant` tokens **only** — it MUST NOT cover the whole capability set, because an honest device whose OS revokes a permission would otherwise be permanently unable to reconnect ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-19). Clearing the floor MUST require an authenticated local management-plane action by the `Owner`. |
| D4 | The set of acceptable versions and suites MUST come from the local build plus local policy. A control-plane-supplied list MUST NOT be able to *narrow* it. |
| D5 | Removed versions MUST be un-negotiable in the build, not merely deprioritised. |
| D6 | No pre-authentication message may cause persistent state change or policy relaxation. |

#### 7.3.1 The handshake prologue — one field, two contributors (normative)

The Noise handshake accepts **exactly one** `prologue`, mixed into the handshake hash before any
key-derivation output is used; a mismatch fails the handshake without producing session keys.
Two ADRs need to bind material into it, so **this ADR owns the field and neither of them does**.
Each contributes one 32-byte digest:

```
identity_binding_hash = SHA-256( "TWINVPN-IDBIND-v1"
                               || twinnet_id(16)
                               || device_id_init(32) || device_id_resp(32)
                               || trust_epoch(u64 BE) || psk_epoch(u64 BE)
                               || anchor_version(u32 BE)
                               || delegation_set_digest(32) )     # ADR-0007 S7.6 contributes

negotiation_hash      = SHA-256( "TWINVPN-NEG-v1"
                               || H_initiator || H_responder
                               || det_CBOR(Selection) )           # ADR-0014 N-6 contributes

prologue              = "TWINVPN-PROLOGUE-v1"
                               || identity_binding_hash
                               || negotiation_hash                # 19 + 32 + 32 = 83 bytes
```

**Normative rules.**

- **P-1** The `prologue` MUST be exactly the 83-byte concatenation above. No other document may
  define, extend, or reorder it. [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-20 and
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-6 **contribute a
  digest each**; they do not define the field.
- **P-2** The monotonic floor (D3, S-37) is a **negotiation** input and is carried inside
  `Selection` under `negotiation_hash`. It MUST NOT be duplicated in the identity half.
- **P-3** The prologue is a local hash input and is **never transmitted**. A mismatch is therefore
  observationally indistinguishable from any other handshake failure. Anything that a peer must be
  able to *observe* — rather than merely agree on — MUST NOT rely on the prologue. In particular
  the `trust_epoch` gossip of [ADR-0009](ADR-0009-state-consistency.md) §11.6 G-1/G-2 and the
  unexpected-delegation detection of [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.5 MUST
  use the in-session `TrustEpochAssert` message, not the prologue.
- **P-4** A version epoch that is not yet confirmed in-session MUST NOT be written to the S-37
  floor (D1).

Because L-DATA is fixed-suite, D1–D6 are cheap: there is no cipher negotiation to protect,
only feature negotiation.


#### 7.3.2 Tunnel-layer session resumption (discharging protocol.md A4)

`docs/protocol.md` A4 assumes resumption exists **at the tunnel layer** and needs no
control-plane round trip; §12.1 makes it the first recovery attempt and a user-visible
availability property. The `Resumption` line in §7.2 governs **L-CTRL** (the control-plane
QUIC/TLS channel) and does not discharge A4. This section does.

```
resumption_secret = HKDF-Expand-Label(handshake_secret, "twinvpn resume", "", 32)
resumption_id     = HKDF-Expand-Label(handshake_secret, "twinvpn resume id", "", 16)
```

| # | Rule |
|---|---|
| **RS-1** | Both peers derive `resumption_secret` and `resumption_id` from the completed handshake and retain them **in memory only**, for the life of the `Session` (S-13: never persisted, never replicated). A process restart therefore loses them and re-establishes with a full handshake. |
| **RS-2** | A resume is a single authenticated datagram: `{resumption_id, session_nonce, path_epoch, new_endpoint_hint, MAC}`, where the MAC is over the whole message under `resumption_secret`. It carries no key exchange, so it is **~1 RTT** and adds no asymmetric operation. |
| **RS-3** | Resumption re-binds an existing `Tunnel` to a new `Path`. It MUST NOT create a second `Session`, reset counters, or reset the replay window (`docs/protocol.md` §12.1). |
| **RS-4** | Replay defence: `path_epoch` MUST strictly increase, and a resume presenting a `path_epoch` at or below the highest seen MUST be dropped silently. |
| **RS-5** | A resume MUST be refused if the peer's `DeviceIdentity` has been revoked since the original handshake — the responder checks `trust_epoch` before accepting (**I3**), emitting `AUTH.DEVICE_REVOKED`. |
| **RS-6** | Resumption provides **no** new forward secrecy. It is bounded by the rekey schedule of §7.2: a `Tunnel` that would rekey MUST rekey rather than resume indefinitely. |
| **RS-7** | Resumption requires **no** control-plane call (**I5**), which is what makes `docs/protocol.md` §12.1's "local-only authority" true. |

**What this deliberately does not cover.** Resumption survives a *path* change, not a *process*
restart — RS-1 makes that explicit, because S-13 forbids persisting key state. `docs/protocol.md`
§12.1's trigger list MUST NOT include process restart; after a restart the recovery path is a full
handshake from cached `TrustedPeer` state, which is still control-plane-free.

### 7.4 Why a compromised control plane cannot read or MITM traffic

A control plane that is fully compromised can: refuse service, lie about which peers exist,
lie about relay availability, and observe control-plane metadata. It **cannot**:

- decrypt any user traffic — it holds no key in the L-DATA schedule (I1);
- insert itself as a peer — peer trust derives from `DeviceCertificate`s signed by the
  `Owner` authority, not by the control plane
  ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §11);
- forge a device statement — every control message is signed end-to-end by
  `DeviceIdentityKey`, so TLS termination is not the trust anchor;
- grant `ExitNode` or `LANGateway` access — `AccessPolicy` is enforced at the resource-owning
  peer and must be Owner-signed ([docs/threat-model.md](../threat-model.md) §7);
- roll a device back to a weaker configuration — monotonic floors (D3) and monotonic policy
  epochs forbid it.

### 7.5 The PSK slot, and what it is for

`Noise_IKpsk2` accepts a 32-byte pre-shared key mixed into the chaining key after the
ephemeral exchange. TwinVPN uses it for three purposes, none of which are novel crypto:

1. **Post-quantum hedge.** A store-now-decrypt-later adversary who breaks X25519 in future
   still faces an unknown symmetric secret. This is the standards-blessed migration path
   (R16) and is how a hybrid PQ key exchange will later be fed in without changing the
   tunnel protocol.
2. **A hard revocation lever (R13).** The `TwinNetPSK` is per-peer-pair and per-`epoch`. On
   revocation the epoch advances and remaining peers derive a new PSK; a revoked device
   holding its old static key can no longer complete a handshake with any peer that has
   advanced, even if that peer has not yet learned *why*.
3. **Defence against a compromised static.** An attacker who extracts only the X25519 static
   (e.g. from a memory dump) but not the PSK cannot impersonate the device.

`TwinNetPSK(A,B,epoch) = HKDF-SHA-256( ikm = PairSecret(A,B) || EpochSeed(epoch), ... )` — derived
from the **pairwise** `PairSecret` plus an `Owner`-generated, per-device-HPKE-sealed `EpochSeed`
([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, which **corrects** an earlier form of
this paragraph). The distinction is load-bearing: derived from a *`TwinNet`-wide* secret the PSK
epoch would **not** be a revocation lever, because a revoked device would know that secret and
could derive every later epoch's PSK. Derived pairwise, plus a seed it is not sealed a copy of, it
is — the revoked device is simply not a recipient of `EpochSeed(epoch+1)`.

### 7.6 Endpoint migration is authenticated, and path-validated

WireGuard updates a peer's `Endpoint` upon receiving a correctly authenticated,
non-replayed transport packet from a new source address. That is cryptographically sound
(an attacker cannot forge such a packet), but it is not sufficient on its own: an attacker
who can *relay* a genuine packet from an address of their choosing can attract the return
flow. TwinVPN therefore imposes on [ADR-0004](ADR-0004-nat-traversal-strategy.md):

> A `Path` change MUST NOT commit bulk traffic to a new `Endpoint` until an authenticated
> challenge/response has completed **on that new path**. Until validation succeeds, the new
> endpoint MAY receive only the validation probe, and the previous endpoint remains
> authoritative. Failed validation MUST NOT tear down the `Session`.

This is QUIC's path-validation discipline applied to L-DATA, and it costs one round trip on
a path we were about to use anyway.

### 7.7 Residual security concerns of the selected option

- **Traffic analysis.** L-DATA hides content, not shape. Packet sizes, timing, and volume
  remain visible to any observer on the path, including relays. TwinVPN does **not** claim
  resistance to traffic-confirmation or traffic-correlation attacks. See
  [docs/threat-model.md](../threat-model.md) §6.
- **Protocol fingerprinting.** `T-UDP` WireGuard is trivially identified by DPI. `T-QUIC`
  improves this but is camouflage, not steganography, and MUST NOT be described to users as
  making TwinVPN undetectable.
- **X25519 in software (C1).** The tunnel static key is hardware-*wrapped*, not
  hardware-*resident*. An attacker with code execution as the TwinVPN service on an unlocked
  device can read it from memory. Mitigations (locked memory, no core dumps, PSK layering,
  short certificate lifetime) reduce but do not eliminate this. This is stated as residual
  risk in §13 and in [ADR-0007](ADR-0007-device-identity-and-pairing.md) §13.
- **Nested QUIC congestion control** in `T-QUIC` mode can interact badly with inner TCP;
  this is a performance risk, but a misconfiguration here could also produce a
  denial-of-service-like experience.

## 8. Reliability Implications

- **Migration without renegotiation.** Because the transport is separable from the session,
  `WAN_DIRECT → MIGRATING → RELAYED` and back is a datagram-routing change. The `Session`,
  its keys, its counters, and its replay window all persist. This eliminates the "relay
  failover drops the tunnel" failure class by construction. [ADR-0006](ADR-0006-relay-discovery-and-failover.md)
  owns *when* to migrate; this ADR guarantees the migration is free of cryptographic cost.
- **Control-plane independence (I5).** L-DATA rekeying is peer-to-peer and needs no control
  plane. An established `Session` continues indefinitely through a total control-plane
  outage. Only new pairings, new policy, and relay *discovery* degrade.
- **Rekey has no traffic gap.** WireGuard's initiator begins a new handshake at 120 s while
  the old keys remain valid until 180 s, giving a 60 s overlap. A handshake failure is
  therefore visible for a full minute before it becomes a data outage, which is exactly the
  window [docs/reliability.md](../reliability.md) needs to enter `DEGRADED` and attempt
  recovery before entering `RECONNECTING`.
- **Deterministic failure timing.** `REKEY_ATTEMPT_TIME` (90 s) bounds how long a broken
  handshake is retried before the `Session` reports failure, which turns "it just hangs"
  into a bounded, reportable event with a reason code (I6).
- **Silence under attack.** Not responding to unauthenticated packets means scanning and
  spoofed floods do not consume handshake resources; cookie replies bound the CPU cost of a
  genuine flood.
- **Where a rejected alternative was better:** A3 (QUIC) is materially better on lossy
  paths. QUIC brings loss recovery, pacing, congestion control, and PMTU discovery that
  WireGuard lacks entirely. On a bad mobile link, a QUIC tunnel degrades more gracefully
  than raw WireGuard-over-UDP. We recover part of this only in `T-QUIC` mode; in `T-UDP`
  mode we do not, and MTU/PMTU management becomes an explicit obligation on
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md).

## 9. Performance Implications

| Axis | Selected (A6) | Note |
|---|---|---|
| Linux throughput | Kernel WireGuard; multi-gigabit on commodity hardware | Best available |
| Windows throughput | WireGuardNT kernel driver | Best available |
| macOS / iOS | Userspace in `NEPacketTunnelProvider` | Bounded by C2; ChaCha20-Poly1305 chosen partly because it is fast without AES-NI |
| Android | Userspace `VpnService` | Same |
| Routers / embedded | Kernel WireGuard where the kernel has it; ChaCha20 is fast on ARM without crypto extensions | C7 satisfied |
| Handshake | 1-RTT, 148 B + 92 B, two X25519 operations per side | Cheapest of all alternatives |
| Per-packet overhead, `T-UDP` | 32 B (WG header + tag) + 8 B UDP + 20/40 B IP = **60 / 80 B** | **1440 (v4) / 1420 (v6)** overlay MTU on a 1500 B underlay (`docs/networking.md` §6.1, which owns the accounting) |
| Per-packet overhead, `T-QUIC` | +~25–35 B QUIC framing on top | Inner MTU drops to roughly 1330–1360; MUST be discovered, not assumed |
| Idle power | Zero traffic when idle on a non-NAT path; 25 s keepalive only where required | R11 |
| CPU under rekey | Two X25519 per peer per 120 s — negligible even for a gateway with hundreds of peers (I7) | |

**Where a rejected alternative was better:** A5 (IPsec) wins on raw throughput where NIC
ESP offload exists, and it is the only option with hardware crypto offload on commodity
server NICs. For a personal VPN this does not dominate, but for a high-throughput
`ExitNode` on server hardware it is a genuine loss and is recorded as such.

**Where the selected option costs us:** `T-QUIC` mode is significantly more expensive than
`T-UDP` — userspace QUIC processing plus WireGuard processing per packet. It is a fallback,
and the design MUST prefer `T-UDP` whenever it works (`ADR-0004` owns that preference
ordering). If `T-QUIC` becomes the common case for a user, that is a signal to revisit
(§14).

## 10. Operational Implications

- **Two implementation surfaces to maintain**: a WireGuard datapath per platform (kernel
  where available, a vendored userspace implementation otherwise) and a QUIC stack. Both
  must be CVE-tracked and updated on a defined cadence.
- **No cipher-suite configuration is exposed to users, ever.** There is nothing to
  misconfigure in L-DATA. This is a deliberate operational-security choice: configurability
  here would only create weak deployments.
- **Key ceremony is invisible to users.** Static keys are generated on-device at enrolment
  and never displayed, exported, backed up, or transmitted (I4).
- **Diagnostics must never print key material.** Handshake failures report a reason code and
  the peer's *public* key fingerprint only. See the "never loggable" list in
  [docs/threat-model.md](../threat-model.md) §9 and the constraints on
  [ADR-0015](ADR-0015-observability-and-diagnostics.md).
- **Reason codes minted by this ADR:** `CRYPTO.HANDSHAKE_AUTH_FAILED`, `AUTH.PEER_UNTRUSTED`,
  `AUTH.DEVICE_REVOKED`, `CRYPTO.REPLAY_DETECTED`, `PROTO.DOWNGRADE_REFUSED`, `AUTH.KEY_UNAVAILABLE`,
  `CRYPTO.REKEY_TIMEOUT`, `CRYPTO.PSK_EPOCH_MISMATCH`, `NET.TRANSPORT_BLOCKED`.
- **MTU is an operational hazard.** Each transport mode has a different effective MTU;
  PMTU black holes are a known, common, hard-to-diagnose failure. This ADR requires that MTU
  be *discovered and verified* per path and surfaced in diagnostics, and delegates the
  mechanism to [ADR-0010](ADR-0010-ipv4-ipv6-routing.md).
- **Time dependence.** Handshake replay protection uses TAI64N timestamps, and
  `DeviceCertificate` validity uses wall-clock time. A device with a badly wrong clock will
  fail to connect. This MUST produce a specific, actionable diagnostic
  (`AUTH.CLOCK_IMPLAUSIBLE`) rather than a generic handshake failure — clock skew is a
  classic source of cryptic VPN errors and we are chartered to eliminate those.
- **Auditability.** Because L-DATA is stock WireGuard, an external auditor can review the
  data plane against a published specification rather than against our prose.

## 11. Decision

TwinVPN adopts **A6, a layered cryptographic foundation**:

1. **L-DATA — the user tunnel — is the WireGuard protocol (`Noise_IKpsk2`, X25519,
   ChaCha20-Poly1305, BLAKE2s), unmodified**, established end-to-end between two `Device`s
   and never terminated by any infrastructure component (I1). Parameters are as specified in
   §7.2. The `psk2` slot carries `TwinNetPSK(peer, epoch)` per §7.5.

2. **L-TRANSPORT is pluggable and security-neutral.** L-DATA datagrams ride `T-UDP`
   (direct), `T-RELAY` (inside a device↔relay authenticated session), or `T-QUIC`
   (QUIC DATAGRAM on 443, for UDP-blocked or DPI-hostile networks). Changing transport mode
   MUST NOT re-run the L-DATA handshake, reset counters, or alter any L-DATA security
   property.

3. **L-CONTROL is QUIC + TLS 1.3 with mutual raw-public-key authentication, plus
   end-to-end per-message signatures by `DeviceIdentityKey`.** TLS 1.3 0-RTT is prohibited.
   The control plane is authenticated but not trusted.

4. **L-STORE is platform-native.** `DeviceIdentityKey` is a non-extractable P-256 key in the
   platform secure element and is the attestable root of device identity. The L-DATA X25519
   static private key is sealed under a hardware-bound wrapping key and used only in locked
   memory. The two are cryptographically bound: `DeviceIdentityKey` signs a
   `TunnelKeyBinding` over the X25519 static public key, and peers MUST verify that binding
   before trusting a static key. Details in
   [ADR-0007](ADR-0007-device-identity-and-pairing.md).

5. **Endpoint migration requires authenticated path validation** before bulk traffic commits
   (§7.6), a requirement placed on [ADR-0004](ADR-0004-nat-traversal-strategy.md).

6. **Negotiation happens only inside the authenticated tunnel, with transcript confirmation
   and a monotonic floor** (§7.3), a requirement placed on
   [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md).

7. **No custom primitives, no custom AEAD, no custom handshake, no custom key schedule**
   (I2). The only TwinVPN-designed element is the composition of these layers and the HKDF
   derivation of `TwinNetPSK`, which uses HKDF exactly as specified.

Preference order for `L-TRANSPORT` is `T-UDP` > `T-RELAY` > `T-QUIC` on capability grounds,
but the actual selection policy — including when `T-QUIC` is tried in parallel — belongs to
[ADR-0004](ADR-0004-nat-traversal-strategy.md) and
[ADR-0006](ADR-0006-relay-discovery-and-failover.md). Whatever they choose, **no transport
selection may result in untunneled carriage of protected traffic** (I3).

## 12. Why the Selected Option Won

- **A1 lost on reachability alone.** WireGuard-only means UDP-only, and "does not connect on
  UDP-hostile networks" is one of the exact failure modes this product exists to eliminate.
  Everything else about A1 is excellent, which is why A6 keeps all of it and adds a
  transport escape hatch rather than replacing the protocol.
- **A2 lost on I2.** Instantiating Noise ourselves gives audited primitives inside an
  unaudited protocol. VPNs do not usually fail at the primitive layer; they fail at the
  protocol layer — timer handling, replay windows, rekey races, fragmentation. WireGuard is
  a Noise instantiation that has already survived a decade of that scrutiny. Choosing A2
  would mean re-earning that scrutiny for no capability we cannot get another way.
- **A3 lost as the *tunnel*, and won as a *transport*.** QUIC's migration and
  loss-recovery story is genuinely better than WireGuard's, and its 443/HTTP-3 camouflage is
  genuinely the best answer to blocked UDP. But as the user-traffic tunnel it costs the
  kernel datapath, brings a much larger attack surface, and carries a permanent 0-RTT replay
  liability. A6 takes the part of A3 that we need and leaves the part that hurts.
- **A4 lost as a *foundation*, and won as *storage*.** Platform stacks cannot interoperate
  peer-to-peer across five OSes and do not remove the need to design a tunnel protocol.
  Their storage and attestation half is retained wholesale as L-STORE, which is where their
  real value is.
- **A5 lost on complexity and middlebox reality.** IKEv2's negotiation surface is the
  largest downgrade target on the list, ESP is widely mishandled by consumer CPE, and using
  native OS clients would forfeit control of the kill switch, roaming, and diagnostics — all
  of which are named requirements. Its throughput advantage on offload-capable NICs is real
  but does not outweigh those.
- **The deciding argument for A6 is the migration property.** Separating the session from
  the transport means `WAN_DIRECT ↔ RELAYED ↔ T-QUIC` transitions cost nothing
  cryptographically. Since unreliable relays, relay failover, and roaming are the three
  loudest complaints in the product charter, a foundation that makes path change free is
  worth the cost of understanding two protocols.

## 13. Known Tradeoffs

| # | Tradeoff | Accepted because | Residual risk |
|---|---|---|---|
| K1 | Two protocol stacks (WireGuard + QUIC) to maintain and CVE-track | The capability gain is decisive | Larger maintenance burden; a QUIC CVE affects relay and control legs |
| K2 | The L-DATA static X25519 key is hardware-*wrapped*, not hardware-*resident* (C1) | No secure element performs X25519; the alternative is abandoning WireGuard or abandoning attestation | Code execution as the service on an unlocked device can extract the tunnel static. Mitigated by PSK layering, short `DeviceCertificate` lifetime, and locked memory — not eliminated |
| K3 | Two identity keys (P-256 identity, X25519 tunnel) that must stay bound | Binding is a signature check; the alternative is losing either attestation or WireGuard | A binding-verification bug would be critical; it must be a mandatory, non-skippable check |
| K4 | No crypto agility in L-DATA | Agility is where downgrades live; a break requires a coordinated version bump | A break in X25519 or ChaCha20-Poly1305 is a fleet-wide emergency, not a config change. The PSK slot is the stopgap |
| K5 | No traffic-analysis resistance | Padding and cover traffic cost battery and bandwidth for a benefit most users do not need | Metadata is exposed to on-path observers and relays; documented honestly in [docs/threat-model.md](../threat-model.md) §6 rather than mitigated |
| K6 | `T-QUIC` is camouflage, not unblockable | Real obfuscation is an arms race we are not resourced to run | A determined national-scale censor can block TwinVPN. We do not claim otherwise |
| K7 | Nested congestion control in `T-QUIC` | Only a fallback mode | Possible throughput pathologies on lossy links; must be measured |
| K8 | MTU differs per transport mode | Unavoidable in a layered design | PMTU black holes are the most likely "connected but broken" bug; requires active discovery |
| K9 | Wall-clock dependence (TAI64N, certificate validity) | Standard and necessary for replay/expiry | Devices with wrong clocks fail; must produce `AUTH.CLOCK_IMPLAUSIBLE`, not a generic error |
| K10 | Revocation propagation is not instant | Offline peers cannot learn of revocation immediately | A revoked device retains access to an offline peer until PSK epoch or certificate expiry catches up. Bounded, not zero — see [ADR-0007](ADR-0007-device-identity-and-pairing.md) §13 |

## 13.1 Assumptions directed at this ADR

| # | Assumption | Source | Disposition |
|---|---|---|---|
| **A1** | The control channel is mutually authenticated to `DeviceKey`, giving a TLS-exporter channel binding usable as `Auth.channel_binding` | protocol.md §18 | **CONFIRMED** — §7.2 L-CTRL, RFC 7250 raw public key + RFC 9266 `tls-exporter` |
| **A2** | The peer handshake accepts an application-supplied prologue so the negotiated version + capability set can be bound into it | protocol.md §18 | **CONFIRMED** — §7.3.1 defines the single 83-byte prologue and the two contributed digests |
| **A3** | A signature scheme with a deterministic canonical input encoding is available, verified over received octets | protocol.md §18 | **CONFIRMED**, jointly with [ADR-0003](ADR-0003-network-contract-schema-format.md) §11 (deterministic CBOR in COSE_Sign1, never re-serialized) |
| **A4** | Session resumption exists at the tunnel layer and requires no control-plane round trip | protocol.md §18 | **CONFIRMED with a scope correction** — §7.3.2. Resumption survives a path change, **not** a process restart; protocol.md §12.1's trigger list must drop "process restart" |
| **A-05** | The tunnel provides a `Path`-independent cryptographic session surviving endpoint change without re-authentication, rekeying without a control-plane call | architecture.md §9 | **CONFIRMED** — §7.6, §7.3.2 |
| **A-06** | The tunnel exposes a "reject handshake from this peer key" hook usable by revocation | architecture.md §9 | **CONFIRMED** — §7.5's `psk2` epoch exclusion is the hook, and it is cryptographic rather than advisory |
| **A1 (networking)** | WireGuard/Noise-shaped UDP, ~32 B per-packet overhead, rekey without changing overlay addresses, disco multiplexed on the same socket | networking.md §11 | **CONFIRMED** — §7.2, §7.6 |
| **A-05 (testing)** | E2E encryption with no relay party to the handshake; a `Relay` is cryptographically indistinguishable from an on-path attacker | testing-strategy.md §0 | **CONFIRMED** — jointly with [ADR-0005](ADR-0005-relay-architecture.md) §7.1's closed three-key relay inventory, which is what makes proof test **P14** structural |

---

## 14. Revisit Conditions
This decision MUST be re-opened if any of the following becomes true.

| # | Falsifiable trigger |
|---|---|
| V1 | A practical cryptanalytic result reduces X25519 below ~110-bit classical security, or any attack on ChaCha20-Poly1305 or BLAKE2s better than generic is published. Immediate emergency revisit. |
| V2 | A hybrid post-quantum key agreement (e.g. an ML-KEM-768 + X25519 construction) is standardised for the Noise/WireGuard PSK path **and** has a published independent audit. Then the PSK slot migration in §7.5 is executed and this ADR is amended. |
| V3 | `T-QUIC` exceeds **15 % of connection-minutes** across the fleet for two consecutive months, or exceeds 40 % for any single user for a week. That means UDP-blocked networks are the common case, and a QUIC-native data plane (A3) becomes the better base. |
| V4 | Measured `T-QUIC` goodput on a reference lossy path (5 % loss, 80 ms RTT) is below **60 %** of `T-UDP` goodput on the same path, indicating the nested-CC pathology in K7 is real and material. |
| V5 | A secure element in general availability on two or more of our platforms performs X25519 (or Ed25519-with-X25519-conversion) in hardware. Then K2 can be retired and the tunnel static becomes hardware-resident. |
| V6 | Apple, Google, or Microsoft removes or materially restricts the API our datapath depends on (`NEPacketTunnelProvider`, `VpnService`, WFP/WireGuardNT driver signing), such that the current datapath cannot ship. |
| V7 | An `ExitNode` deployment requires sustained throughput above what a userspace or kernel WireGuard datapath delivers on the target hardware, and NIC-offloaded ESP (A5) would demonstrably meet it. Then a *second*, additive data plane for that role may be justified — never a replacement for the peer mesh. |
| V8 | WireGuard's upstream protocol makes a breaking change, or the project becomes unmaintained with no credible successor. |
| V9 | Fleet telemetry shows handshake failure attributable to clock skew (`AUTH.CLOCK_IMPLAUSIBLE`) above 0.5 % of handshake attempts, indicating the wall-clock dependence in K9 needs a different mitigation. |
| V10 | Independent security review finds that the L-DATA/L-TRANSPORT composition (§11, item 2) admits any attack that neither layer admits alone. That would falsify the central premise of this ADR. |
