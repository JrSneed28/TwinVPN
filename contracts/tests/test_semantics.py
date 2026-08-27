"""Semantic invariants: identifiers, explicit presence, idempotency metadata,
correlation and causation, and the durable/ephemeral boundary.

These are the rules a schema alone cannot express but which Phase 1 states
normatively, so they are asserted mechanically here rather than trusted to
review.
"""
from harness import case, check, check_eq, image, limits, registry

from test_schema_structure import all_messages, all_enums


def run():
    img = image()
    lim = limits()
    msgs = dict(all_messages(img))
    enums = dict(all_enums(img))
    ids = lim["identifiers"]

    # -- Identifier typing ----------------------------------------------------
    # Every identifier is either opaque bytes of an exact size, or a bounded
    # opaque string. Phase 1 prefers opaque identifiers throughout; the two
    # exceptions - twinnet_id and region_id - are strings because they are
    # operator-facing, and both are still opaque to a device (a device MUST NOT
    # parse region_id for geography).
    case("binary identifiers are bytes, never strings")
    BINARY_IDS = {
        "device_id", "peer_device_id", "target_device_id", "identity_id",
        "advertiser_device_id", "initiator_device_id", "joiner_device_id",
        "gateway_device_id", "exit_node_device_id", "attesting_device_id",
        "subject_device_id", "object_device_id", "object_exit_node_device_id",
        "next_hop_device_id", "conflicting_source_device_id",
        "default_route_exit_node_device_id", "device_id_echo",
        "pairing_id", "session_id", "tunnel_id", "path_id", "candidate_id",
        "relay_id", "from_relay_id", "to_relay_id", "pair_tag", "flow_id",
        "message_id", "correlation_id", "causation_id", "idempotency_key",
        "session_nonce", "probe_id", "resumption_id", "digest", "schema_digest",
        "negotiation_hash", "transcript_commitment", "delegation_set_digest",
        "relay_flow_id",
    }
    for full, m in msgs.items():
        for fld in m.get("field") or []:
            if fld["name"] in BINARY_IDS:
                check_eq(
                    fld["type"], "TYPE_BYTES",
                    f"{full}.{fld['name']} must be bytes - an identifier rendered as "
                    f"text admits case, encoding and padding variance at a boundary "
                    f"where set membership must be exact",
                )

    case("every declared identifier size is exact and documented")
    for k, v in ids.items():
        if k.endswith("_bytes") and not k.endswith("_max_bytes") and not k.endswith("_min_bytes"):
            check(v > 0, f"limits.identifiers.{k} must be positive")
    check_eq(ids["device_id_bytes"], 32,
             "device_id is SHA-256, UNTRUNCATED (ADR-0007 N-2)")
    check_eq(ids["identity_id_bytes"], 32, "identity_id is SHA-256, untruncated")
    check_eq(ids["pairing_id_bytes"], 16,
             "pairing_id is SHA-256(pairing_secret)[0..15]")
    check_eq(ids["message_id_bytes"], 16, "message_id is a UUIDv7")
    check(
        ids["idempotency_key_min_bytes"] * 8 >= 128,
        "ADR-0008 N-4 requires >= 128 bits of randomness in an idempotency key, so "
        "cross-caller collision is negligible even though per-caller scoping already "
        "prevents it",
    )
    check_eq(ids["channel_binding_bytes"], 32,
             "RFC 9266 tls-exporter is 32 bytes (ADR-0002 N-2)")

    # -- Explicit presence where Phase 1 forbids defaulting -------------------
    # docs/protocol.md §13.3: "an explicit per-family grant/deny, WITH NO
    # DEFAULTING: an absent field is a denial, not a permission."
    # docs/protocol.md §13.4: block_fallback is DENY-SHAPED - `false` is a GRANT.
    #
    # Under proto3 IMPLICIT presence absent and false are one wire state, so a
    # bare bool cannot express "no defaulting" and, for a deny-shaped field,
    # silently authors the PERMISSIVE value by omission.
    case("no-defaulting fields have explicit presence")
    NO_DEFAULTING = {
        ("twinvpn.v1.ExitNode", "supports_default_v4"),
        ("twinvpn.v1.ExitNode", "supports_default_v6"),
        ("twinvpn.v1.ExitNodeGrant", "granted_default_v4"),
        ("twinvpn.v1.ExitNodeGrant", "granted_default_v6"),
        ("twinvpn.v1.LanAccessGrant", "granted"),
        ("twinvpn.v1.LanAccessRule", "allow"),
        ("twinvpn.v1.PeerPermission", "allow"),
        ("twinvpn.v1.DNSPolicy", "block_fallback_v4"),
        ("twinvpn.v1.DNSPolicy", "block_fallback_v6"),
        ("twinvpn.v1.DNSPolicy", "servers_declared_v4"),
        ("twinvpn.v1.DNSPolicy", "servers_declared_v6"),
        ("twinvpn.v1.RoutePolicy", "default_route_v4"),
        ("twinvpn.v1.RoutePolicy", "default_route_v6"),
    }
    for tname, fname in sorted(NO_DEFAULTING):
        m = msgs.get(tname)
        check(m is not None, f"{tname} must exist")
        if not m:
            continue
        fld = next((f for f in m["field"] if f["name"] == fname), None)
        check(fld is not None, f"{tname}.{fname} must exist")
        if fld:
            check(
                fld.get("proto3Optional") is True,
                f"{tname}.{fname} must be declared `optional` for EXPLICIT PRESENCE. "
                f"Phase 1 requires this field to be explicitly stated with no "
                f"defaulting; under implicit presence a receiver cannot distinguish "
                f"'the author denied it' from 'the author never considered it', and "
                f"for a deny-shaped field omission silently authors the permissive "
                f"value",
            )

    # -- Idempotency metadata -------------------------------------------------
    case("every mutating request carries metadata with an idempotency key slot")
    CEREMONY_REQUESTS = [
        "RegisterDeviceRequest", "RevokeDeviceRequest",
        "RotateDeviceCredentialRequest", "BeginPairingRequest",
        "CompletePairingRequest", "CancelPairingRequest", "RevokePairingRequest",
        "PutPolicyRequest",
    ]
    DECLARATIVE_REQUESTS = [
        "UpdateDeviceMetadataRequest", "PutRouteAdvertisementRequest",
        "WithdrawRouteAdvertisementRequest", "PutExitNodeOfferRequest",
        "WithdrawExitNodeOfferRequest",
    ]
    for name in CEREMONY_REQUESTS + DECLARATIVE_REQUESTS:
        full = f"twinvpn.v1.{name}"
        m = msgs.get(full)
        check(m is not None, f"{full} must exist")
        if m:
            check(
                any(f["name"] == "metadata" for f in m["field"]),
                f"{full} must carry MessageMetadata - it is the only place "
                f"idempotency_key, correlation_id and causation_id are defined",
            )

    case("declarative mutations carry a version precondition")
    # ADR-0008 N-2: every mutating request is conditional on the version the
    # caller believes it is updating, and N-6 makes that precondition - not a
    # longer dedup window - what closes the expiry cliff.
    for name in ("UpdateDeviceMetadataRequest", "CompletePairingRequest",
                 "PutPolicyRequest"):
        m = msgs.get(f"twinvpn.v1.{name}")
        if m:
            check(
                any(f["name"] == "precondition" for f in m["field"]),
                f"{name} must carry a VersionPrecondition (ADR-0008 N-2). Without it "
                f"a duplicate arriving after the 24 h dedup window would RE-EXECUTE "
                f"rather than fail",
            )

    case("VersionPrecondition makes 'no precondition' unrepresentable")
    m = msgs.get("twinvpn.v1.VersionPrecondition")
    check(m is not None, "VersionPrecondition must exist")
    if m:
        check_eq(
            len(m.get("oneofDecl") or []), 1,
            "VersionPrecondition must be a oneof of if_version | if_absent, so "
            "creation-conditional-on-absence and update-conditional-on-version are "
            "the only two shapes",
        )

    case("every mutating response reports its commit position")
    for name in ("RegisterDeviceResponse", "UpdateDeviceMetadataResponse",
                 "RevokeDeviceResponse", "RotateDeviceCredentialResponse",
                 "BeginPairingResponse", "CompletePairingResponse",
                 "CancelPairingResponse", "RevokePairingResponse",
                 "PutRouteAdvertisementResponse", "WithdrawRouteAdvertisementResponse",
                 "PutExitNodeOfferResponse", "WithdrawExitNodeOfferResponse",
                 "PutPolicyResponse"):
        m = msgs.get(f"twinvpn.v1.{name}")
        check(m is not None, f"{name} must exist")
        if m:
            check(
                any(f["name"] == "result" for f in m["field"]),
                f"{name} must carry MutationResult. docs/protocol.md §5.1 makes "
                f"committed_at_net_seq a PROTOCOL OBLIGATION: the client library MUST "
                f"NOT report the operation complete until the C2 cursor reaches it",
            )

    case("MutationResult carries the read-your-writes position")
    m = msgs.get("twinvpn.v1.MutationResult")
    if m:
        names = {f["name"] for f in m["field"]}
        check("committed_at_net_seq" in names, "committed_at_net_seq is required")
        check(
            "revocation_epoch" in names,
            "revocation_epoch must ride every response so a device detects it is "
            "behind WITHOUT DRAINING THE LOG (docs/protocol.md §8.3)",
        )
        check(
            "idempotent_replay" in names,
            "a recorded-outcome replay must be OBSERVABLE (ADR-0008 §10.2 requires "
            "idempotent_replay_served as a structured event)",
        )

    case("every response can carry an ErrorEnvelope")
    for full, m in msgs.items():
        if full.endswith("Response"):
            names = {f["name"] for f in m["field"]}
            check(
                "error" in names,
                f"{full} has no error field. docs/protocol.md §17 obligation 1: EVERY "
                f"response that is not a success MUST carry at least one reason code",
            )

    # -- Correlation and causation -------------------------------------------
    case("correlation and causation are distinct fields")
    m = msgs["twinvpn.v1.MessageMetadata"]
    fields = {f["name"]: f for f in m["field"]}
    check("correlation_id" in fields and "causation_id" in fields,
          "both must exist as separate fields")
    check(
        fields["correlation_id"]["number"] != fields["causation_id"]["number"],
        "correlation and causation are different facts: one answers 'what is this a "
        "reply to', the other 'what made this happen'. They differ whenever an event "
        "is a second-order consequence",
    )

    # -- Durable versus ephemeral --------------------------------------------
    case("the durability classification is on the wire and assertable")
    m = msgs.get("twinvpn.v1.ControlEvent")
    check(m is not None, "ControlEvent must exist")
    if m:
        names = {f["name"] for f in m["field"]}
        check(
            "durability" in names,
            "a receiver must be able to assert the classification it expected: a "
            "DURABLE event with net_seq == 0, or an EPHEMERAL one with net_seq != 0, "
            "is a defect and must be rejected rather than applied",
        )
        check(
            "publisher" in names,
            "docs/protocol.md §7 / I8: a receiver MUST REJECT an event whose publisher "
            "is not its sole publisher, with CONTROL.EVENT_WRONG_PUBLISHER treated as "
            "a security event",
        )

    case("ephemeral connection signalling is not a durable control-plane event")
    # docs/protocol.md §7: SessionStateChanged is LOCAL-AUTHORITY. Promoting any
    # of these to C2 would make a control-plane outage put every session into an
    # indeterminate state, and reconciliation would eventually tear tunnels down.
    ev = msgs["twinvpn.v1.ControlEvent"]
    control_bodies = set()
    for od in ev.get("oneofDecl") or []:
        pass
    for f in ev["field"]:
        if f.get("typeName"):
            control_bodies.add(f["typeName"].lstrip("."))
    MUST_NOT_BE_CONTROL_EVENTS = {
        "twinvpn.v1.SessionStarted", "twinvpn.v1.SessionResumed",
        "twinvpn.v1.SessionEnded", "twinvpn.v1.PathChanged",
        "twinvpn.v1.TunnelStateChanged", "twinvpn.v1.ConnectionHealthChanged",
        "twinvpn.v1.ConnectionRequested", "twinvpn.v1.ConnectionNegotiated",
        "twinvpn.v1.CandidateUpdated", "twinvpn.v1.DirectPathEstablished",
        "twinvpn.v1.RelayBindRequested", "twinvpn.v1.RelayBound",
        "twinvpn.v1.RelayUnavailable", "twinvpn.v1.RelayChanged",
        "twinvpn.v1.TransitionEvent",
    }
    for t in sorted(MUST_NOT_BE_CONTROL_EVENTS):
        check(
            t not in control_bodies,
            f"{t} appears in ControlEvent. It is DEVICE-AUTHORITATIVE and EPHEMERAL "
            f"(docs/protocol.md §7); making it a durable control-plane event would "
            f"break I5",
        )
        check(t in msgs, f"{t} must exist in diagnostics.proto as a local event")

    case("local session events live in the SessionEvent envelope")
    se = msgs.get("twinvpn.v1.SessionEvent")
    check(se is not None, "SessionEvent must exist")
    if se:
        bodies = {f["typeName"].lstrip(".") for f in se["field"] if f.get("typeName")}
        for t in sorted(MUST_NOT_BE_CONTROL_EVENTS):
            check(t in bodies or t == "twinvpn.v1.TransitionEvent",
                  f"{t} must be reachable from SessionEvent")

    # -- Relay zero-plaintext-access -----------------------------------------
    case("relay contracts identify a pair only by pair_tag")
    for tname in ("twinvpn.v1.RelayBinding", "twinvpn.v1.RelayCapabilityTokenDescriptor",
                  "twinvpn.v1.RelayDrain", "twinvpn.v1.Relay", "twinvpn.v1.RelayHealth"):
        m = msgs.get(tname)
        if m:
            for fld in m["field"]:
                n = fld["name"]
                check(
                    "peer_key" not in n and n != "peer_device_id"
                    and not n.startswith("device_id"),
                    f"{tname}.{n} would tell the relay WHICH TWO DEVICES ARE TALKING. "
                    f"docs/protocol.md §16 row 21 withdrew the former peer_key_id for "
                    f"exactly this reason; the table is keyed by pair_tag, a one-way "
                    f"HKDF output scoped to one relay and one 10-minute bucket",
                )
    check(
        any(f["name"] == "pair_tag" for f in msgs["twinvpn.v1.RelayBinding"]["field"]),
        "RelayBinding must be keyed by pair_tag",
    )

    case("relay telemetry carries no per-session or peer-pair label")
    m = msgs.get("twinvpn.v1.RelayHealth")
    if m:
        names = {f["name"] for f in m["field"]}
        for forbidden in ("session_id", "pair_tag", "flow_id", "device_id"):
            check(
                forbidden not in names,
                f"RelayHealth.{forbidden} would give infrastructure a peer-pair "
                f"correlation label, which ADR-0015 O-13 forbids outright",
            )
