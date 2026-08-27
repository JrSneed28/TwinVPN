"""Structural invariants of the schema itself, read from the compiled image.

These are the checks a code review cannot be relied upon to perform every time:
they are mechanical, they run on every commit, and they fail the build.
"""
from harness import case, check, check_eq, image, limits

# Field/message names that would carry material Phase 1 forbids from ever being
# serialized. ADR-0007 N-5, N-19; S-13; S-33; ADR-0018 CB-5 row 1; I4.
#
# Matching is on a SUBSTRING of the lowercased field name, so `private_key`,
# `device_private_key` and `identity_privatekey` all trip. The list is
# deliberately broader than the exact Phase 1 wording: the point is to make an
# accidental addition impossible, not to enumerate the ones already known.
FORBIDDEN_SUBSTRINGS = [
    "private_key", "privatekey", "secret_key", "secretkey",
    "pair_secret", "pairsecret", "pairing_secret",
    "session_key", "sessionkey", "chaining_key",
    "epoch_seed", "epochseed",
    "resumption_secret", "psk", "passphrase", "password",
    "recovery_phrase", "mnemonic", "seed_phrase",
    "keystore_blob", "keychain_blob", "dpapi", "enclave_key",
    "plaintext", "packet_payload", "payload_bytes",
    "query_name", "qname", "dns_query", "browsing", "visited_host",
    "bearer_token", "access_token", "refresh_token", "api_key",
]

# Fields whose names contain a forbidden substring but are provably not the
# forbidden thing, each with the reason it is safe.
SECRET_ALLOWLIST = {
    # Public halves. The word "key" with an explicit "public" qualifier.
    "twinvpn.v1.DeviceIdentity.identity_public_key": "COSE_Key of the PUBLIC ES256 half",
    "twinvpn.v1.DeviceIdentity.tunnel_public_key": "COSE_Key of the PUBLIC X25519 half",
    "twinvpn.v1.Relay.static_noise_public_key": "the relay's PUBLIC static, published in the signed map",
}


def _walk(msgs, prefix, out):
    for m in msgs or []:
        full = f"{prefix}.{m['name']}"
        out.append((full, m))
        _walk(m.get("nestedType"), full, out)


def all_messages(img):
    out = []
    for f in img["file"]:
        _walk(f.get("messageType"), f["package"], out)
    return out


def all_enums(img):
    out = []
    for f in img["file"]:
        for e in f.get("enumType") or []:
            out.append((f"{f['package']}.{e['name']}", e))
        for full, m in all_messages(img):
            pass
    for full, m in all_messages(img):
        for e in m.get("enumType") or []:
            out.append((f"{full}.{e['name']}", e))
    return out


def run():
    img = image()
    lim = limits()
    msgs = all_messages(img)
    enums = all_enums(img)

    # -- Secret-field absence -------------------------------------------------
    # The single most consequential test in this file. A schema that CAN carry a
    # private key will eventually carry one.
    case("secret-field absence")
    for full, m in msgs:
        for fld in m.get("field") or []:
            fq = f"{full}.{fld['name']}"
            if fq in SECRET_ALLOWLIST:
                continue
            low = fld["name"].lower()
            for bad in FORBIDDEN_SUBSTRINGS:
                check(
                    bad not in low,
                    f"{fq} contains forbidden substring '{bad}' - Phase 1 forbids "
                    f"serializing this class of material (I4, ADR-0007 N-5/N-19, "
                    f"S-13, S-33, ADR-0015 SECRET classification)",
                )

    # ADR-0015 §11.4 gives FieldClassification exactly three members. A SECRET
    # value would create the code path the ADR says does not exist.
    case("no SECRET classification value")
    fc = dict(enums).get("twinvpn.v1.FieldClassification")
    check(fc is not None, "FieldClassification enum must exist")
    if fc:
        names = {v["name"] for v in fc["value"]}
        check(
            "FIELD_CLASSIFICATION_SECRET" not in names,
            "FieldClassification MUST NOT have a SECRET member: ADR-0015 §11.4 says "
            "SECRET material is never stored and never rendered, and giving it an "
            "enum value would create the code path",
        )

    # -- Enum hygiene ---------------------------------------------------------
    case("enum zero value is UNSPECIFIED")
    for full, e in enums:
        zeros = [v for v in e["value"] if v.get("number", 0) == 0]
        check_eq(len(zeros), 1, f"{full} must have exactly one zero value")
        if zeros:
            check(
                zeros[0]["name"].endswith("_UNSPECIFIED"),
                f"{full} zero value {zeros[0]['name']} must end in _UNSPECIFIED - an "
                f"unknown enum value decodes to 0 and MUST be distinguishable from a "
                f"meaningful default",
            )

    case("enum values are unique and stable")
    for full, e in enums:
        nums = [v.get("number", 0) for v in e["value"]]
        check_eq(
            len(nums), len(set(nums)),
            f"{full} has duplicate enum numbers - aliasing makes an unknown value "
            f"indistinguishable from a known one",
        )

    # -- The connection-state vocabulary must not fork ------------------------
    # docs/reliability.md §4 owns these twelve names. A thirteenth here means a
    # second state machine has been created.
    case("ConnectionState is exactly the twelve reliability.md names")
    cs = dict(enums).get("twinvpn.v1.ConnectionState")
    check(cs is not None, "ConnectionState must exist")
    if cs:
        got = {v["name"] for v in cs["value"]} - {"CONNECTION_STATE_UNSPECIFIED"}
        want = {
            "CONNECTION_STATE_DISCONNECTED", "CONNECTION_STATE_DISCOVERING",
            "CONNECTION_STATE_NEGOTIATING", "CONNECTION_STATE_CONNECTING",
            "CONNECTION_STATE_LOCAL_DIRECT", "CONNECTION_STATE_WAN_DIRECT",
            "CONNECTION_STATE_RELAYED", "CONNECTION_STATE_MIGRATING",
            "CONNECTION_STATE_DEGRADED", "CONNECTION_STATE_RECONNECTING",
            "CONNECTION_STATE_BLOCKED", "CONNECTION_STATE_FAILED",
        }
        check_eq(got, want, "ConnectionState members")
        # Values must be stable: these numbers appear in ErrorEnvelope.state_from
        # and state_to and in every stored transition record.
        by_name = {v["name"]: v.get("number", 0) for v in cs["value"]}
        check_eq(by_name["CONNECTION_STATE_DISCONNECTED"], 1, "DISCONNECTED value")
        check_eq(by_name["CONNECTION_STATE_BLOCKED"], 11, "BLOCKED value")
        check_eq(by_name["CONNECTION_STATE_FAILED"], 12, "FAILED value")

    case("HealthState is not a ConnectionState")
    hs = dict(enums).get("twinvpn.v1.HealthState")
    check(hs is not None, "HealthState must exist")
    if hs:
        got = {v["name"] for v in hs["value"]} - {"HEALTH_STATE_UNSPECIFIED"}
        check_eq(
            got,
            {"HEALTH_STATE_HEALTHY", "HEALTH_STATE_DEGRADED",
             "HEALTH_STATE_UNHEALTHY", "HEALTH_STATE_UNKNOWN"},
            "HealthState members (docs/reliability.md §4.1: exactly four, sharing "
            "only the name DEGRADED with a ConnectionState)",
        )

    # -- reason_code must be a string, never an enum --------------------------
    # ADR-0015 §11.2, normative: prefix degradation and unknown-code passthrough
    # both require the receiver to hold the unrecognised code's TEXT. A protobuf
    # enum preserves an unknown value only as an integer, which discards DOMAIN.
    case("reason_code is carried as a string")
    for full, m in msgs:
        for fld in m.get("field") or []:
            if fld["name"] in ("reason_code", "domain") or fld["name"].endswith(
                "reason_codes"
            ):
                check_eq(
                    fld["type"], "TYPE_STRING",
                    f"{full}.{fld['name']} must be a string, never an enum "
                    f"(ADR-0015 §11.2)",
                )

    # -- IPv4/IPv6 co-equality ------------------------------------------------
    # ADR-0010 R1 and docs/protocol.md §13.4: a field set that offers v4 without
    # a matching v6 is how a v6-aware design degrades into a v4-only one.
    case("every _v4 field has a matching _v6 field")
    for full, m in msgs:
        names = {f["name"] for f in m.get("field") or []}
        for n in sorted(names):
            if n.endswith("_v4"):
                partner = n[:-3] + "_v6"
                check(
                    partner in names,
                    f"{full}.{n} has no matching {partner} - IPv4 and IPv6 are "
                    f"co-equal (ADR-0010 R1); an unmatched v4 field makes 'we "
                    f"forgot v6' indistinguishable from 'there is no v6'",
                )
            if n.endswith("_v6"):
                partner = n[:-3] + "_v4"
                check(partner in names, f"{full}.{n} has no matching {partner}")

    case("addresses are fixed-width binary, never strings")
    by_name = dict(msgs)
    for tname, want_len in (
        ("twinvpn.v1.IPv4Address", lim["routing"]["ipv4_address_bytes"]),
        ("twinvpn.v1.IPv6Address", lim["routing"]["ipv6_address_bytes"]),
    ):
        m = by_name.get(tname)
        check(m is not None, f"{tname} must exist")
        if m:
            octets = [f for f in m["field"] if f["name"] == "octets"]
            check_eq(len(octets), 1, f"{tname}.octets")
            if octets:
                check_eq(
                    octets[0]["type"], "TYPE_BYTES",
                    f"{tname}.octets must be bytes, not a string - a textual address "
                    f"admits '010.0.0.1', '::ffff:10.0.0.1' and every other "
                    f"parser-divergence vector at a hostile boundary",
                )

    case("IPv6Address carries a zone index")
    m = by_name.get("twinvpn.v1.IPv6Address")
    if m:
        check(
            any(f["name"] == "zone_index" for f in m["field"]),
            "IPv6Address must carry zone_index: link-local host candidates are "
            "unusable on multi-interface hosts without it (docs/protocol.md §10.4)",
        )

    case("IPAddress makes 'both families' unrepresentable")
    m = by_name.get("twinvpn.v1.IPAddress")
    if m:
        check(
            len(m.get("oneofDecl") or []) == 1,
            "IPAddress must use a oneof so exactly one family is set",
        )

    # -- Metadata completeness ------------------------------------------------
    case("MessageMetadata carries the full standard field set")
    m = by_name.get("twinvpn.v1.MessageMetadata")
    check(m is not None, "MessageMetadata must exist")
    if m:
        names = {f["name"] for f in m["field"]}
        for required in (
            "proto_version", "message_id", "correlation_id", "causation_id",
            "causality_token", "sender_time_ms", "twinnet_id", "sender_id",
            "net_seq", "idempotency_key", "auth",
        ):
            check(required in names, f"MessageMetadata.{required} is required")

    case("ResolvedAttributes carries no localized text")
    m = by_name.get("twinvpn.v1.ResolvedAttributes")
    if m:
        names = {f["name"] for f in m["field"]}
        for forbidden in ("summary", "message", "title", "text", "description"):
            check(
                forbidden not in names,
                f"ResolvedAttributes.{forbidden} would place a second text authority "
                f"outside the registry (ADR-0015 §11.2 rule 4, ADR-0018 F-4, "
                f"ADR-0017 MI-15). Only *_key lookup keys are permitted",
            )
        check("summary_key" in names, "summary_key is required")
        check("next_action_key" in names, "next_action_key is required")

    # -- The two clocks must stay distinct ------------------------------------
    case("wall clock and monotonic clock are separate types")
    check("twinvpn.v1.WallClockMillis" in by_name, "WallClockMillis must exist")
    check("twinvpn.v1.MonotonicMicros" in by_name, "MonotonicMicros must exist")

    # A field named *_at without a unit suffix is ambiguous about which clock it
    # reads, which is exactly the confusion that puts a wall clock on a timeout.
    case("timestamp fields declare their clock")
    for full, m in msgs:
        for fld in m.get("field") or []:
            n = fld["name"]
            if fld["type"] in ("TYPE_UINT64", "TYPE_INT64") and (
                n.endswith("_at") or n == "occurred_at" or n == "observed_at"
            ):
                check(
                    False,
                    f"{full}.{n} is a bare integer instant: name it *_ms for wall "
                    f"clock or use MonotonicMicros, so the clock is unambiguous",
                )

    # -- Reserved-field discipline -------------------------------------------
    # v1 has removed nothing yet, so the correct assertion today is that nothing
    # claims a reserved number it should not. This check becomes load-bearing at
    # the first removal; it exists now so that removal cannot land without it.
    case("no field number collides with a reserved range")
    for full, m in msgs:
        reserved = []
        for r in m.get("reservedRange") or []:
            reserved.append((r.get("start", 0), r.get("end", 0)))
        reserved_names = set(m.get("reservedName") or [])
        for fld in m.get("field") or []:
            num = fld.get("number", 0)
            for start, end in reserved:
                check(
                    not (start <= num < end),
                    f"{full}.{fld['name']} uses reserved number {num} - a reused "
                    f"field number silently reinterprets old bytes",
                )
            check(
                fld["name"] not in reserved_names,
                f"{full}.{fld['name']} reuses a reserved name",
            )

    case("field numbers do not enter the protobuf-internal range")
    for full, m in msgs:
        for fld in m.get("field") or []:
            num = fld.get("number", 0)
            check(
                not (19000 <= num <= 19999),
                f"{full}.{fld['name']} uses reserved-for-protobuf number {num}",
            )
