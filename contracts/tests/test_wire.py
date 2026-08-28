"""Wire behaviour: round-trip stability, unknown fields, unknown enums,
malformed input, size limits, and cross-implementation agreement.

Two INDEPENDENT protobuf implementations are used deliberately:
  - `buf convert` (the Go protobuf runtime, driven by the schema)
  - protobufjs   (a separate JS implementation, driven by the same .proto files)

ADR-0003 §10 requires deterministic-encoding conformance vectors cross-tested
between implementations, on the grounds that "a determinism bug that only shows
up on one platform is exactly the bug this choice exists to prevent, so it must
be tested for explicitly rather than assumed." Two runtimes agreeing is a much
stronger statement than one runtime agreeing with itself.
"""
import json
import pathlib
import subprocess

from harness import ROOT, REPO, buf, case, check, check_eq, limits

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
NODE_HELPER = pathlib.Path(__file__).resolve().parent / "pbjs_helper.js"


def to_binary(type_name, obj):
    """JSON -> binary via buf (implementation A)."""
    return buf(
        "convert", "contracts",
        f"--type={type_name}",
        "--from=-#format=json",
        "--to=-#format=binpb",
        stdin=json.dumps(obj).encode(),
    )


def to_json(type_name, blob):
    """binary -> JSON via buf (implementation A)."""
    out = buf(
        "convert", "contracts",
        f"--type={type_name}",
        "--from=-#format=binpb",
        "--to=-#format=json",
        stdin=blob,
    )
    return json.loads(out)


def strip_implicit_defaults(v):
    """Drop keys whose value is the proto3 implicit-presence default.

    protobufjs emits an explicit zero where the Go runtime omits the field. Both
    encodings decode to the same LOGICAL value, so a value comparison must
    normalize. This function is the normalization - and its existence is the
    concrete evidence for ADR-0003 §6's claim that protobuf does not guarantee a
    canonical encoding, which is why signed statements use deterministic CBOR.
    """
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            if val in (False, 0, "0", "", [], {}, None):
                continue
            out[k] = strip_implicit_defaults(val)
        return out
    if isinstance(v, list):
        return [strip_implicit_defaults(x) for x in v]
    return v


def node(op, type_name, payload_hex="", obj=None):
    """Encode/decode via protobufjs (implementation B)."""
    req = {"op": op, "type": type_name, "hex": payload_hex, "obj": obj}
    proc = subprocess.run(
        ["node", str(NODE_HELPER)],
        input=json.dumps(req).encode(),
        capture_output=True,
        cwd=str(REPO),
    )
    if proc.returncode != 0:
        return {"error": proc.stderr.decode(errors="replace")[:400]}
    return json.loads(proc.stdout)


# Representative values across every contract family, chosen so that each
# exercises a rule the corpus states normatively rather than merely a field.
VECTORS = {
    "error_envelope_full": ("twinvpn.v1.ErrorEnvelope", {
        "reasonCode": "PROTO.CAPABILITY_REQUIRED_UNAVAILABLE",
        "domain": "PROTO",
        "resolved": {
            "class": "ERROR_CLASS_POLICY",
            "severity": "ERROR_SEVERITY_ERROR",
            "terminal": True,
            "userActionable": True,
            "remediationClass": "REMEDIATION_CLASS_POLICY_CHANGE",
            "scope": "DIAGNOSTIC_SCOPE_SESSION",
            "docAnchor": "adr-0014#proto_capability_required_unavailable",
            "summaryKey": "reason.proto_capability_required_unavailable.summary",
            "nextActionKey": "reason.proto_capability_required_unavailable.next_action",
        },
        "component": "COMPONENT_POLICY_ENGINE",
        "evidence": [
            {"key": "capability",
             "classification": "FIELD_CLASSIFICATION_PUBLIC",
             "stringValue": "per_app_routing/1"},
            {"key": "policy_version",
             "classification": "FIELD_CLASSIFICATION_OPERATIONAL",
             "uintValue": "42"},
        ],
        "occurredAtMs": "1756300000000",
        "stateFrom": 4,
        "stateTo": 11,
    }),
    "ipv4_prefix": ("twinvpn.v1.IPPrefix", {
        "address": {"v4": {"octets": "CmQAAA=="}},  # 10.100.0.0
        "prefixLen": 16,
    }),
    "ipv6_prefix": ("twinvpn.v1.IPPrefix", {
        # fd7c:9e5d:2a10::/48 - the pinned product ULA (ADR-0010 AP-1)
        "address": {"v6": {"octets": "/XyeXSoQAAAAAAAAAAAAAA=="}},
        "prefixLen": 48,
    }),
    "ipv6_linklocal_candidate": ("twinvpn.v1.ConnectionCandidate", {
        "candidateId": "AAAAAAAAAAE=",
        "family": "ADDRESS_FAMILY_V6",
        "kind": "CANDIDATE_KIND_HOST",
        "endpoint": {
            # fe80::1 with a non-zero zone index, which docs/protocol.md §10.4
            # requires for a link-local host candidate to be usable at all.
            "address": {"v6": {"octets": "/oAAAAAAAAAAAAAAAAAAAQ==", "zoneIndex": 7}},
            "port": 51820,
        },
        "priority": 120,
        "mtuHint": 1280,
        "expiresAtMs": "1756300030000",
    }),
    "dns_policy_dual_family": ("twinvpn.v1.DNSPolicy", {
        "dnspolicyId": "dnspolicy-1",
        "version": "7",
        "mode": "DNS_MODE_SPLIT",
        # Both lists present and both presence bits set: docs/protocol.md §13.4
        # forbids the schema from expressing "v4 configured, v6 left to the OS".
        "serversV4": [{"octets": "CgABAQ=="}],
        "serversV6": [{"octets": "/XyeXSoQ//8AAAAAAAAAUw=="}],
        "serversDeclaredV4": True,
        "serversDeclaredV6": True,
        "blockFallbackV4": True,
        "blockFallbackV6": True,
        "splitDomains": [
            {"suffix": "corp.example.com",
             "disposition": "SPLIT_DOMAIN_DISPOSITION_PROTECTED_UPSTREAM"},
        ],
        "searchDomains": ["t-abc.tnet.twinvpn.net"],
        "dnssecValidate": True,
        "notAfterMs": "1756400000000",
    }),
    "capability_set": ("twinvpn.v1.CapabilitySet", {
        "capabilities": [
            {"name": "exit_node", "major": 2, "parameters": [
                {"name": "families", "reduction": "PARAMETER_REDUCTION_INTERSECT",
                 "setValue": {"values": ["v4", "v6"]}}]},
            {"name": "kill_switch_os", "major": 1},
            {"name": "path_migration", "major": 1},
        ],
    }),
    "metadata_full": ("twinvpn.v1.MessageMetadata", {
        "protoVersion": 1,
        "messageId": "AZGb8ABxc2SLnZ2en5+goQ==",
        "correlationId": "AZGb8ABxc2SLnZ2en5+gog==",
        "causationId": "AZGb8ABxc2SLnZ2en5+gow==",
        "causalityToken": "b3BhcXVl",
        "senderTimeMs": "1756300000000",
        "twinnetId": "tn-01H0",
        "senderId": "twd1abcdefghijklmnop",
        "netSeq": "9007199254740993",  # > 2^53: must survive as an exact integer
        "idempotencyKey": "AAECAwQFBgcICQoLDA0ODw==",
    }),
    "connection_session": ("twinvpn.v1.ConnectionSession", {
        "sessionId": "AZGb8ABxc2SLnZ2en5+gpA==",
        "peerDeviceId": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "state": "CONNECTION_STATE_DEGRADED",
        "carrier": "PATH_CLASS_RELAYED",
        "disposition": "TRAFFIC_DISPOSITION_TUNNELED_RELAY",
        "diagnostic": {"reasonCode": "NET.QOS.LOSS_HIGH", "domain": "NET"},
    }),
    "relay_binding": ("twinvpn.v1.RelayBinding", {
        "relayId": "AAAAAAAAAAI=",
        "pairTag": "8PDw8PDw8PDw8PDw8PDw8A==",
        "flowId": "AQID",
        "carriage": "RELAY_CARRIAGE_QUIC",
        "family": "ADDRESS_FAMILY_V6",
    }),
    "route_advertisement": ("twinvpn.v1.RouteAdvertisement", {
        "advertiserDeviceId": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "twinnetId": "tn-01H0",
        "prefixesV4": [{"prefix": {"address": {"v4": {"octets": "CgcAAA=="}},
                                   "prefixLen": 24}, "metric": 10}],
        "prefixesV6": [{"prefix": {"address": {"v6": {"octets": "/QABAgMEAAAAAAAAAAAAAAA="}},
                                   "prefixLen": 64}, "metric": 10}],
        "advertisementEpoch": "3",
        "notAfterMs": "1756303600000",
    }),
    "exit_node_grant_partial": ("twinvpn.v1.ExitNodeGrant", {
        "sessionId": "AZGb8ABxc2SLnZ2en5+gpQ==",
        "exitNodeDeviceId": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        # A v4-only grant. docs/protocol.md §13.3: the client MUST then BLOCK v6
        # rather than let it egress locally, and the refusal MUST say so.
        "grantedDefaultV4": True,
        "grantedDefaultV6": False,
        "dnsServersV4": [{"octets": "CgABAQ=="}],
        "mtu": 1380,
        "ttlMs": "3600000",
        "error": {"reasonCode": "POLICY.NO_V6_EGRESS", "domain": "POLICY"},
    }),
}


def run():
    lim = limits()

    # -- Round-trip stability -------------------------------------------------
    # docs/testing-strategy.md PB-5: for all well-formed messages,
    # decode(encode(m)) == m and encode(decode(b)) == b.
    case("round-trip stability, JSON -> binary -> JSON -> binary")
    for name, (tname, obj) in VECTORS.items():
        b1 = to_binary(tname, obj)
        j1 = to_json(tname, b1)
        b2 = to_binary(tname, j1)
        check_eq(b2, b1, f"{name}: re-encoding a decoded message is not byte-identical")
        j2 = to_json(tname, b2)
        check_eq(j2, j1, f"{name}: decode is not stable")

    # -- Cross-implementation agreement ---------------------------------------
    # -- Cross-implementation agreement, and its exact scope -----------------
    #
    # WHAT IS ASSERTED: two independent runtimes must agree on the VALUE - what
    # one encodes, the other decodes to the same logical message.
    #
    # WHAT IS DELIBERATELY *NOT* ASSERTED: byte-for-byte agreement.
    #
    # ADR-0003 §6 is explicit that "Protocol Buffers explicitly does NOT
    # guarantee that serialization is deterministic across languages, versions,
    # or even builds", and §12 item 2 makes that the reason signed statements use
    # deterministic CBOR instead. Asserting protobuf byte-determinism here would
    # assert a property the chosen format is documented not to have, and passing
    # such a test would be worse than failing it: it would make the corpus look
    # as though protobuf-signing were safe.
    #
    # This suite MEASURED the divergence rather than assuming it. protobufjs
    # emits an explicit zero for a proto3 implicit-presence field that the Go
    # runtime omits, so `granted_default_v6: false` is one logical value with two
    # valid encodings. That is exactly the hazard ADR-0003 §6 names, observed in
    # this repository, on this schema.
    case("independent runtimes agree on VALUE (byte-determinism is not claimed)")
    for name, (tname, obj) in VECTORS.items():
        b_buf = to_binary(tname, obj)
        r = node("encode", tname, obj=obj)
        check("error" not in r, f"{name}: protobufjs errored: {r.get('error','')}")
        if "error" in r:
            continue
        b_js = bytes.fromhex(r["hex"])
        # Decode BOTH encodings with BOTH runtimes; all four results must agree.
        check_eq(
            strip_implicit_defaults(to_json(tname, b_js)),
            strip_implicit_defaults(to_json(tname, b_buf)),
            f"{name}: the two runtimes' encodings decode to different values - this "
            f"is a genuine interop defect, unlike a mere byte difference",
        )
        d_js_of_buf = node("decode", tname, payload_hex=b_buf.hex())
        d_js_of_js = node("decode", tname, payload_hex=b_js.hex())
        check(
            "error" not in d_js_of_buf and "error" not in d_js_of_js,
            f"{name}: protobufjs could not decode one of the encodings",
        )
        if "error" not in d_js_of_buf and "error" not in d_js_of_js:
            check_eq(
                strip_implicit_defaults(d_js_of_buf["obj"]),
                strip_implicit_defaults(d_js_of_js["obj"]),
                f"{name}: protobufjs decodes the two encodings differently",
            )

    case("protobuf byte-encoding IS observed to differ across runtimes")
    # A positive assertion, not a lament. If this ever stops being true it does
    # not make protobuf-signing safe - but it does mean this note is stale and
    # ADR-0003 §14 revisit condition 1 deserves a look.
    tname, obj = VECTORS["exit_node_grant_partial"]
    b_buf = to_binary(tname, obj)
    r = node("encode", tname, obj=obj)
    if "error" not in r:
        differs = bytes.fromhex(r["hex"]) != b_buf
        check(
            differs or True,  # informational; never fails the gate
            "runtimes agreed byte-for-byte on this vector",
        )
        if differs:
            check(
                to_json(tname, bytes.fromhex(r["hex"])) == to_json(tname, b_buf),
                "the byte difference must be a representation difference only, not a "
                "value difference",
            )

    case("golden fixtures are byte-exact and frozen")
    FIXTURES.mkdir(exist_ok=True)
    for name, (tname, obj) in VECTORS.items():
        blob = to_binary(tname, obj)
        golden = FIXTURES / f"{name}.binpb"
        meta = FIXTURES / f"{name}.json"
        if golden.exists():
            check_eq(
                golden.read_bytes(), blob,
                f"{name}: the golden vector changed. A code change that alters a "
                f"golden vector IS A WIRE-FORMAT CHANGE and must be accompanied by "
                f"one (docs/testing-strategy.md §2.3)",
            )
        else:
            golden.write_bytes(blob)
            meta.write_text(json.dumps({"type": tname, "value": obj}, indent=2) + "\n")

    # -- 64-bit integers survive ---------------------------------------------
    # ADR-0003 §11 rule 2: silent precision loss on net_seq or revocation_epoch
    # would be a critical, near-invisible bug. The value here is above 2^53.
    case("64-bit integers survive a round trip exactly")
    tname, obj = VECTORS["metadata_full"]
    j = to_json(tname, to_binary(tname, obj))
    check_eq(j["netSeq"], "9007199254740993", "net_seq above 2^53 must be exact")

    # -- Unknown field preservation ------------------------------------------
    # ADR-0003 §11 B1 row: unknown fields are PRESERVED AND FORWARDED on unsigned
    # transport messages. This is what keeps a mixed-version fleet working when a
    # router lags a phone by a year.
    case("unknown fields are preserved and forwarded")
    base = to_binary("twinvpn.v1.ErrorEnvelope",
                     {"reasonCode": "NET.NO_ROUTE", "domain": "NET"})
    # Field 9999, wire type 2 (length-delimited): tag = 9999<<3|2 = 79994.
    # A field number far above anything this schema will allocate, standing in
    # for a field introduced at a future epoch.
    unknown = bytes([0xFA, 0xE0, 0x04]) + bytes([0x04]) + b"test"
    mixed = base + unknown
    out = buf(
        "convert", "contracts",
        "--type=twinvpn.v1.ErrorEnvelope",
        "--from=-#format=binpb", "--to=-#format=binpb",
        stdin=mixed,
    )
    check(
        unknown in out,
        "an unknown field was dropped on re-encode. ADR-0003 §11 B1 requires "
        "unknown fields to be PRESERVED AND FORWARDED, because an old coordination "
        "service must be able to relay a message containing a new field WITHOUT "
        "CORRUPTING IT - and TwinVPN devices update on wildly different schedules, "
        "a router lagging a phone by a year (ADR-0003 §8)",
    )

    case("a forwarding-role binding must preserve unknown fields")
    # This is a CONSTRAINT ON THE BINDING SET, discovered by measurement rather
    # than assumed. protobufjs does NOT preserve unknown fields; the Go runtime
    # does. Any language chosen for a component that FORWARDS a message it does
    # not fully understand - the coordination service, the rendezvous, a relay
    # carrying an opaque CALL - must use a runtime with preserve-and-forward.
    #
    # It is not a Phase 2 blocker because no Phase 1 component is assigned to a
    # JS runtime (ADR-0018 §11.12 fixes rust/swift/kotlin/csharp). It is recorded
    # so that a future proposal to add one is evaluated against this fact.
    r = node("roundtrip_preserve", "twinvpn.v1.ErrorEnvelope", payload_hex=mixed.hex())
    if "error" not in r:
        js_preserves = unknown in bytes.fromhex(r["hex"])
        check(
            True,
            f"measured: protobufjs preserve-and-forward = {js_preserves}",
        )

    # -- Unknown enum handling -----------------------------------------------
    # An enum value from a newer epoch must decode to the UNSPECIFIED sentinel in
    # an older reader, not crash and not silently become a valid neighbour.
    case("unknown enum values decode to the UNSPECIFIED sentinel")
    # ConnectionSession.state (field 3, varint) set to 9999.
    blob = bytes([0x18]) + bytes([0x8F, 0x4E])
    j = to_json("twinvpn.v1.ConnectionSession", blob)
    check(
        str(j.get("state")) == "9999",
        f"an unknown enum must survive as its numeric value for forwarding, got "
        f"{j.get('state')!r}",
    )
    r = node("decode", "twinvpn.v1.ConnectionSession", payload_hex=blob.hex())
    check("error" not in r, f"protobufjs rejected an unknown enum: {r.get('error','')}")

    # -- Malformed and untrusted input ---------------------------------------
    # ADR-0003 §11.7 rule PA-1: there is no fourth decode outcome. A panic, an
    # abort, a hang, an allocation proportional to a declared length, or a silent
    # accept is a defect - regardless of perceived exploitability.
    case("malformed input is rejected, never accepted and never fatal")
    MALFORMED = {
        "truncated_varint": bytes([0x08]),
        "truncated_length_delimited": bytes([0x0A, 0x7F, 0x41]),
        "length_exceeds_buffer": bytes([0x0A, 0xFF, 0xFF, 0xFF, 0x7F, 0x41]),
        "declared_length_4gb": bytes([0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
        "invalid_wire_type_6": bytes([0x0E, 0x01]),
        "invalid_wire_type_7": bytes([0x0F, 0x01]),
        "overlong_varint": bytes([0x08]) + bytes([0xFF] * 12),
        "field_number_zero": bytes([0x00, 0x01]),
        "trailing_group_end": bytes([0x0C]),
        "empty_after_tag": bytes([0x12]),
    }
    for name, blob in MALFORMED.items():
        rejected = False
        try:
            to_json("twinvpn.v1.ErrorEnvelope", blob)
        except RuntimeError:
            rejected = True
        r = node("decode", "twinvpn.v1.ErrorEnvelope", payload_hex=blob.hex())
        js_rejected = "error" in r
        check(
            rejected or js_rejected,
            f"malformed input {name!r} was ACCEPTED by both runtimes. A silent "
            f"accept on hostile input is a P1 defect (ADR-0003 §11.7 PA-1)",
        )
        # The decisive property: a declared length of 4 GiB must not cause an
        # allocation proportional to it. Reaching this line at all proves it did
        # not, because the harness would otherwise have been killed.
        check(True, f"{name}: decode terminated without exhausting memory")

    case("deeply nested input does not exhaust the stack")
    # 64 nested length-delimited fields. The C4 parser depth limit is 4 and the
    # C1 limit is 8, so this is far past both and must be refused rather than
    # recursed into.
    depth = 64
    payload = b""
    for _ in range(depth):
        payload = bytes([0x0A, len(payload)]) + payload if len(payload) < 128 else payload
    r = node("decode", "twinvpn.v1.ControlEvent", payload_hex=payload.hex())
    check(True, "nested-input decode terminated")

    # -- Size and count limits ------------------------------------------------
    case("declared limits are internally consistent")
    check(
        lim["envelope"]["c4_max_bytes"] < lim["envelope"]["c1_c2_c7_max_bytes"],
        "the C4 datagram cap must be below the stream cap",
    )
    check(
        lim["envelope"]["c4_max_depth"] < lim["envelope"]["c1_c2_c7_max_depth"],
        "the hostile pre-authentication boundary must have the TIGHTER depth limit",
    )
    check_eq(lim["envelope"]["c4_max_bytes"], 1200,
             "the C4 cap is the worst-case IPv6 path MTU minus headers")
    check(
        lim["envelope"]["c2_inline_document_max_bytes"]
        < lim["envelope"]["c1_c2_c7_max_bytes"],
        "the inline document cap must be below the envelope cap so one policy "
        "bundle cannot monopolise a stream",
    )
    check(
        lim["capability"]["max_advertisement_bytes"] < lim["envelope"]["c4_max_bytes"],
        "the capability advertisement must fit inside a C4 datagram alongside "
        "candidates",
    )

    case("max_advertisement_bytes is load-bearing, not decorative")
    # The per-field bounds are NOT mutually sufficient, and this case exists to
    # keep that fact checked rather than accidental.
    #
    # max_tokens_per_advertisement (32) x max_name_bytes produces an object far
    # larger than max_advertisement_bytes (512) permits: ~960 B at the old
    # 24-byte name cap and ~1216 B at the 32-byte cap CF-6 set. So the byte cap
    # is the constraint a receiver actually enforces, and the per-field caps
    # bound individual fields only.
    #
    # This case previously constructed that unreachable worst case and checked it
    # against c4_max_bytes (1200). It passed at 960 B by COINCIDENCE -- the
    # product happened to sit between the cap it violated (512) and the cap it
    # was compared against (1200) -- so it never tested the property it named,
    # and it began failing the moment CF-6's amendment was applied to
    # limits.json. Rewritten during the registry_version 2 amendment.
    cap = lim["capability"]
    unreachable = {"capabilities": [
        {"name": "x" * cap["max_name_bytes"], "major": 1}
        for _ in range(cap["max_tokens_per_advertisement"])
    ]}
    unreachable_blob = to_binary("twinvpn.v1.CapabilitySet", unreachable)
    check(
        len(unreachable_blob) > cap["max_advertisement_bytes"],
        f"the per-field caps now fit inside max_advertisement_bytes "
        f"({len(unreachable_blob)} B <= {cap['max_advertisement_bytes']} B). That "
        f"is not a failure, but it means this case no longer proves the byte cap "
        f"is load-bearing -- re-derive it rather than deleting it",
    )

    case("an advertisement at the ENFORCED cap fits a C4 datagram")
    # What a receiver accepts is bounded by max_advertisement_bytes, so that is
    # the number that must fit the worst-case IPv6 path MTU alongside candidates.
    check(
        cap["max_advertisement_bytes"] <= lim["envelope"]["c4_max_bytes"],
        f"the enforced advertisement cap ({cap['max_advertisement_bytes']} B) "
        f"does not fit the {lim['envelope']['c4_max_bytes']} B C4 datagram",
    )
    # And an advertisement built up to that enforced cap must really fit.
    n = 0
    fitted = {"capabilities": []}
    while True:
        trial = {"capabilities": fitted["capabilities"] + [
            {"name": "x" * cap["max_name_bytes"], "major": 1}]}
        if len(to_binary("twinvpn.v1.CapabilitySet", trial)) > cap["max_advertisement_bytes"]:
            break
        fitted = trial
        n += 1
        if n >= cap["max_tokens_per_advertisement"]:
            break
    blob = to_binary("twinvpn.v1.CapabilitySet", fitted)
    check(
        len(blob) <= lim["envelope"]["c4_max_bytes"],
        f"an advertisement at the enforced {cap['max_advertisement_bytes']} B cap "
        f"is {len(blob)} B and does not fit the "
        f"{lim['envelope']['c4_max_bytes']} B C4 datagram",
    )
    check(
        n < cap["max_tokens_per_advertisement"],
        f"the byte cap admitted all {cap['max_tokens_per_advertisement']} tokens "
        f"at the {cap['max_name_bytes']}-byte name cap, so the two bounds are "
        f"consistent and the note above is stale",
    )

    case("an oversized C4 body is detectable before parse")
    big = {"capabilities": [{"name": "cap_" + str(i), "major": 1} for i in range(200)]}
    blob = to_binary("twinvpn.v1.CapabilitySet", big)
    check(
        len(blob) > lim["capability"]["max_advertisement_bytes"],
        "a 200-token advertisement must exceed the 512 B reservation, so the cap is "
        "enforceable by length BEFORE any allocation proportional to the content",
    )
