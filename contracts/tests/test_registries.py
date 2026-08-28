"""The machine-readable registries: reason codes, capabilities, and limits.

ADR-0015 §11.2 rule 6 and ADR-0014 §10 both require these to ship as
machine-readable artifacts diffed in CI as append-only. These tests are what
make "append-only" a property of the build rather than of a reviewer's memory.
"""
import re

from harness import ROOT, case, check, check_eq, image, registry, limits

CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(\.[A-Z][A-Z0-9_]*){1,2}$")
CAP_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

# ADR-0015 §11.2. CLOSED by an admission rule, not by a count: a new top-level
# domain is admissible only when no existing domain is a correct owner, because
# prefix degradation would otherwise produce an ACTIVELY WRONG diagnosis rather
# than a merely vague one.
CLOSED_DOMAINS = {
    "NET", "NAT", "RELAY", "AUTH", "CRYPTO", "PROTO", "POLICY", "DNS", "ROUTE",
    "PLATFORM", "RESOURCE", "CONTROL", "INTERNAL", "MGMT", "STORE", "UPDATE",
}

VALID_CLASS = {"TRANSIENT", "PERSISTENT", "POLICY", "FATAL"}
VALID_SEVERITY = {"INFO", "WARN", "ERROR", "CRITICAL"}
VALID_STATUS = {"ACTIVE", "DEPRECATED", "RETIRED"}
VALID_REMEDIATION = {
    "NONE", "WAIT", "LOCAL_ACTION", "PEER_ACTION", "POLICY_CHANGE",
    "UPDATE_REQUIRED", "NETWORK_CHANGE", "PERMISSION_GRANT", "REPORT_DEFECT",
}
VALID_SCOPE = {"SESSION", "TWINNET", "DEVICE", "PATH", "RELAY"}


def run():
    reasons = registry("reason_codes")
    caps = registry("capabilities")
    lim = limits()
    img = image()

    # ---- Reason codes ------------------------------------------------------
    codes = reasons["reason_codes"]

    case("reason-code format")
    seen = set()
    for e in codes:
        c = e["reason_code"]
        check(CODE_RE.match(c) is not None, f"{c} does not match DOMAIN.CONDITION form")
        check(len(c) <= lim["diagnostics"]["max_reason_code_bytes"], f"{c} exceeds 64 bytes")
        segs = c.split(".")
        check(
            lim["diagnostics"]["min_reason_code_segments"]
            <= len(segs)
            <= lim["diagnostics"]["max_reason_code_segments"],
            f"{c} has {len(segs)} segments; ADR-0015 rule 7 permits two or three, "
            f"because DOMAIN is the only segment with forward-compatibility meaning "
            f"and deeper nesting breaks prefix degradation",
        )
        check(c not in seen, f"{c} is duplicated")
        seen.add(c)

    case("every code sits in the closed domain set")
    for e in codes:
        d = e["domain"]
        check(
            d in CLOSED_DOMAINS,
            f"{e['reason_code']} uses domain {d}, which is not one of the sixteen "
            f"ADR-0015 §11.2 declares. A genuinely new domain is added to THAT "
            f"table, never invented in a contract",
        )
        check_eq(d, e["reason_code"].split(".")[0], f"{e['reason_code']} domain field")

    case("required registry attributes are present and valid")
    for e in codes:
        c = e["reason_code"]
        for k in (
            "class", "severity", "terminal", "user_actionable", "remediation_class",
            "scope", "summary_key", "doc_anchor", "evidence_fields",
            "owning_document", "introduced_in_registry_version", "status",
        ):
            check(k in e, f"{c} is missing required attribute {k}")
        check(e.get("class") in VALID_CLASS, f"{c} class={e.get('class')}")
        check(e.get("severity") in VALID_SEVERITY, f"{c} severity={e.get('severity')}")
        check(e.get("status") in VALID_STATUS, f"{c} status={e.get('status')}")
        check(
            e.get("remediation_class") in VALID_REMEDIATION,
            f"{c} remediation_class={e.get('remediation_class')}",
        )
        check(e.get("scope") in VALID_SCOPE, f"{c} scope={e.get('scope')}")
        check(isinstance(e.get("terminal"), bool), f"{c} terminal must be a bool")
        check(
            isinstance(e.get("user_actionable"), bool),
            f"{c} user_actionable must be a bool",
        )

    case("user_actionable codes carry a next action")
    for e in codes:
        if e["user_actionable"]:
            check(
                e.get("next_action_key"),
                f"{e['reason_code']} is user_actionable but has no next_action_key - "
                f"ADR-0015 §11.2 requires one, and 'something went wrong, good luck' "
                f"is the defect this product exists to fix",
            )
            check(
                e.get("remediation_class") != "NONE",
                f"{e['reason_code']} is user_actionable with remediation_class NONE, "
                f"which is self-contradictory",
            )

    case("no code is both terminal and merely informational")
    for e in codes:
        check(
            not (e["terminal"] and e["severity"] == "INFO"),
            f"{e['reason_code']} is terminal at INFO severity: a condition that ends "
            f"the attempt is not informational",
        )

    case("summary and next-action keys are lookup keys, not sentences")
    for e in codes:
        for k in ("summary_key", "next_action_key"):
            v = e.get(k)
            if v:
                check(
                    " " not in v and v.startswith("reason."),
                    f"{e['reason_code']}.{k}={v!r} must be an i18n lookup key. THE "
                    f"CODE IS THE CONTRACT; THE HUMAN TEXT IS NOT (ADR-0015 rule 4)",
                )

    case("deprecated codes alias forward, retired codes are never reused")
    for e in codes:
        if e["status"] == "DEPRECATED":
            check(
                e.get("alias_of"),
                f"{e['reason_code']} is DEPRECATED without alias_of - ADR-0015 rule 3 "
                f"requires the replacement to be named so peers inside the "
                f"compatibility window can follow it",
            )
        if e["status"] == "RETIRED":
            check(
                not e.get("alias_of"),
                f"{e['reason_code']} is RETIRED but still aliases forward",
            )

    case("evidence field names are declared and well-formed")
    maxk = lim["diagnostics"]["max_evidence_key_bytes"]
    for e in codes:
        for f in e["evidence_fields"]:
            check(
                re.match(r"^[a-z][a-z0-9_]*$", f) is not None,
                f"{e['reason_code']} evidence field {f!r} must be lower_snake_case",
            )
            check(len(f) <= maxk, f"{e['reason_code']} evidence field {f!r} too long")

    case("codes cited in the schema exist in the registry")
    # Any DOMAIN.CONDITION string appearing in a proto comment is a promise that
    # the registry defines it. A citation with no entry is a code that will
    # never resolve to a summary or a next action.
    cited = set()
    for f in img["file"]:
        blob = str(f.get("sourceCodeInfo", {}))
        for m in re.finditer(r"\b([A-Z][A-Z0-9]{1,11}\.[A-Z][A-Z0-9_.]{2,50})\b", blob):
            tok = m.group(1).rstrip(".")
            # A comment may cite a FAMILY rather than a code - "the AUTH.PAIRING_*
            # codes" - which is a prose reference, not a promise that a code by
            # that exact name exists.
            if tok.endswith("_") or tok.endswith("*"):
                continue
            if tok.split(".")[0] in CLOSED_DOMAINS and CODE_RE.match(tok):
                cited.add(tok)
    for c in sorted(cited):
        check(
            c in seen,
            f"{c} is cited in a .proto comment but is absent from "
            f"registry/reason_codes.json",
        )

    # ---- Capabilities ------------------------------------------------------
    entries = caps["capabilities"]

    case("capability naming (ADR-0014 N-11)")
    # The bound is 32 characters as of the 2026-08-27 amendment to N-11. The
    # waiver mechanism that previously carried CF-6 is gone because the conflict
    # is resolved at its source: an ADR that contradicted its own registry table
    # has been corrected, rather than a security_relevant token being renamed.
    check(
        caps.get("capability_name_max_length") == 32,
        "capabilities.json must record the amended N-11 bound",
    )
    check(
        "phase1_conflicts" not in caps,
        "the CF-6 waiver must be removed now that ADR-0014 N-11 is amended - a "
        "stale waiver would suppress a real future violation",
    )
    pairs = set()
    for e in entries:
        check(
            CAP_NAME_RE.match(e["name"]) is not None,
            f"capability {e['name']!r} must match [a-z][a-z0-9_]{{0,31}} "
            f"(ADR-0014 N-11 as amended)",
        )
    case("every capability declares real-probe evidence (ADR-0014 N-14)")
    for e in entries:
        check(
            e.get("probe_evidence"),
            f"{e['name']}/{e['major']} has no probe_evidence. A Capability MUST be "
            f"advertised only if the platform probe OBSERVED the ability in this "
            f"process, on this OS build, with the permissions currently granted - a "
            f"build-time constant or an OS-version table MUST NOT be the sole basis",
        )
        check(
            e.get("absent_consequence"),
            f"{e['name']}/{e['major']} does not say what its absence costs. "
            f"ADR-0014 N-28: SILENCE IS A DEFECT",
        )
        check(e.get("owning_adr"), f"{e['name']} has no owning ADR")

    case("parameter reductions are role-independent (ADR-0014 N-13)")
    for e in entries:
        params = e["parameters"]
        check(
            len(params) <= lim["capability"]["max_parameters_per_token"],
            f"{e['name']} has {len(params)} parameters, over the cap",
        )
        for p in params:
            check(
                p["reduction"] in {"MIN", "MAX", "INTERSECT", "EQUAL"},
                f"{e['name']}.{p['name']} reduction={p['reduction']!r}",
            )
            if p["reduction"] == "INTERSECT":
                check(
                    p.get("allowed_values"),
                    f"{e['name']}.{p['name']} is INTERSECT with no allowed_values",
                )

    case("kill_switch_os is parameterless, deliberately (ADR-0014 §11.11)")
    ks = [e for e in entries if e["name"] == "kill_switch_os"]
    check_eq(len(ks), 1, "kill_switch_os must be registered exactly once")
    if ks:
        check_eq(
            ks[0]["parameters"], [],
            "kill_switch_os MUST have no parameters. A per-family `scope` would make "
            "a v4-only kill switch EXPRESSIBLE, NEGOTIABLE and - under INTERSECT - "
            "CONTAGIOUS ACROSS THE PAIR, re-introducing in the capability layer the "
            "family asymmetry ADR-0010 §11.5 and ADR-0012 KS-5 forbid. Dual-family "
            "coverage is not negotiable: a device that cannot deliver both families "
            "MUST NOT advertise the token at all",
        )
        check(ks[0]["security_relevant"], "kill_switch_os must be security_relevant")
        check(ks[0]["session_critical"], "kill_switch_os must be session_critical")

    case("security_relevant tokens are the S-37 floor set (ADR-0014 N-19)")
    sec = {e["name"] for e in entries if e["security_relevant"]}
    for expected in (
        "site_remap", "per_app_routing", "path_migration", "exit_node",
        "lan_gateway", "dns_split", "dns_full", "kill_switch_os",
        "kill_switch_boot", "dns_scoped_api", "dns_config_dies_with_tunnel",
        "rekey_in_place", "psk_epoch",
    ):
        check(
            expected in sec,
            f"{expected} must be security_relevant: it participates in the S-37 "
            f"monotonic floor, and losing it must be REFUSED rather than surfaced",
        )
    # The floor covers ONLY security_relevant tokens. A whole-set ratchet would
    # permanently brick an honest device whose OS revokes a permission.
    check(
        len(sec) < len(entries),
        "not every capability may be security_relevant - capability sets are a "
        "PARTIAL order and a capability can legitimately vanish (ADR-0014 N-19)",
    )

    case("session_critical implies security_relevant")
    for e in entries:
        if e["session_critical"]:
            check(
                e["security_relevant"],
                f"{e['name']} is session_critical but not security_relevant: a token "
                f"whose loss forces a new Tunnel is by definition one whose loss must "
                f"not be silently accepted",
            )

    case("the whole registry fits the advertisement budget (ADR-0014 N-10)")
    # Serialized as the canonical wire form: "name/major" tokens plus their
    # parameters, canonically sorted. This is the test ADR-0014 N-10 names by
    # hand: "a CI contract test MUST serialise the complete current registry and
    # assert it fits the 512 B reservation", so REGISTRY GROWTH FAILS THE BUILD
    # RATHER THAN THE FIELD.
    active = [e for e in entries if e["status"] == "ACTIVE"]
    tokens = sorted(f"{e['name']}/{e['major']}" for e in active)
    wire = ",".join(tokens).encode()
    budget = caps["advertisement_byte_budget"]
    maxtok = caps["max_tokens_per_advertisement"]
    check_eq(budget, lim["capability"]["max_advertisement_bytes"], "budget agrees with limits.json")
    check_eq(maxtok, lim["capability"]["max_tokens_per_advertisement"], "token cap agrees with limits.json")
    # The full registry is larger than any single device's probe-verified set,
    # so the assertion is about the CAPS, not about a device advertising all of
    # them: a device advertises at most `maxtok` tokens within `budget` bytes.
    worst = sorted(tokens, key=len, reverse=True)[:maxtok]
    worst_bytes = len(",".join(worst).encode())
    check(
        worst_bytes <= budget,
        f"the {maxtok} longest registry tokens serialize to {worst_bytes} B, over the "
        f"{budget} B reservation. The advertisement cannot trickle across datagrams "
        f"the way candidates can - it must be complete and atomic to be bound into "
        f"the prologue - so this failing means the registry has outgrown the C4 "
        f"datagram and ADR-0014 §14 V2 has fired",
    )
    check(
        len(active) <= 64,
        f"{len(active)} active capabilities: the registry is growing toward the point "
        f"where a device's probe-verified subset could exceed {maxtok} tokens",
    )

    # -- CF-9: the B2 statement-count tripwire --------------------------------
    #
    # ADR-0003 §6 justified thin CBOR codegen - and therefore hand-written B2
    # mappers - on B2 being a small set. §11.5 corrects the real count to
    # seventeen and states plainly that §14 revisit trigger 7 fires at ~20, so
    # "the mitigation is close to expiring and is restated honestly here rather
    # than left resting on a stale number".
    #
    # A number restated in prose goes stale again. This check makes the trigger
    # MECHANICAL: adding an eighteenth statement warns, and a twentieth FAILS THE
    # BUILD until ADR-0003 is reopened. The whole point of a revisit condition is
    # that something notices when it fires.
    case("B2 signed-statement count against the ADR-0003 revisit trigger")
    cddl = (ROOT / "cddl" / "twinvpn" / "v1" / "signed_statements.cddl").read_text()
    union = cddl[cddl.index("signed-statement ="):]
    members = [
        line.split("/")[-1].strip()
        for line in union.splitlines()
        if line.strip() and ("=" in line or "/" in line)
    ]
    members = [m for m in members if m and not m.startswith(";")]
    n = len(members)
    check(
        n >= 17,
        f"the B2 inventory has {n} members; ADR-0003 §11.5 enumerates seventeen. "
        f"A statement type removed from the CDDL is still a statement peers may "
        f"send",
    )
    check(
        n < 20,
        f"the B2 inventory has reached {n} signed statement types. ADR-0003 §14 "
        f"REVISIT TRIGGER 7 FIRES AT ~20: past that point CBOR's thin codegen "
        f"becomes a real defect source and the evolution-tooling argument may "
        f"outweigh the determinism argument. Reopen ADR-0003 before adding "
        f"another - do not raise this bound to make the build green",
    )
    if n >= 18:
        check(True, f"NOTE: B2 inventory at {n}/20 - approaching the trigger")

    case("registry versions agree")
    # Bumped 1 -> 2 by the first amendment under ownership.md §3 (2026-08-28).
    # The three registries ship as ONE versioned set, which is what this case
    # asserts; reason_codes and limits both changed, so all three move together.
    check_eq(reasons["registry_version"], 2, "reason registry version")
    check_eq(caps["registry_version"], 2, "capability registry version")
    check_eq(lim["registry_version"], 2, "limits registry version")

    # ---- Known-encrypted-resolver endpoints (ADR-0011 §11.9) ---------------
    # This artifact exists because §11.9 requires all three desktop enforcement
    # layers to deny "known-DoH endpoints" off-overlay and says the list "ships
    # with the reason-code registry, is versioned, and is explicitly incomplete
    # - a detection aid, never a guarantee". It did not exist, so that half of
    # the containment could not be installed anywhere.
    enc = registry("encrypted_resolvers")

    case("the encrypted-resolver list carries its own incompleteness as data")
    # The most important assertion in this block. A consumer must be unable to
    # mistake a detection aid for a guarantee, and prose in a comment is not
    # something a consumer can read.
    check_eq(enc["status"], "EXPLICITLY_INCOMPLETE", "encrypted-resolver status")
    check_eq(enc["guarantee"], "NONE", "encrypted-resolver guarantee")
    for k in ("what_this_is_not", "consumer_rule"):
        check(enc.get(k), f"encrypted_resolvers.{k} must be present and non-empty")
    check_eq(enc["registry_version"], 2, "encrypted-resolver registry version")

    case("the encrypted-resolver list is well-formed and family-symmetric")
    import ipaddress
    check(len(enc["endpoints"]) > 0, "the endpoint list must not be empty")
    n4 = n6 = 0
    for e in enc["endpoints"]:
        check(e.get("provider"), "every endpoint entry names a provider")
        check(e.get("transports"), f"{e.get('provider')} declares no transports")
        for a in e.get("v4", []):
            ipaddress.IPv4Address(a)
            n4 += 1
        for a in e.get("v6", []):
            ipaddress.IPv6Address(a)
            n6 += 1
        # ADR-0010 R1: "a v4 story and a v6 story" is the defect. A provider
        # listed for one family only would be denied on one family only.
        check(
            bool(e.get("v4")) == bool(e.get("v6")),
            f"{e.get('provider')} is listed for one address family only - "
            f"ADR-0010 R1 makes a per-family asymmetry the defect, and here it "
            f"would mean the resolver is contained on one family and reachable "
            f"on the other",
        )
    check(n4 > 0 and n6 > 0, "both families must be represented")

    case("the encrypted-resolver ports cover what ADR-0011 §11.9 names")
    ports = enc["ports"]
    for k, v in (("do53_udp", 53), ("do53_tcp", 53), ("dot_tcp", 853), ("doh_tcp", 443)):
        check_eq(ports.get(k), v, f"encrypted_resolvers.ports.{k}")
    check_eq(
        enc["canary"]["name"], "use-application-dns.net", "the DoH canary name"
    )
    check_eq(enc["canary"]["answer"], "NXDOMAIN", "the DoH canary answer")

    case("universal evidence keys are declared (W-5)")
    # errors.proto REQUIRES a truncating emitter to append {key:
    # "evidence_truncated"}, and no reason code declared it - so a validator
    # checking a message's keys against its code's declared evidence_fields
    # rejected a message the schema mandates.
    uni = reasons.get("universal_evidence_fields")
    check(uni is not None, "reason_codes.universal_evidence_fields must exist (W-5)")
    check(
        "evidence_truncated" in uni["fields"],
        "evidence_truncated must be declared as a universal evidence key - "
        "errors.proto requires a truncating emitter to append it to ANY code",
    )
    for f in uni["fields"]:
        check(
            re.match(r"^[a-z][a-z0-9_]*$", f) is not None,
            f"universal evidence field {f!r} must be lower_snake_case",
        )
        check(len(f) <= lim["diagnostics"]["max_evidence_key_bytes"],
              f"universal evidence field {f!r} too long")
