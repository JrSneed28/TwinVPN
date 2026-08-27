//! Compiles `contracts/registry/limits.json` into `const` values.
//!
//! **Why not a runtime parse.** `limits.json` exists "to be *the* source for
//! validators on untrusted input" (`ownership.md` §4.3). A validator that reads
//! it at runtime can be wrong in two ways this cannot: the file can be missing at
//! run time, and a key that disappears from the registry becomes a runtime
//! `None` instead of a compile error. Compiling it makes a limit that has moved
//! or vanished fail the build, and `cargo:rerun-if-changed` makes the compiled
//! copy re-derive whenever the frozen registry does.
//!
//! The raw JSON is *also* embedded with `include_str!` (see `src/limits.rs`), and
//! `limits_generated_from_the_frozen_registry` re-parses it at test time and
//! asserts every generated constant against it. Two independent paths from one
//! frozen file; a drift between them fails `cargo test`.

use std::path::PathBuf;

const REGISTRY_REL: &str = "../../../contracts/registry/limits.json";

/// `(json path, rust const name, doc)`. Every entry is required: a key that
/// vanishes from the frozen registry fails this build rather than silently
/// disabling a validator.
const LIMITS: &[(&str, &str, &str, &str)] = &[
    ("envelope", "c1_c2_c7_max_bytes", "C1_C2_C7_MAX_BYTES", "Envelope byte cap for the C1, C2 and C7 channels."),
    ("envelope", "c1_c2_c7_max_depth", "C1_C2_C7_MAX_DEPTH", "Nesting-depth cap for the C1, C2 and C7 channels."),
    ("envelope", "c4_max_bytes", "C4_MAX_BYTES", "C4 byte cap. 1200 B is the worst-case IPv6 path MTU minus headers, **not** the IPv4 576 B floor: C4 is never fragmented and IPv6 forbids in-network fragmentation."),
    ("envelope", "c4_max_depth", "C4_MAX_DEPTH", "C4 nesting-depth cap."),
    ("envelope", "c2_inline_document_max_bytes", "C2_INLINE_DOCUMENT_MAX_BYTES", "Inline-document cap on C2. Lower than the envelope cap on purpose, so a single policy bundle cannot monopolise a stream; larger documents are announced by reference and pulled."),
    ("identifiers", "device_id_bytes", "DEVICE_ID_BYTES", "Exact width of `device_id`."),
    ("identifiers", "identity_id_bytes", "IDENTITY_ID_BYTES", "Exact width of `identity_id`."),
    ("identifiers", "pairing_id_bytes", "PAIRING_ID_BYTES", "Exact width of `pairing_id`."),
    ("identifiers", "session_id_bytes", "SESSION_ID_BYTES", "Exact width of `session_id`."),
    ("identifiers", "tunnel_id_bytes", "TUNNEL_ID_BYTES", "Exact width of `tunnel_id`."),
    ("identifiers", "path_id_bytes", "PATH_ID_BYTES", "Exact width of `path_id`."),
    ("identifiers", "candidate_id_bytes", "CANDIDATE_ID_BYTES", "Exact width of `candidate_id`."),
    ("identifiers", "relay_id_bytes", "RELAY_ID_BYTES", "Exact width of `relay_id`."),
    ("identifiers", "pair_tag_bytes", "PAIR_TAG_BYTES", "Exact width of `pair_tag`."),
    ("identifiers", "message_id_bytes", "MESSAGE_ID_BYTES", "Exact width of `message_id`."),
    ("identifiers", "correlation_id_bytes", "CORRELATION_ID_BYTES", "Exact width of `correlation_id`."),
    ("identifiers", "causation_id_bytes", "CAUSATION_ID_BYTES", "Exact width of `causation_id`."),
    ("identifiers", "idempotency_key_min_bytes", "IDEMPOTENCY_KEY_MIN_BYTES", "The >= 128-bit floor on `idempotency_key`."),
    ("identifiers", "idempotency_key_max_bytes", "IDEMPOTENCY_KEY_MAX_BYTES", "Upper bound on `idempotency_key`."),
    ("identifiers", "digest_bytes", "DIGEST_BYTES", "Exact width of a carried digest."),
    ("identifiers", "channel_binding_bytes", "CHANNEL_BINDING_BYTES", "Exact width of the RFC 9266 `tls-exporter` value."),
    ("identifiers", "session_nonce_bytes", "SESSION_NONCE_BYTES", "Exact width of `session_nonce`."),
    ("identifiers", "twinnet_id_max_bytes", "TWINNET_ID_MAX_BYTES", "Cap on `twinnet_id`."),
    ("identifiers", "region_id_max_bytes", "REGION_ID_MAX_BYTES", "Cap on `region_id`."),
    ("identifiers", "policy_id_max_bytes", "POLICY_ID_MAX_BYTES", "Cap on `policy_id` and `dnspolicy_id`."),
    ("identifiers", "signer_key_id_max_bytes", "SIGNER_KEY_ID_MAX_BYTES", "Cap on `signer_key_id`."),
    ("identifiers", "causality_token_max_bytes", "CAUSALITY_TOKEN_MAX_BYTES", "Cap on `causality_token`."),
    ("capability", "max_tokens_per_advertisement", "CAPABILITY_MAX_TOKENS", "Cap on tokens in one capability advertisement."),
    ("capability", "max_advertisement_bytes", "CAPABILITY_MAX_ADVERTISEMENT_BYTES", "Byte cap on one capability advertisement."),
    ("capability", "max_name_bytes", "CAPABILITY_MAX_NAME_BYTES_REGISTRY", "The registry's capability-name cap. **Stale at 24** — see `ownership.md` §4.3 and use `CAPABILITY_MAX_NAME_BYTES` instead."),
    ("capability", "max_parameters_per_token", "CAPABILITY_MAX_PARAMETERS", "Cap on parameters per capability token."),
    ("capability", "max_parameter_bytes_total", "CAPABILITY_MAX_PARAMETER_BYTES", "Byte cap on one token's parameters."),
    ("capability", "max_epoch_above_current", "CAPABILITY_MAX_EPOCH_ABOVE_CURRENT", "How far above the current epoch an advertisement may reach."),
    ("candidates", "max_candidates_per_set", "MAX_CANDIDATES_PER_SET", "Cap on candidates in one `CandidateSet`."),
    ("candidates", "max_birthday_port_hints", "MAX_BIRTHDAY_PORT_HINTS", "Cap on birthday-paradox port hints in one `PunchSync`."),
    ("candidates", "default_expiry_ms", "CANDIDATE_DEFAULT_EXPIRY_MS", "Default candidate TTL."),
    ("diagnostics", "max_evidence_entries", "MAX_EVIDENCE_ENTRIES", "Cap on evidence entries in one envelope."),
    ("diagnostics", "max_evidence_bytes", "MAX_EVIDENCE_BYTES", "Byte cap on one envelope's evidence."),
    ("diagnostics", "max_reason_code_bytes", "MAX_REASON_CODE_BYTES", "Byte cap on a `reason_code`."),
    ("diagnostics", "min_reason_code_segments", "MIN_REASON_CODE_SEGMENTS", "Minimum `reason_code` segment count."),
    ("diagnostics", "max_reason_code_segments", "MAX_REASON_CODE_SEGMENTS", "Maximum `reason_code` segment count."),
    ("diagnostics", "max_evidence_key_bytes", "MAX_EVIDENCE_KEY_BYTES", "Byte cap on an evidence key."),
    ("routing", "max_prefixes_per_advertisement", "MAX_PREFIXES_PER_ADVERTISEMENT", "Cap on prefixes in one route advertisement."),
    ("routing", "ipv4_max_prefix_len", "IPV4_MAX_PREFIX_LEN", "Maximum IPv4 prefix length."),
    ("routing", "ipv6_max_prefix_len", "IPV6_MAX_PREFIX_LEN", "Maximum IPv6 prefix length."),
    ("routing", "ipv4_address_bytes", "IPV4_ADDRESS_BYTES", "Exact IPv4 address width."),
    ("routing", "ipv6_address_bytes", "IPV6_ADDRESS_BYTES", "Exact IPv6 address width."),
    ("dns", "max_split_domain_rules", "MAX_SPLIT_DOMAIN_RULES", "Cap on split-DNS rules in one `DNSPolicy`."),
    ("dns", "max_search_domains", "MAX_SEARCH_DOMAINS", "Cap on search domains."),
    ("dns", "max_domain_name_bytes", "MAX_DOMAIN_NAME_BYTES", "Byte cap on a domain name (RFC 1035's 253)."),
    ("dns", "max_resolvers_per_family", "MAX_RESOLVERS_PER_FAMILY", "Cap on resolvers **per address family**."),
    ("pairing", "ceremony_expiry_ms", "PAIRING_CEREMONY_EXPIRY_MS", "Pairing-ceremony lifetime."),
    ("pairing", "max_failed_runs", "PAIRING_MAX_FAILED_RUNS", "The five-attempt budget that makes a nine-digit code safe (ADR-0007 N-17)."),
    ("pairing", "max_peer_hint_bytes", "PAIRING_MAX_PEER_HINT_BYTES", "Byte cap on a pairing peer hint."),
    ("pairing", "max_ceremony_payload_bytes", "PAIRING_MAX_CEREMONY_PAYLOAD_BYTES", "Byte cap on a ceremony payload."),
    ("relay", "pair_tag_bucket_seconds", "RELAY_PAIR_TAG_BUCKET_SECONDS", "The `pair_tag` rotation bucket."),
    ("relay", "accepted_bucket_skew", "RELAY_ACCEPTED_BUCKET_SKEW", "How many buckets either side of the current one a peer accepts."),
    ("relay", "token_lifetime_ms", "RELAY_TOKEN_LIFETIME_MS", "Relay token lifetime."),
    ("relay", "token_clock_skew_ms", "RELAY_TOKEN_CLOCK_SKEW_MS", "Skew allowance on a relay token's window."),
    ("control_plane", "c2_backlog_watermark_bytes", "C2_BACKLOG_WATERMARK_BYTES", "C2 backpressure watermark, in bytes."),
    ("control_plane", "c2_backlog_watermark_events", "C2_BACKLOG_WATERMARK_EVENTS", "C2 backpressure watermark, in events."),
    ("control_plane", "idempotency_dedup_window_ms", "IDEMPOTENCY_DEDUP_WINDOW_MS", "The idempotency dedup window."),
    ("control_plane", "relay_flow_idempotency_window_ms", "RELAY_FLOW_IDEMPOTENCY_WINDOW_MS", "The relay-flow idempotency window."),
    ("ports", "min", "PORT_MIN", "Lowest valid port. Port 0 is malformed."),
    ("ports", "max", "PORT_MAX", "Highest valid port."),
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let registry = manifest.join(REGISTRY_REL);
    println!("cargo:rerun-if-changed={}", registry.display());
    println!("cargo:rerun-if-changed=build.rs");
    // The generated bindings are `include!`d rather than copied, so a change to
    // the frozen source must re-run this crate's build.
    println!(
        "cargo:rerun-if-changed={}",
        manifest
            .join("../../../contracts/gen/rust/src/twinvpn.v1.rs")
            .display()
    );

    let raw = std::fs::read_to_string(&registry)
        .unwrap_or_else(|e| panic!("cannot read frozen registry {}: {e}", registry.display()));
    let doc: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("limits.json is not valid JSON: {e}"));

    let mut out = String::with_capacity(16 * 1024);
    out.push_str("// @generated by twinvpn-schema/build.rs from contracts/registry/limits.json.\n");
    out.push_str(
        "// DO NOT EDIT. The registry is frozen; edit neither this file nor the registry.\n\n",
    );

    for (section, key, name, doc_text) in LIMITS {
        let value = doc[section][key].as_u64().unwrap_or_else(|| {
            panic!("limits.json has no numeric `{section}.{key}`; a validator depends on it")
        });
        let ty = if *name == "PORT_MIN" || *name == "PORT_MAX" {
            "u32"
        } else {
            "usize"
        };
        // Underscore separators, so the generated file satisfies
        // `clippy::unreadable_literal` under the crate's pedantic lint level.
        let literal = group_digits(value);
        out.push_str(&format!(
            "/// {doc_text}\n///\n/// `contracts/registry/limits.json` `{section}.{key}`.\npub const {name}: {ty} = {literal};\n\n"
        ));
    }

    let version = doc["registry_version"]
        .as_u64()
        .expect("limits.json registry_version");
    out.push_str(&format!(
        "/// The frozen limits registry version this build embeds.\npub const LIMITS_REGISTRY_VERSION: u32 = {version};\n"
    ));

    let dest =
        PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("limits_generated.rs");
    std::fs::write(&dest, out).expect("write generated limits");
}

/// Formats `v` with `_` separators every three digits.
fn group_digits(v: u64) -> String {
    let digits = v.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('_');
        }
        out.push(c);
    }
    out
}
