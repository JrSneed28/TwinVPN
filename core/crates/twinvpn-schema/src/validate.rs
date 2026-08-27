//! Validators for untrusted input, driven by `contracts/registry/limits.json`.
//!
//! **Authority:** `contracts/registry/limits.json`,
//! `contracts/docs/trust-boundaries.md`, `docs/implementation/ownership.md` §6
//! rules 9 and 10.
//!
//! # The order every entry point follows
//!
//! 1. **Byte cap first**, on the raw bytes, before `prost` allocates anything.
//! 2. **Depth cap second**, on the raw bytes, before `prost` recurses.
//! 3. **Decode.**
//! 4. **Field validation** — widths, counts, canonical forms — each against a
//!    `limits.json` constant, each producing a typed [`Reject`].
//!
//! Steps 1 and 2 are what make rule 9's "before any allocation proportional to a
//! declared length" true rather than aspirational: after step 2 the message is
//! known to be within a bounded size and a bounded nesting, so `prost`'s own
//! allocations are bounded by construction.
//!
//! Nothing here truncates, pads, normalizes or silently accepts.

use twinvpn_types::{
    AddressFamily, CandidateId, CausalityToken, ChannelBinding, CorrelationId, DeviceId, Digest,
    Endpoint, IdempotencyKey, IdentityId, IpAddr, IpPrefix, MessageId, PairTag, PairingId, PathId,
    PolicyId, Port, RegionId, RelayId, SessionId, SessionNonce, SignerKeyId, TunnelId, TwinnetId,
    V4Addr, V6Addr,
};

use crate::depth;
use crate::limits::{self, Channel};
use crate::reject::Reject;
use crate::v1;

/// Applies the byte and depth caps, then decodes.
///
/// The single entry point for anything arriving on a wire. A caller that decodes
/// without going through here has skipped both caps.
///
/// # Errors
///
/// [`Reject::SizeExceeded`], [`Reject::DepthExceeded`] or
/// [`Reject::Unparseable`].
pub fn decode<M: prost::Message + Default>(bytes: &[u8], channel: Channel) -> Result<M, Reject> {
    if bytes.len() > channel.max_bytes() {
        return Err(Reject::SizeExceeded {
            parser_id: channel.parser_id(),
            observed: bytes.len(),
            limit: channel.max_bytes(),
        });
    }
    depth::check(bytes, channel)?;
    M::decode(bytes).map_err(|_| Reject::Unparseable {
        parser_id: channel.parser_id(),
    })
}

/// Rejects an inline C2 document that exceeds its own cap.
///
/// `limits.json` explains why this is lower than the envelope cap: "so a single
/// policy bundle cannot monopolise a stream. Larger documents are announced by
/// reference and pulled."
///
/// # Errors
///
/// [`Reject::SizeExceeded`] past 16 KiB.
pub fn check_c2_inline_document(bytes: &[u8]) -> Result<(), Reject> {
    if bytes.len() > limits::C2_INLINE_DOCUMENT_MAX_BYTES {
        return Err(Reject::SizeExceeded {
            parser_id: "c2_inline_document",
            observed: bytes.len(),
            limit: limits::C2_INLINE_DOCUMENT_MAX_BYTES,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Builds an identifier from wire bytes, or rejects.
macro_rules! id_validator {
    ($fn_name:ident, $ty:ty, $key:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Errors
        ///
        /// [`Reject::Malformed`] on any length but the declared one. A length
        /// mismatch is never truncated and never padded: both would silently
        /// convert one identifier into another
        /// (`contracts/docs/identifiers.md` §5).
        pub fn $fn_name(bytes: &[u8]) -> Result<$ty, Reject> {
            <$ty>::from_slice(bytes).map_err(|e| Reject::malformed($key, e))
        }
    };
}

id_validator!(
    device_id,
    DeviceId,
    "device_id_bytes",
    "Validates a `device_id`."
);
id_validator!(
    identity_id,
    IdentityId,
    "identity_id_bytes",
    "Validates an `identity_id`."
);
id_validator!(
    pairing_id,
    PairingId,
    "pairing_id_bytes",
    "Validates a `pairing_id`."
);
id_validator!(
    session_id,
    SessionId,
    "session_id_bytes",
    "Validates a `session_id`."
);
id_validator!(
    tunnel_id,
    TunnelId,
    "tunnel_id_bytes",
    "Validates a `tunnel_id`."
);
id_validator!(path_id, PathId, "path_id_bytes", "Validates a `path_id`.");
id_validator!(
    candidate_id,
    CandidateId,
    "candidate_id_bytes",
    "Validates a `candidate_id`."
);
id_validator!(
    relay_id,
    RelayId,
    "relay_id_bytes",
    "Validates a `relay_id`."
);
id_validator!(
    pair_tag,
    PairTag,
    "pair_tag_bytes",
    "Validates a `pair_tag`."
);
id_validator!(
    message_id,
    MessageId,
    "message_id_bytes",
    "Validates a `message_id`."
);
id_validator!(
    correlation_id,
    CorrelationId,
    "correlation_id_bytes",
    "Validates a `correlation_id`."
);
id_validator!(
    digest,
    Digest,
    "digest_bytes",
    "Validates a carried digest."
);
id_validator!(
    session_nonce,
    SessionNonce,
    "session_nonce_bytes",
    "Validates a `session_nonce`."
);
id_validator!(
    channel_binding,
    ChannelBinding,
    "channel_binding_bytes",
    "Validates an RFC 9266 `tls-exporter` channel binding."
);
id_validator!(
    idempotency_key,
    IdempotencyKey,
    "idempotency_key",
    "Validates an `idempotency_key` against its 16..=64 range."
);
id_validator!(
    causality_token,
    CausalityToken,
    "causality_token_max_bytes",
    "Validates a `causality_token` **before** it allocates."
);

/// Validates a bounded text identifier.
macro_rules! text_validator {
    ($fn_name:ident, $ty:ty, $key:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Errors
        ///
        /// [`Reject::Malformed`] past the cap, on an empty value, or on any
        /// control character.
        pub fn $fn_name(s: &str) -> Result<$ty, Reject> {
            <$ty>::new(s).map_err(|e| Reject::malformed($key, e))
        }
    };
}

text_validator!(
    twinnet_id,
    TwinnetId,
    "twinnet_id_max_bytes",
    "Validates a `twinnet_id`."
);
text_validator!(
    region_id,
    RegionId,
    "region_id_max_bytes",
    "Validates a `region_id`. A device MUST NOT parse the result."
);
text_validator!(
    policy_id,
    PolicyId,
    "policy_id_max_bytes",
    "Validates a `policy_id` or `dnspolicy_id`."
);
text_validator!(
    signer_key_id,
    SignerKeyId,
    "signer_key_id_max_bytes",
    "Validates a `signer_key_id`."
);

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// Validates a wire `AddressFamily`, rejecting `UNSPECIFIED`.
///
/// # Errors
///
/// [`Reject::Malformed`] on `UNSPECIFIED` or an unknown value. Proto3 cannot
/// distinguish "absent" from "zero", so a zero here is a missing required field
/// rather than a default to fill in — and guessing a family is exactly the
/// asymmetry ADR-0010 R1 forbids.
pub fn address_family(value: i32) -> Result<AddressFamily, Reject> {
    match value {
        1 => Ok(AddressFamily::V4),
        2 => Ok(AddressFamily::V6),
        _ => Err(Reject::cap(
            "address_family",
            value.unsigned_abs() as usize,
            2,
        )),
    }
}

/// Validates a wire `IPAddress`, enforcing both canonical-form rules.
///
/// # Errors
///
/// [`Reject::Malformed`] if neither family is set, if a width is wrong, if the
/// address is IPv4-mapped IPv6, or if the RFC 4007 zone rule is violated.
pub fn ip_address(msg: &v1::IpAddress) -> Result<IpAddr, Reject> {
    match &msg.address {
        Some(v1::ip_address::Address::V4(a)) => V4Addr::from_slice(&a.octets)
            .map(IpAddr::V4)
            .map_err(|e| Reject::malformed("ipv4_address_bytes", e)),
        Some(v1::ip_address::Address::V6(a)) => V6Addr::from_slice(&a.octets, a.zone_index)
            .map(IpAddr::V6)
            .map_err(|e| Reject::malformed("ipv6_address_bytes", e)),
        // "An IPAddress with neither set is malformed; the oneof makes 'both'
        // unrepresentable" (common.proto §4).
        None => Err(Reject::cap("ip_address_family_set", 0, 1)),
    }
}

/// Validates a wire `IPPrefix`, enforcing the canonical form.
///
/// # Errors
///
/// [`Reject::Malformed`] on a length past the family's maximum, on a scope zone,
/// or on any set host bit. `10.0.0.1/24` is **rejected, never normalized**:
/// normalizing attacker input before a policy check is how a rule intended to
/// match one network comes to match another.
pub fn ip_prefix(msg: &v1::IpPrefix) -> Result<IpPrefix, Reject> {
    let address = msg
        .address
        .as_ref()
        .ok_or_else(|| Reject::cap("ip_prefix_address_set", 0, 1))?;
    let addr = ip_address(address)?;
    IpPrefix::new(addr, msg.prefix_len).map_err(|e| Reject::malformed("prefix_len", e))
}

/// Validates a wire `Endpoint`.
///
/// # Errors
///
/// [`Reject::Malformed`] on a bad address or on port 0, which `common.proto`
/// declares malformed.
pub fn endpoint(msg: &v1::Endpoint) -> Result<Endpoint, Reject> {
    let address = msg
        .address
        .as_ref()
        .ok_or_else(|| Reject::cap("endpoint_address_set", 0, 1))?;
    let addr = ip_address(address)?;
    let port = Port::from_wire(msg.port).map_err(|e| Reject::malformed("port", e))?;
    Ok(Endpoint::new(addr, port))
}

// ---------------------------------------------------------------------------
// Capabilities — ADR-0014 N-10's pre-authentication caps
// ---------------------------------------------------------------------------

/// One advertised capability token, as it arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken<'a> {
    /// The token name.
    pub name: &'a str,
    /// Its parameters, as `(name, value)`.
    pub parameters: &'a [(&'a str, &'a str)],
}

/// Validates a capability advertisement against ADR-0014 N-10's caps.
///
/// # The capability-name cap is 32, not the registry's 24
///
/// `docs/implementation/ownership.md` §4.3: `limits.json` says 24, but
/// `capabilities.json` says 32, the CDDL says `[a-z][a-z0-9_]{0,31}`, and the
/// capability registry itself contains `dns_config_dies_with_tunnel` — 27 bytes.
/// Validating against 24 would reject a Phase-1-mandated token. `contracts/` is
/// frozen, so this validates against [`limits::CAPABILITY_MAX_NAME_BYTES`] (32)
/// and the exception is legible and removable at that one constant.
///
/// # Errors
///
/// [`Reject::CapViolated`] on a token count, byte, parameter or name violation.
pub fn capability_advertisement(
    tokens: &[CapabilityToken<'_>],
    encoded_bytes: usize,
) -> Result<(), Reject> {
    Reject::check_max(
        "capability.max_tokens_per_advertisement",
        tokens.len(),
        limits::CAPABILITY_MAX_TOKENS,
    )?;
    Reject::check_max(
        "capability.max_advertisement_bytes",
        encoded_bytes,
        limits::CAPABILITY_MAX_ADVERTISEMENT_BYTES,
    )?;
    for token in tokens {
        // ownership.md §4.3: 32, not limits.json's stale 24.
        Reject::check_max(
            "capability.max_name_bytes",
            token.name.len(),
            limits::CAPABILITY_MAX_NAME_BYTES,
        )?;
        if !is_capability_name(token.name) {
            return Err(Reject::cap("capability.name_shape", 0, 1));
        }
        Reject::check_max(
            "capability.max_parameters_per_token",
            token.parameters.len(),
            limits::CAPABILITY_MAX_PARAMETERS,
        )?;
        let param_bytes: usize = token
            .parameters
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        Reject::check_max(
            "capability.max_parameter_bytes_total",
            param_bytes,
            limits::CAPABILITY_MAX_PARAMETER_BYTES,
        )?;
    }
    Ok(())
}

/// `capabilities.cddl`'s `[a-z][a-z0-9_]{0,31}`.
#[must_use]
pub fn is_capability_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= limits::CAPABILITY_MAX_NAME_BYTES
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Rejects an advertised epoch further above `current` than the cap allows.
///
/// # Errors
///
/// [`Reject::CapViolated`] past `capability.max_epoch_above_current`.
pub fn epoch_reach(current: u32, advertised: u32) -> Result<(), Reject> {
    let above = advertised.saturating_sub(current) as usize;
    Reject::check_max(
        "capability.max_epoch_above_current",
        above,
        limits::CAPABILITY_MAX_EPOCH_ABOVE_CURRENT,
    )
}

// ---------------------------------------------------------------------------
// Candidate sets
// ---------------------------------------------------------------------------

/// Validates a `CandidateSet` against its caps, then every candidate in it.
///
/// The count cap is checked **first**, so a set claiming ten thousand candidates
/// is rejected before ten thousand endpoints are validated.
///
/// # Errors
///
/// [`Reject::CapViolated`] past the set cap; whatever [`endpoint`] rejects for a
/// member.
pub fn candidate_set(set: &v1::CandidateSet) -> Result<(), Reject> {
    Reject::check_max(
        "candidates.max_candidates_per_set",
        set.candidates.len(),
        limits::MAX_CANDIDATES_PER_SET,
    )?;
    if !set.session_nonce.is_empty() {
        session_nonce(&set.session_nonce)?;
    }
    for candidate in &set.candidates {
        candidate_id(&candidate.candidate_id)?;
        address_family(candidate.family)?;
        if let Some(ep) = candidate.endpoint.as_ref() {
            let parsed = endpoint(ep)?;
            // ADR-0010 R1: the declared family and the endpoint's actual family
            // must agree. A mismatch would let a v6 candidate be raced as a v4
            // one, which is a per-family asymmetry arriving through the back door.
            if parsed.family() != address_family(candidate.family)? {
                return Err(Reject::cap("candidate.family_matches_endpoint", 0, 1));
            }
        }
    }
    Ok(())
}

/// Validates a `PunchSync`'s port hints and pairs.
///
/// # Errors
///
/// [`Reject::CapViolated`] past the hint cap, or on a pair index that names a
/// candidate outside the accompanying set.
pub fn punch_sync(sync: &v1::PunchSync, local_len: usize, remote_len: usize) -> Result<(), Reject> {
    Reject::check_max(
        "candidates.max_birthday_port_hints",
        sync.birthday_port_hints.len(),
        limits::MAX_BIRTHDAY_PORT_HINTS,
    )?;
    for hint in &sync.birthday_port_hints {
        Port::from_wire(*hint).map_err(|e| Reject::malformed("port", e))?;
    }
    for pair in &sync.pairs {
        // An index past the set is a malformed reference, not a candidate to
        // skip: skipping would let a peer silently change which pair is raced.
        if pair.local_candidate_index as usize >= local_len
            || pair.remote_candidate_index as usize >= remote_len
        {
            return Err(Reject::cap("candidate_pair.index_in_range", 0, 1));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routing and DNS
// ---------------------------------------------------------------------------

/// Validates a route advertisement's prefixes.
///
/// # Errors
///
/// [`Reject::CapViolated`] past `routing.max_prefixes_per_advertisement`, or
/// whatever [`ip_prefix`] rejects.
pub fn route_advertisement(prefixes: &[v1::IpPrefix]) -> Result<Vec<IpPrefix>, Reject> {
    Reject::check_max(
        "routing.max_prefixes_per_advertisement",
        prefixes.len(),
        limits::MAX_PREFIXES_PER_ADVERTISEMENT,
    )?;
    // The cap is checked before this allocates, so the capacity is bounded by the
    // registry rather than by the sender's claim.
    let mut out = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        out.push(ip_prefix(p)?);
    }
    Ok(out)
}

/// Validates a DNS domain name against RFC 1035's 253-byte limit.
///
/// # Errors
///
/// [`Reject::CapViolated`] past the cap, or on an empty or non-ASCII name.
pub fn domain_name(name: &str) -> Result<(), Reject> {
    Reject::check_max(
        "dns.max_domain_name_bytes",
        name.len(),
        limits::MAX_DOMAIN_NAME_BYTES,
    )?;
    if name.is_empty() || !name.is_ascii() || name.chars().any(char::is_control) {
        return Err(Reject::cap("dns.domain_name_shape", 0, 1));
    }
    Ok(())
}

/// Validates a `DNSPolicy`'s counts and its per-family resolver lists.
///
/// # Errors
///
/// [`Reject::CapViolated`] past any of the four DNS caps.
pub fn dns_policy_shape(
    split_rules: usize,
    search_domains: usize,
    resolvers_v4: usize,
    resolvers_v6: usize,
) -> Result<(), Reject> {
    Reject::check_max(
        "dns.max_split_domain_rules",
        split_rules,
        limits::MAX_SPLIT_DOMAIN_RULES,
    )?;
    Reject::check_max(
        "dns.max_search_domains",
        search_domains,
        limits::MAX_SEARCH_DOMAINS,
    )?;
    // Per family, and both families checked — the cap is "per family", so
    // checking their sum would silently allow eight of one and zero of the other
    // to become sixteen of one.
    Reject::check_max(
        "dns.max_resolvers_per_family",
        resolvers_v4,
        limits::MAX_RESOLVERS_PER_FAMILY,
    )?;
    Reject::check_max(
        "dns.max_resolvers_per_family",
        resolvers_v6,
        limits::MAX_RESOLVERS_PER_FAMILY,
    )
}

// ---------------------------------------------------------------------------
// Pairing and relay
// ---------------------------------------------------------------------------

/// Validates the pre-authentication caps on a pairing ceremony's payload.
///
/// These are B3 inputs — they arrive **pre-authentication through an untrusted
/// rendezvous** (`common.proto`'s trust-boundary note), which is why the caps
/// are small and why they are applied before anything is parsed.
///
/// # Errors
///
/// [`Reject::CapViolated`] past either cap.
pub fn pairing_payload(peer_hint: &[u8], ceremony_payload: &[u8]) -> Result<(), Reject> {
    Reject::check_max(
        "pairing.max_peer_hint_bytes",
        peer_hint.len(),
        limits::PAIRING_MAX_PEER_HINT_BYTES,
    )?;
    Reject::check_max(
        "pairing.max_ceremony_payload_bytes",
        ceremony_payload.len(),
        limits::PAIRING_MAX_CEREMONY_PAYLOAD_BYTES,
    )
}

/// Whether a received `pair_tag` bucket is within the accepted skew.
///
/// `contracts/docs/identifiers.md` §4: both peers accept `bucket`, `bucket-1` and
/// `bucket+1`. Expressed as a comparison rather than a subtraction because the
/// bucket is a `u64` and an underflow would silently accept everything.
#[must_use]
pub fn pair_tag_bucket_accepted(current: u64, received: u64) -> bool {
    let skew = limits::RELAY_ACCEPTED_BUCKET_SKEW as u64;
    received >= current.saturating_sub(skew) && received <= current.saturating_add(skew)
}

/// Validates the evidence caps on a received `ErrorEnvelope`.
///
/// `errors.proto` requires the **emitter** to truncate; a receiver that is handed
/// an over-cap set rejects it rather than truncating, because truncating on
/// receipt would silently discard evidence the emitter believed it had sent.
///
/// # Errors
///
/// [`Reject::CapViolated`] past the entry or byte cap.
pub fn evidence_caps(entries: usize, bytes: usize) -> Result<(), Reject> {
    Reject::check_max(
        "diagnostics.max_evidence_entries",
        entries,
        limits::MAX_EVIDENCE_ENTRIES,
    )?;
    Reject::check_max(
        "diagnostics.max_evidence_bytes",
        bytes,
        limits::MAX_EVIDENCE_BYTES,
    )
}
