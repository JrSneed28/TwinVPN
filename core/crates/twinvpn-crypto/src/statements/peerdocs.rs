//! Device-signed and Owner-signed peer documents: routes, exit offers, the
//! relay epoch floor, the freshness proof, and the network contract.
//!
//! **Authority:** `signed_statements.cddl` §11, §12, §14, §16, §17; ADR-0010 R1;
//! ADR-0006 §11.2; ADR-0002 §S-3; ADR-0003 §11.5 NC-2..NC-4.

use super::{array, boolean, fixed, text, uint, Schema};
use crate::cose::VerifiedStatement;
use crate::dcbor::Value;
use crate::error::StatementKind;
use crate::{CryptoError, Result};

/// The cap on advertised prefixes per family, applied before any `Vec` grows.
///
/// A device advertises the prefixes behind a `LANGateway`; a few dozen is a
/// large home or small office. 256 per family bounds a hostile advertisement
/// without constraining a real one.
pub const MAX_PREFIXES_PER_FAMILY: usize = 256;

/// The cap on `requires_capability` entries.
pub const MAX_REQUIRED_CAPABILITIES: usize = 32;

// --- 11. RouteAdvertisement -------------------------------------------------

const ROUTE_SCHEMA: Schema = Schema {
    kind: StatementKind::RouteAdvertisement,
    labels: &[1, 2, 3, 4, 5, 6, 7, 8, 9],
    crit_label: 9,
    understood_crit: &[
        "advertiser",
        "twinnet_id",
        "prefixes_v4",
        "prefixes_v6",
        "metric",
        "advertisement_epoch",
        "not_after_ms",
        "requires_capability",
    ],
    required_crit: &["advertisement_epoch"],
};

/// One advertised prefix, canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrefix {
    /// Network octets: four for v4, sixteen for v6.
    pub octets: Vec<u8>,
    /// Prefix length: `0..=32` for v4, `0..=128` for v6.
    pub prefix_len: u8,
}

/// A device's authoritative advertisement of its own routes (S-16).
///
/// The CDDL states the reason the signature exists: "Without the signature, a
/// coordination service that could mint routes could advertise `0.0.0.0/0` and
/// `::/0` and **CAPTURE THE WHOLE TwinNet'S TRAFFIC**."
///
/// # The two families are co-equal
///
/// "The two prefix lists are SEPARATE AND CO-EQUAL. A device MUST NOT infer v6
/// reachability from a v4 advertisement or vice versa." Both fields are
/// non-optional here, and each may legitimately be empty — an empty v6 list
/// means *no v6 routes*, never "same as v4".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    /// Who is advertising.
    pub advertiser: [u8; 32],
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// IPv4 prefixes.
    pub prefixes_v4: Vec<SignedPrefix>,
    /// IPv6 prefixes.
    pub prefixes_v6: Vec<SignedPrefix>,
    /// Advertised metric.
    pub metric: u64,
    /// **Monotone per advertiser**: "a lower epoch from the same advertiser MUST
    /// BE IGNORED."
    pub advertisement_epoch: u64,
    /// Default 1 h, refreshed at half TTL. Expiry "MUST produce a visible
    /// `ROUTE.ADVERTISEMENT_EXPIRED`, not a silent disappearance."
    pub not_after_ms: u64,
    /// Capabilities a peer needs to accept these routes.
    pub requires_capability: Vec<String>,
}

/// Decodes a verified `RouteAdvertisement`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_route_advertisement(s: &VerifiedStatement) -> Result<RouteAdvertisement> {
    ROUTE_SCHEMA.check(s)?;
    let caps_raw = array(s, 8, "requires_capability")?;
    if caps_raw.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(bad("requires_capability over cap"));
    }
    let mut requires_capability = Vec::with_capacity(caps_raw.len());
    for v in caps_raw {
        let t = v.as_text().ok_or_else(|| bad("capability is not text"))?;
        // `ownership.md` §4.3: capability names validate against 32, not
        // `limits.json`'s stale 24.
        if t.is_empty() || t.len() > 32 {
            return Err(bad("capability name outside its bound"));
        }
        requires_capability.push(t.to_owned());
    }
    Ok(RouteAdvertisement {
        advertiser: fixed::<32>(s, 1, "advertiser")?,
        twinnet_id: text(s, 2, "twinnet_id")?,
        prefixes_v4: prefixes(array(s, 3, "prefixes_v4")?, 4, 32)?,
        prefixes_v6: prefixes(array(s, 4, "prefixes_v6")?, 16, 128)?,
        metric: uint(s, 5, "metric")?,
        advertisement_epoch: uint(s, 6, "advertisement_epoch")?,
        not_after_ms: uint(s, 7, "not_after_ms")?,
        requires_capability,
    })
}

/// Decodes `[* [bstr .size N, uint]]`, enforcing canonical prefixes.
///
/// "Canonical" here means the host bits are zero. A prefix whose host bits are
/// set has two readings — the network it names and the address it looks like —
/// and `common.proto`'s rule is "reject, never normalize", because normalizing
/// attacker input before a policy check is how a rule intended to match one
/// network comes to match another.
fn prefixes(raw: &[Value], width: usize, max_len: u8) -> Result<Vec<SignedPrefix>> {
    if raw.len() > MAX_PREFIXES_PER_FAMILY {
        return Err(bad("prefix count over cap"));
    }
    let mut out = Vec::with_capacity(raw.len());
    for v in raw {
        let pair = v.as_array().ok_or_else(|| bad("prefix is not a pair"))?;
        if pair.len() != 2 {
            return Err(bad("prefix pair arity"));
        }
        let octets = pair[0]
            .as_bytes()
            .filter(|b| b.len() == width)
            .ok_or_else(|| bad("prefix octet width"))?;
        let len = pair[1].as_uint().ok_or_else(|| bad("prefix length"))?;
        let len = u8::try_from(len)
            .ok()
            .filter(|l| *l <= max_len)
            .ok_or_else(|| bad("prefix length out of range"))?;
        if !host_bits_are_zero(octets, len) {
            return Err(bad("prefix is not canonical"));
        }
        out.push(SignedPrefix {
            octets: octets.to_vec(),
            prefix_len: len,
        });
    }
    Ok(out)
}

fn host_bits_are_zero(octets: &[u8], prefix_len: u8) -> bool {
    let bits = usize::from(prefix_len);
    let full = bits / 8;
    let rem = bits % 8;
    if rem != 0 {
        let mask = 0xffu8 >> rem;
        if octets[full] & mask != 0 {
            return false;
        }
    }
    let first_zero = if rem == 0 { full } else { full + 1 };
    octets[first_zero..].iter().all(|b| *b == 0)
}

// --- 12. ExitNodeOffer ------------------------------------------------------

const EXIT_SCHEMA: Schema = Schema {
    kind: StatementKind::ExitNodeOffer,
    labels: &[1, 2, 3, 4, 5, 6, 7, 8, 9],
    crit_label: 9,
    understood_crit: &[
        "device_id",
        "egress_families",
        "supports_default_v4",
        "supports_default_v6",
        "geo_hint",
        "bandwidth_class",
        "offer_epoch",
        "not_after_ms",
    ],
    // "MUST include \"supports_default_v4\" and \"supports_default_v6\" — a
    // future restriction on either MUST NOT be silently ignored by an old
    // device."
    required_crit: &["supports_default_v4", "supports_default_v6"],
};

/// A device's offer to act as an `ExitNode`.
///
/// The CDDL: "PER-FAMILY AND EXPLICIT, WITH NO DEFAULTING: an absent field is a
/// DENIAL, not a permission. A v4-only exit grant with v6 leaking to the local
/// ISP is the exact IPv6 leak this product must never ship."
///
/// So both `supports_default_*` fields are non-optional `bool`s, and the decoder
/// refuses a statement missing either rather than reading it as `false` — the
/// difference matters because a *missing* field is a malformed statement, while
/// an explicit `false` is a considered denial, and conflating them hides a
/// producer bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitNodeOffer {
    /// The offering device.
    pub device_id: [u8; 32],
    /// Which families this node egresses. `"v4"` and/or `"v6"`.
    pub egress_families: Vec<String>,
    /// Whether it will carry a v4 default route.
    pub supports_default_v4: bool,
    /// Whether it will carry a v6 default route.
    pub supports_default_v6: bool,
    /// "Never finer than a country."
    pub geo_hint: String,
    /// Coarse bandwidth class.
    pub bandwidth_class: u64,
    /// **Monotone per offerer.**
    pub offer_epoch: u64,
    /// Expiry.
    pub not_after_ms: u64,
}

/// Decodes a verified `ExitNodeOffer`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_exit_node_offer(s: &VerifiedStatement) -> Result<ExitNodeOffer> {
    EXIT_SCHEMA.check(s)?;
    let raw = array(s, 2, "egress_families")?;
    if raw.len() > 2 {
        return Err(bad("egress_families over cap"));
    }
    let mut egress_families = Vec::with_capacity(raw.len());
    for v in raw {
        let t = v.as_text().ok_or_else(|| bad("family is not text"))?;
        if t != "v4" && t != "v6" {
            return Err(bad("egress family outside {v4, v6}"));
        }
        if egress_families.contains(&t.to_owned()) {
            return Err(bad("duplicate egress family"));
        }
        egress_families.push(t.to_owned());
    }
    Ok(ExitNodeOffer {
        device_id: fixed::<32>(s, 1, "device_id")?,
        egress_families,
        supports_default_v4: boolean(s, 3, "supports_default_v4")?,
        supports_default_v6: boolean(s, 4, "supports_default_v6")?,
        geo_hint: text(s, 5, "geo_hint")?,
        bandwidth_class: uint(s, 6, "bandwidth_class")?,
        offer_epoch: uint(s, 7, "offer_epoch")?,
        not_after_ms: uint(s, 8, "not_after_ms")?,
    })
}

// --- 14. RelayEpochFloor ----------------------------------------------------

const RELAY_FLOOR_SCHEMA: Schema = Schema {
    kind: StatementKind::RelayEpochFloor,
    labels: &[1, 2, 3, 4, 5],
    crit_label: 5,
    understood_crit: &[
        "twinnet_id",
        "operator_group_id",
        "epoch_floor",
        "not_after_ms",
    ],
    required_crit: &["epoch_floor"],
};

/// The Owner-signed, monotone relay epoch floor.
///
/// Owner-signed and monotone is what lets it be piggybacked by any connecting
/// client, "because a relay partitioned from the control plane STILL LEARNS OF
/// REVOCATIONS FROM ITS OWN USERS." Relay denial is defence in depth only:
/// revocation is enforced at the peer, so a lagging relay leaks no access and no
/// confidentiality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEpochFloor {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// Which operator group.
    pub operator_group_id: String,
    /// **Monotone.**
    pub epoch_floor: u64,
    /// Expiry.
    pub not_after_ms: u64,
}

/// Decodes a verified `RelayEpochFloor`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_relay_epoch_floor(s: &VerifiedStatement) -> Result<RelayEpochFloor> {
    RELAY_FLOOR_SCHEMA.check(s)?;
    Ok(RelayEpochFloor {
        twinnet_id: text(s, 1, "twinnet_id")?,
        operator_group_id: text(s, 2, "operator_group_id")?,
        epoch_floor: uint(s, 3, "epoch_floor")?,
        not_after_ms: uint(s, 4, "not_after_ms")?,
    })
}

// --- 16. LogHead ------------------------------------------------------------

const LOG_HEAD_SCHEMA: Schema = Schema {
    kind: StatementKind::LogHead,
    labels: &[1, 2, 3, 4, 5, 6],
    crit_label: 6,
    understood_crit: &[
        "twinnet_id",
        "net_seq",
        "revocation_epoch",
        "issued_at_ms",
        "not_after_ms",
    ],
    required_crit: &[],
};

/// The periodic freshness proof.
///
/// # Its stated limitation, carried in the type's documentation
///
/// "the signing key is an ONLINE control-plane key, so a COMPROMISED control
/// plane CAN FORGE FRESHNESS. It cannot forge TRUST — that requires the Owner
/// authority — but it can lie about there being nothing to fetch." A caller must
/// not read a valid `LogHead` as evidence of anything but liveness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHead {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// The writer's sequence number.
    pub net_seq: u64,
    /// The revocation epoch as of this head.
    pub revocation_epoch: u64,
    /// When it was issued.
    pub issued_at_ms: u64,
    /// Expiry. Three missed intervals raise `CONTROL.FRESHNESS_PROOF_MISSING`.
    pub not_after_ms: u64,
}

/// Decodes a verified `LogHead`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_log_head(s: &VerifiedStatement) -> Result<LogHead> {
    LOG_HEAD_SCHEMA.check(s)?;
    Ok(LogHead {
        twinnet_id: text(s, 1, "twinnet_id")?,
        net_seq: uint(s, 2, "net_seq")?,
        revocation_epoch: uint(s, 3, "revocation_epoch")?,
        issued_at_ms: uint(s, 4, "issued_at_ms")?,
        not_after_ms: uint(s, 5, "not_after_ms")?,
    })
}

// --- 17. NetworkContract ----------------------------------------------------

const CONTRACT_SCHEMA: Schema = Schema {
    kind: StatementKind::NetworkContract,
    labels: &[1, 2, 3, 4, 5, 6, 7, 8, 9],
    crit_label: 9,
    understood_crit: &["contract_seq", "address_v4", "address_v6", "routes", "dns"],
    // NC-4: "THE crit SET IS FIXED at {contract_seq, address_v4, address_v6,
    // routes, dns}". Fixed means every member is required, not merely permitted.
    required_crit: &["contract_seq", "address_v4", "address_v6", "routes", "dns"],
};

/// The cap on peers in one contract, applied before the `Vec` grows.
pub const MAX_CONTRACT_PEERS: usize = 1024;

/// The signed contract ADR-0010, ADR-0011 and ADR-0013 consume offline.
///
/// `routes`, `dns` and the peer index are carried as opaque deterministic-CBOR
/// octets for the same reason the `PolicyBundle`'s documents are: their shapes
/// belong to other ADRs.
///
/// NC-2 atomicity — "a device either installs the WHOLE generation … or NONE of
/// it" — is `twinvpn-route`'s to enforce; this decoder's contribution is that a
/// partially decodable contract is **no** contract, because every field is
/// mandatory and one failure rejects the whole statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkContractHeader {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// **Monotone.** NC-3: "a device MUST REJECT a contract whose
    /// `contract_seq` is AT OR BELOW its high-water mark."
    pub contract_seq: u64,
    /// This device's overlay `/32`.
    pub address_v4: [u8; 4],
    /// This device's overlay `/128`.
    pub address_v6: [u8; 16],
    /// Opaque deterministic-CBOR route document.
    pub routes: Vec<u8>,
    /// Opaque deterministic-CBOR DNS document.
    pub dns: Vec<u8>,
    /// The forward and reverse index source for ADR-0011 DN-7.
    pub peers: Vec<ContractPeer>,
    /// Expiry.
    pub not_after_ms: u64,
}

/// One peer's entry in the contract's name and address index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractPeer {
    /// The peer.
    pub device_id: [u8; 32],
    /// Its DNS label.
    pub label: String,
    /// Its overlay v4 address.
    pub address_v4: [u8; 4],
    /// Its overlay v6 address.
    pub address_v6: [u8; 16],
}

/// Decodes a verified `NetworkContract` header.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_network_contract(s: &VerifiedStatement) -> Result<NetworkContractHeader> {
    CONTRACT_SCHEMA.check(s)?;
    let raw = array(s, 7, "peers")?;
    if raw.len() > MAX_CONTRACT_PEERS {
        return Err(bad("contract peer count over cap"));
    }
    let mut peers = Vec::with_capacity(raw.len());
    for v in raw {
        if v.map_keys() != vec![1, 2, 3, 4] {
            return Err(bad("contract peer field set"));
        }
        peers.push(ContractPeer {
            device_id: map_fixed::<32>(v, 1)?,
            label: {
                let t = v
                    .map_get(2)
                    .and_then(Value::as_text)
                    .ok_or_else(|| bad("contract peer label"))?;
                // A DNS label: LDH, <= 63 octets (`device.proto`).
                if t.is_empty() || t.len() > 63 {
                    return Err(bad("contract peer label length"));
                }
                t.to_owned()
            },
            address_v4: map_fixed::<4>(v, 3)?,
            address_v6: map_fixed::<16>(v, 4)?,
        });
    }
    let doc = |label: u64, what: &'static str| -> Result<Vec<u8>> {
        let b = super::bytes(s, label, what)?;
        crate::dcbor::require_canonical(b)
            .map_err(|e| e.into_crypto_error(StatementKind::NetworkContract))?;
        Ok(b.to_vec())
    };
    Ok(NetworkContractHeader {
        twinnet_id: text(s, 1, "twinnet_id")?,
        contract_seq: uint(s, 2, "contract_seq")?,
        address_v4: fixed::<4>(s, 3, "address_v4")?,
        address_v6: fixed::<16>(s, 4, "address_v6")?,
        routes: doc(5, "routes")?,
        dns: doc(6, "dns")?,
        peers,
        not_after_ms: uint(s, 8, "not_after_ms")?,
    })
}

fn map_fixed<const N: usize>(v: &Value, label: u64) -> Result<[u8; N]> {
    v.map_get(label)
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| bad("fixed-width field in a nested map"))
}

fn bad(step: &'static str) -> CryptoError {
    CryptoError::NonCanonicalCbor {
        // The kind is refined by the caller's schema check, which has already
        // run; this is the shared shape for a field-level rejection.
        kind: StatementKind::NetworkContract,
        step,
    }
}
