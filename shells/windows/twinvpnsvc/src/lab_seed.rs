//! The `lab-seed` feature: the two control-plane facts and the one key set that
//! a disposable lab guest has no control plane to deliver.
//!
//! **Never in `default`.** This module exists only under the `lab-seed` Cargo
//! feature, which also turns on `twinvpn-crypto/test-support` — a feature
//! `core/README.md` §3 records as never shipping. A build that carries it is a
//! lab artifact and says so at WARN on every start.
//!
//! # What is missing on a lab guest, and why seeding is the honest answer
//!
//! `twinvpn_core::enforce::arm` cannot assemble a `NetworkContract` without this
//! device's own overlay allocation (S-08), and it treats a peer as authorized
//! only through a `PeerRecord` whose `tunnel_key_binding_verified` is true
//! (ADR-0007 N-4). Both are written by `ControlPlanePort` and both are
//! memory-only, so both are gone at every service start. `Core::install_tunnel_keying`
//! and `Core::set_peer_endpoint` are the two further seams the composed core
//! documents as *real entry points with no production source on this build* —
//! the pairing ceremony and rendezvous are what will fill them.
//!
//! So the guest is seeded from a file rather than from a fabricated control
//! plane: the values are exactly the ones the real sources would deliver, they
//! arrive through the same public API, and nothing below invents a value that a
//! production build would have derived.
//!
//! # This is a trust boundary
//!
//! The file is parsed as untrusted input: every field is length-checked and
//! range-checked, the read is bounded, and **any malformed field refuses the
//! start by name** rather than being defaulted. A lab rig that silently started
//! with half a seed would be measuring something nobody could name.

use twinvpn_core::Core;
use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::prologue::NegotiationBinding;
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_types::{
    DeviceId, Endpoint, IpAddr, OverlayAddresses, Port, TwinnetId, V4Addr, V6Addr,
};

use crate::service::start::StartupRefusal;

/// The environment variable that names the seed file. Unset means "do nothing".
pub const SEED_FILE_VAR: &str = "TWINVPN_LAB_SEED_FILE";

/// The largest seed file this will read.
///
/// The document is a few hundred bytes; the cap exists because a path from the
/// environment is an input like any other and an unbounded read is an
/// unbounded allocation.
const MAX_SEED_BYTES: u64 = 64 * 1024;

/// The `trust_epoch` a seeded `DataPlaneView` reports.
///
/// `planes::DataPlaneView::trust_epoch` answers 0 for a `TwinNet` no anchor
/// chain has advanced, and `execute::establishment::direct` reads the epoch from
/// there rather than from the seed — so the prologue is built at 0 whatever the
/// file says. A seed claiming anything else would produce a handshake that
/// failed for a reason the file appears to explain, so it is refused instead.
const SEEDED_TRUST_EPOCH: u64 = 0;

/// Seeds `core` from the file [`SEED_FILE_VAR`] names, if it names one.
///
/// # Errors
///
/// [`StartupRefusal`] naming the field, if the variable is set and the file is
/// unreadable, oversized, not JSON, or carries a field that does not parse.
/// **An unreadable seed is a refusal, not a warning**: the lane's whole
/// measurement depends on the tunnel that this file is what builds.
pub fn seed_from_env(core: &Core) -> Result<(), StartupRefusal> {
    let Some(path) = std::env::var_os(SEED_FILE_VAR) else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let text = read_bounded(&path)?;
    let seed = Seed::parse(&text)?;
    seed.install(core);
    Ok(())
}

/// Reads the file, refusing one larger than [`MAX_SEED_BYTES`].
fn read_bounded(path: &std::path::Path) -> Result<String, StartupRefusal> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        refuse(
            SEED_FILE_VAR,
            &format!("{} cannot be read: {error}", path.display()),
        )
    })?;
    if metadata.len() > MAX_SEED_BYTES {
        return Err(refuse(
            SEED_FILE_VAR,
            &format!(
                "{} is {} bytes; the seed document is bounded at {MAX_SEED_BYTES}",
                path.display(),
                metadata.len()
            ),
        ));
    }
    std::fs::read_to_string(path).map_err(|error| {
        refuse(
            SEED_FILE_VAR,
            &format!("{} cannot be read: {error}", path.display()),
        )
    })
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// `guest.json`, as written. Every value is text or a small integer here;
/// nothing is interpreted until [`Seed::parse`] has checked it.
///
/// `deny_unknown_fields` on every level: a field the generator meant to matter
/// and this build does not understand is a mismatch between two halves of one
/// lab, and discovering it at start is strictly better than discovering it as a
/// handshake that will not complete.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    twinnet_id: String,
    local: LocalHalf,
    peer: PeerHalf,
    psk: PskHalf,
    negotiation: NegotiationHalf,
    anchor_version: u32,
    delegation_set_digest: String,
    trust_epoch: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHalf {
    device_id: String,
    static_private: String,
    overlay_v4: String,
    overlay_v6: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerHalf {
    device_id: String,
    static_public: String,
    overlay_v4: String,
    overlay_v6: String,
    endpoint: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PskHalf {
    pair_secret: String,
    epoch_seed: String,
    epoch: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NegotiationHalf {
    h_initiator: String,
    h_responder: String,
    selection_dcbor: String,
}

/// One parsed, checked seed: exactly the arguments the four core calls take.
pub struct Seed {
    twinnet: TwinnetId,
    local_device: DeviceId,
    local_overlay: OverlayAddresses,
    peer_device: DeviceId,
    peer_overlay: OverlayAddresses,
    peer_endpoint: Endpoint,
    keying: twinvpn_core::session_table::TunnelKeying,
}

impl Seed {
    /// Parses and checks `guest.json`.
    ///
    /// # Errors
    ///
    /// [`StartupRefusal`] naming the first field that does not parse.
    pub fn parse(text: &str) -> Result<Self, StartupRefusal> {
        let doc: Document =
            serde_json::from_str(text).map_err(|error| refuse("guest.json", &error.to_string()))?;

        if doc.trust_epoch != SEEDED_TRUST_EPOCH {
            return Err(refuse(
                "trust_epoch",
                &format!(
                    "is {}; a seeded DataPlaneView reports {SEEDED_TRUST_EPOCH} and the \
                     prologue is built from that, not from this file",
                    doc.trust_epoch
                ),
            ));
        }

        let twinnet = TwinnetId::new(&doc.twinnet_id)
            .map_err(|error| refuse("twinnet_id", &error.to_string()))?;
        let local_device = device_id("local.device_id", &doc.local.device_id)?;
        let peer_device = device_id("peer.device_id", &doc.peer.device_id)?;

        // `adopt` and not `new_with`: the bytes have already been in unlocked
        // memory — they arrived as hex in a file — and `LockedBytes::adopt` is
        // the path this crate names for exactly that case. It erases `decoded`
        // before returning, which is the most that can be done from here.
        let mut decoded = hex_32("local.static_private", &doc.local.static_private)?;
        let local_static = LockedBytes::adopt(&mut decoded)
            .map_err(|error| refuse("local.static_private", &error.to_string()))?;

        let peer_static = hex_32("peer.static_public", &doc.peer.static_public)?;
        let peer_key = twinvpn_crypto::testkit::verified_tunnel_key(&peer_static);

        let pair_secret = hex_32("psk.pair_secret", &doc.psk.pair_secret)?;
        let epoch_seed = hex_32("psk.epoch_seed", &doc.psk.epoch_seed)?;
        let psk = TwinNetPsk::derive(&pair_secret, &epoch_seed, &doc.twinnet_id, doc.psk.epoch)
            .map_err(|error| refuse("psk", &error.to_string()))?;

        let negotiation = NegotiationBinding {
            h_initiator: hex_32("negotiation.h_initiator", &doc.negotiation.h_initiator)?,
            h_responder: hex_32("negotiation.h_responder", &doc.negotiation.h_responder)?,
            selection_dcbor: hex_bytes(
                "negotiation.selection_dcbor",
                &doc.negotiation.selection_dcbor,
            )?,
        };
        let delegation_set_digest = hex_32("delegation_set_digest", &doc.delegation_set_digest)?;

        let keying = twinvpn_core::session_table::TunnelKeying::new(
            local_static,
            peer_key,
            psk,
            negotiation,
            local_device,
            twinnet.clone(),
            doc.anchor_version,
            delegation_set_digest,
        )
        .ok_or_else(|| {
            refuse(
                "local.static_private",
                "is not the width an L-DATA static key has",
            )
        })?;

        Ok(Self {
            twinnet,
            local_device,
            local_overlay: overlay("local", &doc.local.overlay_v4, &doc.local.overlay_v6)?,
            peer_device,
            peer_overlay: overlay("peer", &doc.peer.overlay_v4, &doc.peer.overlay_v6)?,
            peer_endpoint: endpoint("peer.endpoint", &doc.peer.endpoint)?,
            keying,
        })
    }

    /// The four calls, in the order the core documents them.
    ///
    /// Announced at WARN — the identifiers only. No key material, no PSK input
    /// and no static reaches a log line here or anywhere below.
    ///
    /// `TwinnetId` and `DeviceId` are `SENSITIVE`, so `as_str` and `text_form`
    /// are the redaction-bypassing paths and are named here rather than reached
    /// through a `Debug` that would have hidden them. On a lab guest that is the
    /// point: this line is how the lane says which TwinNet it measured.
    pub fn install(self, core: &Core) {
        tracing::warn!(
            target: "twinvpn.service",
            twinnet = %self.twinnet.as_str(),
            local_device = %self.local_device.text_form(),
            peer_device = %self.peer_device.text_form(),
            peer_endpoint = ?self.peer_endpoint,
            "LAB SEED ACTIVE: this build is not a release artifact"
        );

        let control_plane = core.control_plane_port();
        // S-08: this device's own allocation, which `enforce::arm` cannot
        // assemble a contract without.
        control_plane.put_local_overlay(&self.twinnet, self.local_overlay);
        // ADR-0007 N-4: the verdict, which is what makes the record an
        // authorization rather than an acquaintance.
        control_plane.put_peer(
            &self.twinnet,
            twinvpn_core::PeerRecord {
                device_id: self.peer_device,
                generation: 1,
                tk_generation: 1,
                tunnel_key_binding_verified: true,
                endpoints: vec![self.peer_endpoint],
                overlay: self.peer_overlay,
            },
        );
        core.install_tunnel_keying(self.peer_device, self.keying);
        core.set_peer_endpoint(self.peer_device, self.peer_endpoint);
    }
}

// ---------------------------------------------------------------------------
// Field parsing. Every helper names the field it refused.
// ---------------------------------------------------------------------------

fn refuse(field: &str, detail: &str) -> StartupRefusal {
    StartupRefusal::platform(
        "PLATFORM.ADAPTER_UNAVAILABLE",
        "PLATFORM.ADAPTER_UNAVAILABLE",
        format!("the lab seed field `{field}` {detail}"),
    )
}

const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Lower- or upper-case hex, of any even length.
///
/// Decoded from the bytes rather than by slicing the `str`, so a non-ASCII
/// character is a refusal and never a panic on a character boundary.
fn hex_bytes(field: &str, text: &str) -> Result<Vec<u8>, StartupRefusal> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(refuse(field, "has an odd number of hex digits"));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let (Some(hi), Some(lo)) = (nibble(pair[0]), nibble(pair[1])) else {
            return Err(refuse(field, "is not hexadecimal"));
        };
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_32(field: &str, text: &str) -> Result<[u8; 32], StartupRefusal> {
    let bytes = hex_bytes(field, text)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| refuse(field, &format!("is {} bytes; 32 are required", bytes.len())))
}

fn device_id(field: &str, text: &str) -> Result<DeviceId, StartupRefusal> {
    Ok(DeviceId::from_array(hex_32(field, text)?))
}

fn overlay(half: &str, v4: &str, v6: &str) -> Result<OverlayAddresses, StartupRefusal> {
    // ADR-0010 R1: both families, always. `OverlayAddresses` has no half, so a
    // seed that named one family could not be represented even if it wanted to.
    Ok(OverlayAddresses {
        v4: match address(&format!("{half}.overlay_v4"), v4)? {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => {
                return Err(refuse(&format!("{half}.overlay_v4"), "is an IPv6 address"))
            }
        },
        v6: match address(&format!("{half}.overlay_v6"), v6)? {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => {
                return Err(refuse(&format!("{half}.overlay_v6"), "is an IPv4 address"))
            }
        },
    })
}

fn address(field: &str, text: &str) -> Result<IpAddr, StartupRefusal> {
    let parsed: std::net::IpAddr = text
        .parse()
        .map_err(|_| refuse(field, "is not an IP address"))?;
    from_std(field, parsed)
}

fn from_std(field: &str, parsed: std::net::IpAddr) -> Result<IpAddr, StartupRefusal> {
    match parsed {
        std::net::IpAddr::V4(a) => Ok(IpAddr::V4(V4Addr::from_octets(a.octets()))),
        // Zone index zero: a seeded overlay or endpoint address is never
        // link-local, and `V6Addr::new` refuses one that is without a zone
        // rather than accepting an address no socket could use.
        std::net::IpAddr::V6(a) => V6Addr::from_slice(&a.octets(), 0)
            .map(IpAddr::V6)
            .map_err(|error| refuse(field, &error.to_string())),
    }
}

fn endpoint(field: &str, text: &str) -> Result<Endpoint, StartupRefusal> {
    let parsed: std::net::SocketAddr = text
        .parse()
        .map_err(|_| refuse(field, "is not an `address:port`"))?;
    let port = Port::new(parsed.port()).map_err(|error| refuse(field, &error.to_string()))?;
    Ok(Endpoint::new(from_std(field, parsed.ip())?, port))
}

#[cfg(test)]
#[path = "lab_seed/tests.rs"]
mod tests;
