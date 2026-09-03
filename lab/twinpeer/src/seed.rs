//! `twinpeer seed` — generates the two halves of a lab seed.
//!
//! Everything random here comes from the platform CSPRNG through
//! [`twinvpn_env::Entropy`], and on a host that has none the draw **refuses**
//! rather than substituting anything: `twinvpn_platform_windows::clock`'s
//! non-Windows `fill_random` returns `EntropyUnavailable` for exactly that
//! reason. So `twinpeer seed` runs on the Hyper-V host, which is where the lane
//! runs it.

use std::path::Path;

use anyhow::{Context as _, Result};
use twinvpn_env::Entropy as _;
use twinvpn_platform_windows::clock::WindowsEntropy;

use crate::seedfile::{
    hex, LocalHalf, NegotiationMaterial, PeerHalf, PskMaterial, SeedFile, ResolvedSeed,
};

/// The overlay addresses the lane's address plan fixes.
///
/// Defaults rather than constants: the lane passes them explicitly, and a
/// default that cannot be overridden is a second address plan nobody can see.
pub const GUEST_OVERLAY_V4: &str = "100.64.1.1";
/// The guest's overlay IPv6 address.
pub const GUEST_OVERLAY_V6: &str = "fd7c:9e5d:2a10:1::1";
/// The peer's overlay IPv4 address, which is also the oracle's beacon target.
pub const PEER_OVERLAY_V4: &str = "100.64.1.2";
/// The peer's overlay IPv6 address.
pub const PEER_OVERLAY_V6: &str = "fd7c:9e5d:2a10:1::2";

/// The `det_CBOR(Selection)` stand-in both ends bind.
///
/// A fixed label, not an encoded `Selection`: ADR-0014 owns that encoding and
/// this workspace has no negotiation to encode. What the binding needs is that
/// **both ends cover the same octets**, and a label does that honestly. Named
/// with a version so a change to it is a visible change.
pub const SELECTION_LABEL: &[u8] = b"twinpeer-lab-selection-v1";

/// What `seed` was asked for.
pub struct SeedArgs {
    /// Where the guest half is written.
    pub guest_out: std::path::PathBuf,
    /// Where the peer half is written.
    pub peer_out: std::path::PathBuf,
    /// The peer's UDP endpoint, which the guest sends its initiation to.
    pub peer_endpoint: String,
    /// The `TwinNet` both halves name.
    pub twinnet_id: String,
    /// The guest's overlay addresses.
    pub guest_overlay_v4: String,
    /// The guest's overlay IPv6 address.
    pub guest_overlay_v6: String,
    /// The peer's overlay addresses.
    pub peer_overlay_v4: String,
    /// The peer's overlay IPv6 address.
    pub peer_overlay_v6: String,
}

/// Writes both halves.
///
/// # Errors
///
/// An entropy failure, a field that will not resolve, or a write that failed.
/// **Both halves are resolved before either is written**, so a seed that the
/// service or the peer would refuse at start is refused here instead.
pub fn run(args: &SeedArgs) -> Result<()> {
    let entropy = WindowsEntropy::new();
    let draw = |what: &'static str| -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        entropy
            .fill(&mut out)
            .with_context(|| format!("the platform CSPRNG refused while drawing {what}"))?;
        Ok(out)
    };

    // Ordered so the GUEST is the initiator. `role_for` is a total order over
    // the two names and both ends compute it from the same rule, so the order is
    // decided here once rather than negotiated later — and the lane's `net up`
    // then sends message 1 without waiting for anything.
    let (guest_device, peer_device) = ordered_pair(draw("the device ids")?, draw("the device ids")?);
    let guest_static = draw("the guest's L-DATA static")?;
    let peer_static = draw("the peer's L-DATA static")?;
    let guest_public = public_of(&guest_static)?;
    let peer_public = public_of(&peer_static)?;

    let psk = PskMaterial {
        pair_secret: hex(&draw("the pair secret")?),
        epoch_seed: hex(&draw("the epoch seed")?),
        epoch: 1,
    };
    let negotiation = NegotiationMaterial {
        h_initiator: hex(&draw("H_initiator")?),
        h_responder: hex(&draw("H_responder")?),
        selection_dcbor: hex(SELECTION_LABEL),
    };
    let delegation_set_digest = hex(&draw("the delegation-set digest")?);

    let (guest, peer) = halves(
        args,
        &Material {
            guest_device,
            peer_device,
            guest_static,
            guest_public,
            peer_static,
            peer_public,
            psk,
            negotiation,
            delegation_set_digest,
        },
    );

    let guest_resolved = guest.resolve().context("the guest half is malformed")?;
    let peer_resolved = peer.resolve().context("the peer half is malformed")?;
    assert_halves(&guest_resolved, &peer_resolved)?;

    write(&args.guest_out, &guest)?;
    write(&args.peer_out, &peer)?;
    tracing::info!(
        guest = %args.guest_out.display(),
        peer = %args.peer_out.display(),
        "wrote the lab seed; this material is not a release artifact"
    );
    Ok(())
}

/// Everything drawn from the CSPRNG, so the two halves are a pure function of
/// it and of the address plan — which is what lets a test pin the shape the
/// service's `deny_unknown_fields` parser demands without needing entropy.
struct Material {
    guest_device: [u8; 32],
    peer_device: [u8; 32],
    guest_static: [u8; 32],
    guest_public: [u8; 32],
    peer_static: [u8; 32],
    peer_public: [u8; 32],
    psk: PskMaterial,
    negotiation: NegotiationMaterial,
    delegation_set_digest: String,
}

/// The two halves: the same document with `local` and `peer` swapped.
///
/// **The guest half carries no key the guest does not need.** It gets its own
/// private static and the peer's PUBLIC one, and never the peer's private half
/// — which is what keeps the file the lane copies into the disposable guest
/// from being the whole pair.
fn halves(args: &SeedArgs, m: &Material) -> (SeedFile, SeedFile) {
    let guest = SeedFile {
        twinnet_id: args.twinnet_id.clone(),
        local: LocalHalf {
            device_id: hex(&m.guest_device),
            static_private: hex(&m.guest_static),
            overlay_v4: args.guest_overlay_v4.clone(),
            overlay_v6: args.guest_overlay_v6.clone(),
            // Skipped on serialisation. The service parses guest.json with
            // `deny_unknown_fields` at every level, so a key it does not know
            // is a refusal to start rather than a field it ignores.
            bind: None,
        },
        peer: PeerHalf {
            device_id: hex(&m.peer_device),
            static_public: hex(&m.peer_public),
            overlay_v4: args.peer_overlay_v4.clone(),
            overlay_v6: args.peer_overlay_v6.clone(),
            endpoint: Some(args.peer_endpoint.clone()),
        },
        psk: m.psk.clone(),
        negotiation: m.negotiation.clone(),
        anchor_version: 1,
        delegation_set_digest: m.delegation_set_digest.clone(),
        // The seeded `DataPlaneView` has written no trust epoch, so `0` is the
        // fact rather than a placeholder.
        trust_epoch: 0,
    };
    let peer = SeedFile {
        twinnet_id: args.twinnet_id.clone(),
        local: LocalHalf {
            device_id: hex(&m.peer_device),
            static_private: hex(&m.peer_static),
            overlay_v4: args.peer_overlay_v4.clone(),
            overlay_v6: args.peer_overlay_v6.clone(),
            bind: Some(args.peer_endpoint.clone()),
        },
        peer: PeerHalf {
            device_id: hex(&m.guest_device),
            static_public: hex(&m.guest_public),
            overlay_v4: args.guest_overlay_v4.clone(),
            overlay_v6: args.guest_overlay_v6.clone(),
            // Learned from the initiation's source address, which is the only
            // value that is right through a NAT.
            endpoint: None,
        },
        psk: m.psk.clone(),
        negotiation: m.negotiation.clone(),
        anchor_version: 1,
        delegation_set_digest: m.delegation_set_digest.clone(),
        trust_epoch: 0,
    };
    (guest, peer)
}

/// `(lower, higher)` by byte order — the guest first, so it is the initiator.
fn ordered_pair(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn public_of(private: &[u8; 32]) -> Result<[u8; 32]> {
    let locked = twinvpn_crypto::locked::LockedBytes::new_with(private.len(), |slot| {
        slot.copy_from_slice(private);
    })
    .context("the static could not be placed in the locked allocator")?;
    twinvpn_crypto::noise::static_public_key(&locked)
        .map_err(|e| anyhow::anyhow!("the static's public half could not be derived: {e}"))
}

/// The two halves are the right way round, asserted rather than assumed.
///
/// Both failures are silent at run time and expensive to diagnose. A guest that
/// is the **responder** makes `execute::handshake::drive` wait for a datagram
/// the peer will never send first, so the lane fails as a ten-second timeout
/// with no cause visible anywhere. A guest half with no `peer.endpoint`, or a
/// peer half with no `local.bind`, is the two files written the wrong way round
/// — which fails at the far end, minutes later, as "no usable candidates".
fn assert_halves(guest: &ResolvedSeed, peer: &ResolvedSeed) -> Result<()> {
    use twinvpn_core::lab::{role_for, Role};
    if role_for(guest.local_device, guest.peer_device) != Role::Initiator
        || role_for(peer.local_device, peer.peer_device) != Role::Responder
    {
        anyhow::bail!("the generated device ids do not make the guest the initiator");
    }
    if guest.peer_endpoint.is_none() {
        anyhow::bail!("the guest half carries no `peer.endpoint`");
    }
    if peer.bind.is_none() {
        anyhow::bail!("the peer half carries no `local.bind`");
    }
    if guest.local_overlay != peer.peer_overlay || guest.peer_overlay != peer.local_overlay {
        anyhow::bail!("the two halves disagree about the overlay addresses");
    }
    Ok(())
}

fn write(path: &Path, seed: &SeedFile) -> Result<()> {
    let text = serde_json::to_string_pretty(seed).context("the seed would not serialise")?;
    std::fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> SeedArgs {
        SeedArgs {
            guest_out: std::path::PathBuf::from("guest.json"),
            peer_out: std::path::PathBuf::from("peer.json"),
            peer_endpoint: "10.77.0.1:51820".to_owned(),
            twinnet_id: "tn-lab".to_owned(),
            guest_overlay_v4: GUEST_OVERLAY_V4.to_owned(),
            guest_overlay_v6: GUEST_OVERLAY_V6.to_owned(),
            peer_overlay_v4: PEER_OVERLAY_V4.to_owned(),
            peer_overlay_v6: PEER_OVERLAY_V6.to_owned(),
        }
    }

    /// Fixed material, so the shape is a pure function of it. Never a key.
    fn material() -> Material {
        Material {
            guest_device: [0x11; 32],
            peer_device: [0x22; 32],
            guest_static: [0x33; 32],
            guest_public: [0x34; 32],
            peer_static: [0x44; 32],
            peer_public: [0x45; 32],
            psk: PskMaterial {
                pair_secret: hex(&[0x55; 32]),
                epoch_seed: hex(&[0x66; 32]),
                epoch: 1,
            },
            negotiation: NegotiationMaterial {
                h_initiator: hex(&[0x77; 32]),
                h_responder: hex(&[0x88; 32]),
                selection_dcbor: hex(SELECTION_LABEL),
            },
            delegation_set_digest: hex(&[0x99; 32]),
        }
    }

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut out: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        out.sort();
        out
    }

    #[test]
    fn the_guest_half_carries_exactly_the_keys_the_service_parser_accepts() {
        // `shells/windows/twinvpnsvc`'s `lab_seed` parses this with
        // `deny_unknown_fields` at EVERY level, so one extra key here is a
        // service that refuses to start rather than one that ignores a field.
        // This test is the contract between the two packages.
        let (guest, _) = halves(&args(), &material());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&guest).expect("serialises"))
                .expect("round-trips");

        assert_eq!(
            keys(&json),
            [
                "anchor_version",
                "delegation_set_digest",
                "local",
                "negotiation",
                "peer",
                "psk",
                "trust_epoch",
                "twinnet_id",
            ]
        );
        assert_eq!(
            keys(&json["local"]),
            ["device_id", "overlay_v4", "overlay_v6", "static_private"],
            "`bind` is the peer half's; the guest's parser would refuse it"
        );
        assert_eq!(
            keys(&json["peer"]),
            [
                "device_id",
                "endpoint",
                "overlay_v4",
                "overlay_v6",
                "static_public"
            ]
        );
        assert_eq!(keys(&json["psk"]), ["epoch", "epoch_seed", "pair_secret"]);
        assert_eq!(
            keys(&json["negotiation"]),
            ["h_initiator", "h_responder", "selection_dcbor"]
        );
        assert_eq!(json["trust_epoch"], 0, "a seeded view has no trust epoch");
        assert_eq!(json["peer"]["endpoint"], "10.77.0.1:51820");
    }

    #[test]
    fn the_guest_half_never_carries_the_peers_private_static() {
        let (guest, _) = halves(&args(), &material());
        let text = serde_json::to_string(&guest).expect("serialises");
        assert!(
            !text.contains(&hex(&[0x44; 32])),
            "the peer's private static must not reach the disposable guest"
        );
        assert!(text.contains(&hex(&[0x45; 32])), "its PUBLIC half must");
    }

    #[test]
    fn the_peer_half_carries_the_bind_and_no_endpoint() {
        let (_, peer) = halves(&args(), &material());
        assert_eq!(peer.local.bind.as_deref(), Some("10.77.0.1:51820"));
        assert!(
            peer.peer.endpoint.is_none(),
            "the peer learns the guest's endpoint from the initiation's source"
        );
    }

    #[test]
    fn the_two_halves_agree_and_the_guest_is_the_initiator() {
        let (guest, peer) = halves(&args(), &material());
        let guest = guest.resolve().expect("resolves");
        let peer = peer.resolve().expect("resolves");
        assert_halves(&guest, &peer).expect("the halves are the right way round");
    }

    #[test]
    fn a_seed_that_made_the_guest_the_responder_is_refused() {
        // The failure this catches is silent: `drive` would wait for a datagram
        // the peer never sends first, and the lane would report a ten-second
        // timeout with no cause anywhere.
        let mut m = material();
        m.guest_device = [0xff; 32];
        m.peer_device = [0x00; 32];
        let (guest, peer) = halves(&args(), &m);
        let guest = guest.resolve().expect("resolves");
        let peer = peer.resolve().expect("resolves");
        let error = assert_halves(&guest, &peer)
            .expect_err("refuses")
            .to_string();
        assert!(error.contains("initiator"), "{error}");
    }

    #[test]
    fn the_ordering_makes_the_lower_id_first() {
        // `role_for` gives the lower `DeviceId` the initiator role, so this
        // ordering IS the decision that the guest sends message 1.
        let (low, high) = ordered_pair([9u8; 32], [1u8; 32]);
        assert_eq!(low, [1u8; 32]);
        assert_eq!(high, [9u8; 32]);
        assert_eq!(
            twinvpn_core::lab::role_for(
                twinvpn_types::DeviceId::from_array(low),
                twinvpn_types::DeviceId::from_array(high),
            ),
            twinvpn_core::lab::Role::Initiator
        );
    }
}
