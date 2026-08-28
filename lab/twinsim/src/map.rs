//! The **development** relay map: how a simulator learns a relay's static key.
//!
//! **Authority:** ADR-0006 §11.2 (the relay map is one Owner-signed
//! COSE_Sign1/CBOR document per operator group, and a device "MUST NOT bind a
//! relay whose `relay_id` and static Noise public key are not present in a
//! VERIFIED map"), ADR-0005 §10 (endpoints are per-instance and individually
//! addressable, never a load-balanced VIP), ADR-0011 DN-0 (literal addresses,
//! never hostnames).
//!
//! # This is not a relay map, and the difference is the whole file
//!
//! A real `RelayMap` is **Owner-signed**, and that signature is the root of
//! relay trust for every device in a TwinNet: `services/relay/src/register.rs`
//! explains that a relay which could write itself into the map "could add a
//! relay of its choosing", which is the compromised-relay steering attack.
//!
//! This document has **no signature**. It is a plain JSON file the operator of
//! the local environment writes on the host, out of band, and mounts read-only
//! into the simulators. It stands in for a *key distribution*, never for a
//! *verification*: nothing here decides that a relay is trustworthy, it only
//! carries a key the operator already had on the same disk.
//!
//! Two consequences are stated rather than implied:
//!
//! 1. **A `twinsim` bind is not evidence that map verification works.** It
//!    cannot be — this simulator never verifies a map. ADR-0006's verification
//!    path is exercised by `twinvpn-relay-client`'s own tests and by nothing
//!    here.
//! 2. **The private half never leaves the host.** [`RelayEntry::from_static_key_file`]
//!    reads a relay's `static-noise.key`, derives the public half through
//!    `twinvpn-crypto`, and writes only that. Mounting a relay's private key
//!    into a client container would make the simulator able to impersonate the
//!    relay it is testing.
//!
//! The failure this file prevents is otherwise silent and expensive: a map
//! entry whose `static_noise_public_key` does not match the key the relay
//! actually loaded makes every `Noise_IK` initiation fail at the responder,
//! with the device blaming the network and the relay logging nothing — because
//! a failed handshake is deliberately indistinguishable from noise.

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use twinvpn_schema::limits::RELAY_ID_BYTES;

use crate::issuer::hex;

/// One relay instance the simulators may bind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEntry {
    /// `RELAY_ID_BYTES` as lowercase hex, matching `TWINVPN_RELAY_ID`.
    ///
    /// The width is the contract's, not a literal: `contracts/registry/limits.json`
    /// puts `relay_id_bytes` at 8, so this is **16** hex characters. Guessing
    /// 32 here — the width `pair_tag` and `jti` use — produces a map the relay
    /// refuses at startup with `RelayIdWidth`, which is where this comment
    /// came from.
    pub relay_id: String,
    /// A **literal** address and port. ADR-0011 DN-0: never a hostname, so the
    /// local environment cannot come to depend on a resolver the product
    /// forbids on this path.
    pub endpoint: String,
    /// The relay's static Noise public key, lowercase hex. Public material.
    pub static_noise_public_key_hex: String,
    /// ADR-0006 §11.1 rule 3 ranks within a region.
    pub region: String,
    /// …across at least two failure domains.
    pub failure_domain: String,
}

impl RelayEntry {
    /// Builds an entry by deriving the public half of a relay's static key.
    ///
    /// # Errors
    ///
    /// A read failure, a key file that is not exactly 32 bytes, or a scalar the
    /// curve refuses. A short key file is an error and never a zero-padded key:
    /// padding it would produce a public half no relay answers to, and the
    /// symptom is the silent-handshake failure above.
    pub fn from_static_key_file(
        relay_id: &str,
        endpoint: &str,
        region: &str,
        failure_domain: &str,
        static_key_path: &Path,
    ) -> anyhow::Result<Self> {
        let private = std::fs::read(static_key_path)?;
        anyhow::ensure!(
            private.len() == 32,
            "{}: a static Noise key is exactly 32 bytes, found {}",
            static_key_path.display(),
            private.len()
        );
        let public = twinvpn_crypto::relay_leg::static_public_key(&private)
            .map_err(|e| anyhow::anyhow!("{}: {e}", static_key_path.display()))?;
        Ok(Self {
            relay_id: relay_id.to_owned(),
            endpoint: endpoint.to_owned(),
            static_noise_public_key_hex: hex(&public),
            region: region.to_owned(),
            failure_domain: failure_domain.to_owned(),
        })
    }

    /// The endpoint as a socket address.
    ///
    /// # Errors
    ///
    /// An endpoint that is not a literal `addr:port`. A hostname is refused
    /// here rather than resolved, because DN-0 forbids one on this path and a
    /// resolver that "helpfully" worked locally would hide the violation until
    /// it reached a device.
    pub fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        self.endpoint.parse::<SocketAddr>().map_err(|_| {
            anyhow::anyhow!(
                "{}: `{}` is not a literal address:port. ADR-0011 DN-0 forbids a hostname \
                 in a relay endpoint.",
                self.relay_id,
                self.endpoint
            )
        })
    }

    /// The static public key as bytes.
    ///
    /// # Errors
    ///
    /// Hex that is not exactly 64 lowercase characters.
    pub fn static_public(&self) -> anyhow::Result<[u8; 32]> {
        unhex32(&self.static_noise_public_key_hex).ok_or_else(|| {
            anyhow::anyhow!(
                "{}: static_noise_public_key_hex must be 64 hex characters",
                self.relay_id
            )
        })
    }

    /// The `relay_id` as bytes, for the `pair_tag` derivation's scoping.
    ///
    /// # Errors
    ///
    /// Hex of any width but the contract's. Checked here rather than left to
    /// the relay: a map whose ids are the wrong width fails the *relay* at
    /// startup with `RelayIdWidth`, three components away from the file that
    /// caused it.
    pub fn relay_id_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = unhex(&self.relay_id).ok_or_else(|| {
            anyhow::anyhow!("relay_id `{}` is not lowercase base16", self.relay_id)
        })?;
        anyhow::ensure!(
            bytes.len() == RELAY_ID_BYTES,
            "relay_id `{}` is {} bytes; contracts/registry/limits.json fixes relay_id_bytes \
             at {RELAY_ID_BYTES}, so it must be {} hex characters",
            self.relay_id,
            bytes.len(),
            RELAY_ID_BYTES * 2
        );
        Ok(bytes)
    }
}

/// The development fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevRelayMap {
    /// Loud, and first in the serialized form.
    #[serde(rename = "_comment")]
    pub comment: String,
    /// Which operator group these relays and the issuer both belong to.
    pub operator_group_id: String,
    /// The instances.
    pub relays: Vec<RelayEntry>,
}

impl DevRelayMap {
    /// A map over `relays`.
    #[must_use]
    pub fn new(operator_group_id: &str, relays: Vec<RelayEntry>) -> Self {
        Self {
            comment: "DEVELOPMENT relay map, written by `twinsim map init`. UNSIGNED: it \
                      stands in for key distribution, NOT for the Owner-signed RelayMap of \
                      ADR-0006 §11.2. A twinsim bind is therefore not evidence that map \
                      verification works. Public material only."
                .to_owned(),
            operator_group_id: operator_group_id.to_owned(),
            relays,
        }
    }

    /// Loads a map.
    ///
    /// # Errors
    ///
    /// A read or parse failure, or a fleet below ADR-0006 §11.1 rule 3's floor.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let map: Self =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        map.check_fleet_floor()?;
        Ok(map)
    }

    /// Writes the map, creating its directory.
    ///
    /// # Errors
    ///
    /// A write failure, or a fleet that does not meet the floor — refused here
    /// rather than at load, so the mistake is caught by the person making it.
    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        self.check_fleet_floor()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(self)?))?;
        Ok(())
    }

    /// The entry for `relay_id`, if the fleet has one.
    #[must_use]
    pub fn find(&self, relay_id: &str) -> Option<&RelayEntry> {
        self.relays.iter().find(|r| r.relay_id == relay_id)
    }

    /// ADR-0006 §11.1 rule 3: at least two alternates across at least two
    /// failure domains. `architecture.md` §2.12 calls a set of size one a
    /// design error, and a local environment that quietly had one would make
    /// every failover scenario `Unavailable` without saying so.
    ///
    /// # Errors
    ///
    /// A fleet below the floor, naming which half of it failed.
    pub fn check_fleet_floor(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.relays.len() >= 2,
            "ADR-0006 §11.1 rule 3: a region needs at least 2 alternates, this map has {}",
            self.relays.len()
        );
        let mut domains: Vec<&str> = self
            .relays
            .iter()
            .map(|r| r.failure_domain.as_str())
            .collect();
        domains.sort_unstable();
        domains.dedup();
        anyhow::ensure!(
            domains.len() >= 2,
            "ADR-0006 §11.1 rule 3: at least 2 failure domains, this map has {} ({})",
            domains.len(),
            domains.join(", ")
        );
        Ok(())
    }
}

/// Decodes lowercase base16 into 32 bytes.
fn unhex32(s: &str) -> Option<[u8; 32]> {
    let v = unhex(s)?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// Decodes lowercase base16.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, domain: &str) -> RelayEntry {
        RelayEntry {
            relay_id: id.to_owned(),
            endpoint: "[fd00:7717:1::20]:41641".to_owned(),
            static_noise_public_key_hex: "aa".repeat(32),
            region: "local".to_owned(),
            failure_domain: domain.to_owned(),
        }
    }

    #[test]
    fn a_fleet_of_one_is_refused_because_it_makes_every_failover_scenario_unrunnable() {
        let m = DevRelayMap::new(
            "local-operator",
            vec![entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1")],
        );
        let e = m.check_fleet_floor().expect_err("refused");
        assert!(e.to_string().contains("at least 2 alternates"));
    }

    #[test]
    fn two_relays_in_one_failure_domain_are_refused() {
        let m = DevRelayMap::new(
            "local-operator",
            vec![
                entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1"),
                entry(&"b".repeat(RELAY_ID_BYTES * 2), "d1"),
            ],
        );
        let e = m.check_fleet_floor().expect_err("refused");
        assert!(e.to_string().contains("2 failure domains"));
    }

    #[test]
    fn the_reference_fleet_meets_the_floor() {
        let m = DevRelayMap::new(
            "local-operator",
            vec![
                entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1"),
                entry(&"b".repeat(RELAY_ID_BYTES * 2), "d2"),
            ],
        );
        m.check_fleet_floor().expect("meets the floor");
        assert!(m.find(&"a".repeat(RELAY_ID_BYTES * 2)).is_some());
        assert!(m.find("nope").is_none());
    }

    #[test]
    fn a_relay_id_of_the_wrong_width_is_refused_here_and_not_by_the_relay_at_startup() {
        // The failure this prevents, observed: a 32-character id looks right
        // next to `pair_tag` and `jti`, and produces `Error: RelayIdWidth(8)`
        // from the relay with no mention of the map that caused it.
        let e = entry(&"a".repeat(32), "d1");
        let err = e.relay_id_bytes().expect_err("refused");
        assert!(err.to_string().contains("relay_id_bytes"));
        assert_eq!(
            entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1")
                .relay_id_bytes()
                .expect("correct width")
                .len(),
            RELAY_ID_BYTES
        );
    }

    #[test]
    fn a_hostname_endpoint_is_refused_rather_than_resolved() {
        let mut e = entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1");
        e.endpoint = "relay-a:41641".to_owned();
        let err = e.socket_addr().expect_err("refused");
        assert!(err.to_string().contains("DN-0"));
    }

    #[test]
    fn both_address_families_are_accepted_as_literals() {
        let mut e = entry(&"a".repeat(RELAY_ID_BYTES * 2), "d1");
        assert!(e.socket_addr().expect("v6").is_ipv6());
        e.endpoint = "172.31.240.20:41641".to_owned();
        assert!(e.socket_addr().expect("v4").is_ipv4());
    }

    #[test]
    fn a_static_key_of_the_wrong_width_is_refused_rather_than_padded() {
        let dir = std::env::temp_dir().join(format!("twinsim-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("static-noise.key");
        std::fs::write(&p, [0_u8; 16]).expect("write");
        let err = RelayEntry::from_static_key_file("id", "127.0.0.1:1", "r", "d", &p)
            .expect_err("refused");
        assert!(err.to_string().contains("exactly 32 bytes"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_the_public_half_is_ever_written() {
        let dir = std::env::temp_dir().join(format!("twinsim-map-pub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("static-noise.key");
        let private = [0x51_u8; 32];
        std::fs::write(&p, private).expect("write");
        let e = RelayEntry::from_static_key_file(
            &"a".repeat(RELAY_ID_BYTES * 2),
            "127.0.0.1:41641",
            "r",
            "d",
            &p,
        )
        .expect("entry");
        assert_ne!(e.static_noise_public_key_hex, hex(&private));
        assert_eq!(e.static_public().expect("32 bytes").len(), 32);
        // The serialized form must not be able to carry the private half.
        let json = serde_json::to_string(&e).expect("json");
        assert!(!json.contains(&hex(&private)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
