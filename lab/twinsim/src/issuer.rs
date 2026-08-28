//! The **development** relay-credential issuer.
//!
//! **Authority:** ADR-0005 §11.3 (a relay verifies a `RelayCapabilityToken`
//! offline against a held issuer public-key set), ADR-0007 (the Owner is the
//! root of trust), `contracts/cddl/twinvpn/v1/signed_statements.cddl` §13 (the
//! token's field numbering).
//!
//! # Why this exists, and the gap it closes
//!
//! `infra/scripts/bootstrap-local.sh` writes an issuer key set with an **empty**
//! `issuers` array and says why: "an EMPTY key set means NO TOKEN VERIFIES,
//! which is the correct fail-closed default: a relay that admitted flows because
//! it had no issuer keys would be an open relay."
//!
//! That default is right and is not changed here. Its consequence, though, is
//! that **no leg can be established in the local environment at all** — every
//! `BIND` is refused for the same reason, so the local topology cannot exercise
//! a single one of ADR-0005's admission, quota, pairing or failover paths. A
//! development environment that cannot reach its own happy path is not a
//! reproduction of anything.
//!
//! So the empty default stays, and this type is the *explicit, separate act*
//! that populates it — `make dev-issuer`, never a side effect of bringing the
//! stack up. Three properties keep that act from becoming a production
//! credential path:
//!
//! 1. **The signing key is generated per machine from OS entropy** and lands
//!    under `infra/secrets/`, which `infra/secrets/.gitignore` covers and
//!    `build/verify/check-compose.py` asks *git itself* to confirm is
//!    unreachable. There is no committed seed and no default seed.
//! 2. **The signer is `twinvpn_crypto::testkit`, behind `test-support`** — a
//!    feature ADR-0018 CD-5 makes never-shipped. No product artifact can link
//!    it, so this issuer cannot accidentally become one.
//! 3. **The key set it writes names `operator_group_id` explicitly**, and a
//!    relay refuses a set belonging to another group. A development issuer's
//!    tokens are inert against any relay not configured for the development
//!    group.
//!
//! # What it is not
//!
//! It is not an Owner. ADR-0007 makes device pairing and the `OwnerTrustAnchor`
//! set an Owner's to create, and `bootstrap-local.sh` deliberately refuses to
//! invent one. This issuer signs *relay capability* only — the credential that
//! admits a leg — and touches neither `owner-anchors.hex` nor any device
//! identity.

use std::path::Path;

use twinvpn_crypto::emit::Item;
use twinvpn_crypto::testkit::{x25519_cose_key, FixtureIssuer};

/// The operator group the local environment uses. Must equal every relay's
/// `TWINVPN_RELAY_OPERATOR_GROUP_ID`, or the key set is refused at load.
pub const DEV_OPERATOR_GROUP: &str = "local-operator";

/// The issuer key id the development key set publishes.
pub const DEV_ISSUER_KEY_ID: &str = "local-dev-issuer";

/// The seed's exact width. 32 bytes of OS entropy, hashed into an Ed25519
/// scalar by the fixture.
pub const SEED_BYTES: usize = 32;

/// A development issuer, with a real Ed25519 signing key.
///
/// `Debug` is implemented by hand and **redacts the signer**. A derived one
/// would put the Ed25519 scalar into any `{:?}` — a log line, an `expect`
/// message, an `anyhow` chain — and a signing key that reaches a log is a
/// signing key that reaches CI output.
pub struct DevIssuer {
    identity: FixtureIssuer,
    key_id: String,
    operator_group: String,
}

// The whole point of this impl is that it does NOT include the signer, so the
// lint asking for every field is asking for the defect.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for DevIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevIssuer")
            .field("key_id", &self.key_id)
            .field("operator_group", &self.operator_group)
            .field("signing", &"<redacted>")
            .finish()
    }
}

impl DevIssuer {
    /// An issuer from a seed.
    ///
    /// The seed is the whole secret: two machines with the same seed mint
    /// interchangeable tokens, which is why [`Self::load_or_create`] generates
    /// it from OS entropy rather than deriving it from anything guessable.
    #[must_use]
    pub fn from_seed(seed: &[u8], key_id: &str, operator_group: &str) -> Self {
        Self {
            identity: FixtureIssuer::from_seed(seed),
            key_id: key_id.to_owned(),
            operator_group: operator_group.to_owned(),
        }
    }

    /// Loads the seed at `path`, generating one if it is absent.
    ///
    /// **Idempotent, and never rotates.** Overwriting an existing seed would
    /// invalidate every token the running stack is holding, which presents as
    /// relays refusing binds for no visible reason — the same trap
    /// `bootstrap-local.sh` avoids by never overwriting a key it finds.
    ///
    /// # Errors
    ///
    /// Any read, write or entropy failure, and a seed file of the wrong width:
    /// a truncated seed is a weaker key, and silently accepting one would make
    /// the strength of the credential depend on a filesystem accident.
    pub fn load_or_create(path: &Path, key_id: &str, operator_group: &str) -> anyhow::Result<Self> {
        let seed = if path.exists() {
            let seed = std::fs::read(path)?;
            anyhow::ensure!(
                seed.len() == SEED_BYTES,
                "{}: a development issuer seed must be exactly {SEED_BYTES} bytes, found {}. \
                 Delete it and re-run to generate a new one; every token minted under the old \
                 seed stops verifying.",
                path.display(),
                seed.len()
            );
            seed
        } else {
            let seed = os_entropy(SEED_BYTES)?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, &seed)?;
            set_container_readable(path)?;
            seed
        };
        Ok(Self::from_seed(&seed, key_id, operator_group))
    }

    /// The issuer key id this issuer publishes.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The operator group its tokens are audienced to.
    #[must_use]
    pub fn operator_group(&self) -> &str {
        &self.operator_group
    }

    /// The `issuer-keys.json` a relay loads, as `IssuerKeySet::parse` spells it.
    ///
    /// **Public material only.** A relay verifies; it never signs, so nothing
    /// in this document is a secret and it is written world-readable on purpose
    /// — a mode that made it unreadable would fail the relay closed at startup
    /// for a reason unrelated to its configuration.
    #[must_use]
    pub fn key_set_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"_comment\": \"DEVELOPMENT RelayCapabilityToken issuer set, written by ",
                "`twinsim issuer init`. PUBLIC material only. The signing half lives outside ",
                "the container in infra/secrets/dev-issuer/seed.bin and is never mounted into ",
                "a relay: a relay that could sign a token could admit itself.\",\n",
                "  \"operator_group_id\": \"{}\",\n",
                "  \"issuers\": [\n",
                "    {{ \"key_id\": \"{}\", \"alg\": \"Ed25519\", \"cose_key_hex\": \"{}\" }}\n",
                "  ]\n",
                "}}\n"
            ),
            self.operator_group,
            self.key_id,
            hex(&self.identity.cose_key())
        )
    }

    /// Mints a real `RelayCapabilityToken`, CDDL §13's field numbering.
    #[must_use]
    pub fn mint(&self, spec: &TokenSpec) -> Vec<u8> {
        let payload = Item::Map(vec![
            (Item::Uint(1), Item::Text(self.key_id.clone())),
            (Item::Uint(2), Item::Text(self.operator_group.clone())),
            (Item::Uint(3), Item::Bytes(spec.subject.to_vec())),
            (
                Item::Uint(4),
                Item::Bytes(x25519_cose_key(&spec.rlk_public)),
            ),
            (Item::Uint(5), Item::Uint(spec.not_before_ms)),
            (Item::Uint(6), Item::Uint(spec.not_after_ms)),
            (Item::Uint(7), Item::Uint(spec.epoch)),
            (
                Item::Uint(8),
                Item::Map(vec![
                    (Item::Uint(1), Item::Uint(u64::from(spec.max_flows))),
                    (Item::Uint(2), Item::Uint(u64::from(spec.max_kbps))),
                    (Item::Uint(3), Item::Uint(spec.max_bytes_per_hour)),
                    (Item::Uint(4), Item::Uint(u64::from(spec.max_binds_per_min))),
                ]),
            ),
            (Item::Uint(9), Item::Bytes(spec.jti.to_vec())),
            // CDDL 10 — `renewed_by_relay`. Always false from an issuer: only a
            // relay sets it, and only under the epoch-equality rule. A minted
            // token that claimed it would be asserting a renewal that never
            // happened.
            (Item::Uint(10), Item::Bool(false)),
        ]);
        self.identity.sign(&payload)
    }
}

/// Every claim a minted token carries that is not the issuer's own.
///
/// The `cnf` is derived from `rlk_public` rather than passed in: ADR-0005 §7.6
/// makes "a stolen token without `RLK` is inert" the property, and it holds only
/// if `cnf` is *always* the leg key the bearer will actually prove possession
/// of. A `confirmation_key` field here would be a way to mint a token bound to
/// somebody else's key.
#[derive(Debug, Clone)]
pub struct TokenSpec {
    /// The relay-leg static public key the token is bound to.
    pub rlk_public: [u8; 32],
    /// CDDL 3 — the per-operator per-day pseudonym. **Never a `device_id`.**
    pub subject: [u8; 16],
    /// CDDL 9 — 16 random bytes for the relay's bounded replay cache.
    pub jti: [u8; 16],
    /// CDDL 5.
    pub not_before_ms: u64,
    /// CDDL 6. ADR-0005 §11.3: a 24 h lifetime, refreshed at 50 %.
    pub not_after_ms: u64,
    /// CDDL 7 — the S-03 trust epoch at issuance.
    pub epoch: u64,
    /// CDDL 8/1.
    pub max_flows: u32,
    /// CDDL 8/2.
    pub max_kbps: u32,
    /// CDDL 8/3.
    pub max_bytes_per_hour: u64,
    /// CDDL 8/4. ADR-0006 §11.15(b) requires this to be raisable for a
    /// gateway-class device, or the ~15-peer listening ceiling stands.
    pub max_binds_per_min: u32,
}

impl TokenSpec {
    /// A token that admits `rlk_public` for the next 24 hours.
    ///
    /// `not_before` is set 60 s in the past, not at `now`: a relay and a
    /// simulator on the same host still disagree about the millisecond, and a
    /// token that is not yet valid by 3 ms fails with `TOKEN_NOT_YET_VALID`,
    /// which reads like a broken relay rather than a clock.
    #[must_use]
    pub fn admitting(
        rlk_public: [u8; 32],
        subject: [u8; 16],
        jti: [u8; 16],
        now_ms: u64,
        epoch: u64,
    ) -> Self {
        Self {
            rlk_public,
            subject,
            jti,
            not_before_ms: now_ms.saturating_sub(60_000),
            not_after_ms: now_ms + 86_400_000,
            epoch,
            max_flows: 64,
            max_kbps: 20_000,
            max_bytes_per_hour: 21_474_836_480,
            max_binds_per_min: 30,
        }
    }

    /// Raises `max_binds_per_min` to the gateway ceiling of ADR-0006 §11.15(b).
    ///
    /// A gateway fronts many peers and re-binds for each; at the device default
    /// of 30 binds/min it hits its own quota at roughly fifteen peers, which
    /// ADR-0006 names as the reason the claim must be raisable at all.
    #[must_use]
    pub const fn as_gateway(mut self, max_binds_per_min: u32) -> Self {
        self.max_binds_per_min = max_binds_per_min;
        self
    }
}

/// `n` bytes from the OS CSPRNG.
///
/// `/dev/urandom` directly rather than a crate: `lab/Cargo.toml` is the
/// integration lead's, adding a dependency to it is that domain's act, and this
/// is one read of one file on the only platform TwinLab runs on.
fn os_entropy(n: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut out = vec![0_u8; n];
    f.read_exact(&mut out)?;
    Ok(out)
}

/// `0644`, and the loosening is deliberate — see `infra/scripts/bootstrap-local.sh`.
///
/// `0600` is the right mode for a signing key and is what this was. It does not
/// work here: `infra/compose/netlab.yml` bind-mounts this seed into the
/// `twinsim` image, which is distroless `:nonroot` and runs as **uid 65532**.
/// That uid does not own this file and cannot read it at 0600 — on Docker
/// exactly as on podman — so every simulated peer died at startup.
///
/// What is being widened is a DEVELOPMENT issuer seed: generated per machine
/// from OS entropy, gitignored, verified unreachable by git, and audienced to
/// `local-operator` so its tokens are inert against any other relay fleet. The
/// cost is that another local user on this machine can read it. A real issuer
/// key would be given to the service's uid by ownership or a secret store, and
/// never by widening the mode.
fn set_container_readable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Lowercase base16, which is what the key set spells `cose_key_hex` in.
///
/// Written as a table lookup rather than `char::from_digit`, which is fallible
/// for a value it can never receive here: an `expect` on an unreachable branch
/// is still a panic path in a process that runs unattended in a container.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0F)] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> DevIssuer {
        DevIssuer::from_seed(b"a-test-seed", DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP)
    }

    #[test]
    fn the_key_set_names_the_group_and_carries_public_material_only() {
        let json = issuer().key_set_json();
        assert!(json.contains(DEV_OPERATOR_GROUP));
        assert!(json.contains(DEV_ISSUER_KEY_ID));
        assert!(json.contains("\"alg\": \"Ed25519\""));
        // A private half in a document a relay loads would be the whole
        // failure: the relay could then mint what it is supposed to verify.
        // Asserted against the actual key material, not against the word
        // "seed" — the `_comment` legitimately names the seed FILE, and a
        // substring check on the word would fail for the wrong reason while
        // still not proving the bytes are absent.
        let signing_seed_hex = hex(&twinvpn_crypto::sha256(b"a-test-seed"));
        assert!(!json.contains(&signing_seed_hex));
        assert!(!json.contains("PRIVATE KEY"));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["issuers"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn a_minted_token_is_a_cose_sign1_and_two_mints_differ_only_by_their_claims() {
        let iss = issuer();
        let spec = TokenSpec::admitting([7_u8; 32], [1_u8; 16], [2_u8; 16], 1_700_000_000_000, 1);
        let a = iss.mint(&spec);
        // UNTAGGED, and that is the contract rather than an accident:
        // `twinvpn_crypto::verify_cose_sign1` admits the untagged COSE_Sign1
        // array only, because "a second accepted spelling is a second encoding
        // of one statement". 0x84 is `array(4)`; a leading 0xD2 (tag 18) would
        // be refused by every relay in the fleet.
        assert_eq!(a[0], 0x84, "the token must be an untagged COSE_Sign1 array");
        assert_eq!(iss.mint(&spec), a, "minting is deterministic in its claims");

        let mut other = spec.clone();
        other.jti = [3_u8; 16];
        assert_ne!(iss.mint(&other), a);
    }

    #[test]
    fn the_confirmation_key_cannot_be_chosen_independently_of_the_leg_key() {
        // The property is structural: `TokenSpec` has no `confirmation_key`
        // field, so `cnf` is always derived from `rlk_public`. Two specs that
        // differ only in `rlk_public` must therefore produce different tokens.
        let iss = issuer();
        let a = TokenSpec::admitting([7_u8; 32], [1_u8; 16], [2_u8; 16], 1_700_000_000_000, 1);
        let b = TokenSpec::admitting([8_u8; 32], [1_u8; 16], [2_u8; 16], 1_700_000_000_000, 1);
        assert_ne!(iss.mint(&a), iss.mint(&b));
    }

    #[test]
    fn a_token_is_valid_before_now_so_a_millisecond_of_clock_skew_is_not_a_refusal() {
        let now = 1_700_000_000_000;
        let s = TokenSpec::admitting([7_u8; 32], [1_u8; 16], [2_u8; 16], now, 1);
        assert!(s.not_before_ms < now);
        assert_eq!(s.not_after_ms - now, 86_400_000, "ADR-0005 §11.3's 24 h");
    }

    #[test]
    fn the_gateway_claim_is_raised_and_nothing_else_moves() {
        let base = TokenSpec::admitting([7_u8; 32], [1_u8; 16], [2_u8; 16], 1, 1);
        let gw = base.clone().as_gateway(240);
        assert_eq!(gw.max_binds_per_min, 240);
        assert_eq!(gw.max_flows, base.max_flows);
        assert_eq!(gw.max_kbps, base.max_kbps);
        assert_eq!(gw.max_bytes_per_hour, base.max_bytes_per_hour);
    }

    #[test]
    fn hex_is_lowercase_and_two_characters_per_octet() {
        assert_eq!(hex(&[0x00, 0x0F, 0xA5, 0xFF]), "000fa5ff");
    }

    #[test]
    fn a_seed_of_the_wrong_width_is_refused_rather_than_silently_weakening_the_key() {
        let dir = std::env::temp_dir().join(format!("twinsim-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("seed.bin");
        std::fs::write(&path, [0_u8; 8]).expect("write");
        let err = DevIssuer::load_or_create(&path, DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP)
            .expect_err("a short seed is refused");
        assert!(err.to_string().contains("exactly 32 bytes"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn creating_a_seed_is_idempotent_and_never_rotates_it() {
        let dir = std::env::temp_dir().join(format!("twinsim-seed-idem-{}", std::process::id()));
        let path = dir.join("seed.bin");
        std::fs::remove_dir_all(&dir).ok();
        let first = DevIssuer::load_or_create(&path, DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP)
            .expect("creates");
        let again =
            DevIssuer::load_or_create(&path, DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP).expect("loads");
        assert_eq!(first.key_set_json(), again.key_set_json());
        std::fs::remove_dir_all(&dir).ok();
    }
}
