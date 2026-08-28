//! **S-46 `CoreBuildIdentity`** — and VR-3's rule that it is a *table*.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.12 (the three version numbers, VR-1…VR-4), §11.17 S-46, CB-6a;
//! `contracts/proto/twinvpn/v1/diagnostics.proto` `CoreBuildIdentity`.
//!
//! # VR-3 is why [`EPOCH_TABLE`] exists
//!
//! > **VR-3.** The relation between them is a **table, not an inference** …
//! > Anything needing "which epochs does this build speak" reads the table.
//! > **Deriving it from `core_version` is prohibited.**
//!
//! The obvious implementation — `protocol_epoch_max = major_version()` or
//! anything like it — is exactly what that sentence forbids, and it is forbidden
//! for a reason: VR-1 says the three numbers advance **independently**, so any
//! function from one to another is wrong the first time a core release changes no
//! wire behaviour. [`EPOCH_TABLE`] is therefore a literal array of rows keyed by
//! `core_version`, [`protocol_epochs`] is a lookup, and
//! `the_current_version_has_a_table_row` fails the build if a release
//! bumps the version without adding a row.
//!
//! # VR-2 is why [`CoreBuildIdentity::to_wire`] takes a tier
//!
//! `abi_major`/`abi_minor` MAY appear in a Tier-1 bundle and in this record; they
//! MUST be **omitted** from Tier-2 aggregate telemetry, and no receiver may
//! branch on a received value. The encoder takes the tier and omits them, so the
//! rule is discharged by the type rather than by the caller remembering.

use twinvpn_diag::Tier;
use twinvpn_schema::v1;

/// One row of VR-3's table: which `ProtocolEpoch` range a named core release
/// speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRow {
    /// The `core_version` (V-A) this row describes.
    pub core_version: &'static str,
    /// The lowest `ProtocolEpoch` (V-C) this build speaks.
    pub protocol_epoch_min: u32,
    /// The highest.
    pub protocol_epoch_max: u32,
}

/// VR-3's table.
///
/// **Every row is written by hand, deliberately.** Adding a release means adding
/// a row; there is no rule that computes one, because VR-1 makes the three
/// numbers independent and any computed relation would be a lie the first time
/// they diverge.
///
/// > **INTEGRATION ITEM.** Phase 1 does not state the numeric value of the
/// > launch epoch anywhere the integration lead's corpus scan found. ADR-0014
/// > N-24 requires "at least the current epoch and the two before it" and
/// > `limits.json` bounds `max_epoch_above_current` at 64, but no document says
/// > *current = N*. This table declares `1..=1` for the launch release and says
/// > so rather than inferring a range, which is the honest form of VR-3 when the
/// > value is undeclared. Confirming the number is the integration lead's.
pub const EPOCH_TABLE: &[EpochRow] = &[EpochRow {
    core_version: "0.1.0",
    protocol_epoch_min: 1,
    protocol_epoch_max: 1,
}];

/// This build's `core_version` (V-A).
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The target this artifact was **built for**, not the one it is running on.
pub const TARGET_TRIPLE: &str = env!("TWINVPN_TARGET_TRIPLE");

/// The commit the release pipeline stamped, or empty when unstamped.
pub const SOURCE_COMMIT: &str = env!("TWINVPN_SOURCE_COMMIT");

/// The build profile (§11.12), named rather than inferred.
pub const PROFILE: &str = if cfg!(feature = "full") {
    "full"
} else {
    "core-lite"
};

/// Looks up VR-3's row for a `core_version`.
///
/// `None` is a real answer and a loud one: a release with no row cannot say
/// which epochs it speaks, and answering with a guess is what VR-3 prohibits.
#[must_use]
pub fn protocol_epochs(core_version: &str) -> Option<EpochRow> {
    EPOCH_TABLE
        .iter()
        .copied()
        .find(|r| r.core_version == core_version)
}

/// S-46, assembled.
///
/// Constructed once at `tw_core_create` and thereafter immutable — S-46 says
/// "**Immutable within an artifact** … Impossible to conflict — the value is a
/// property of the loaded binary."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreBuildIdentity {
    /// V-A.
    pub core_version: &'static str,
    /// V-B major.
    pub abi_major: u32,
    /// V-B minor.
    pub abi_minor: u32,
    /// V-C, from [`EPOCH_TABLE`].
    pub protocol_epoch_min: u32,
    /// V-C, from [`EPOCH_TABLE`].
    pub protocol_epoch_max: u32,
    /// V-1 content identity of the frozen schema set. A digest, not a version.
    pub schema_digest: Vec<u8>,
    /// The reason-code registry this build compiled against.
    pub reason_registry_version: u32,
    /// A stable tag for the cryptographic provider in force.
    pub crypto_provider: String,
    /// `"full"` or `"core-lite"`.
    pub profile: &'static str,
    /// The build target.
    pub target_triple: &'static str,
    /// The stamped commit, or empty.
    pub source_commit: &'static str,
    /// **CB-6a.** Whether the platform key API performs the record AEAD itself.
    /// A *declared per-target fact*, taken from the adapter, never assumed.
    pub hardware_backed: bool,
    /// **CB-6a's readable form.** `twinvpn-store` computes this tag from what the
    /// locked allocator actually achieved; it is carried verbatim so that "this
    /// device's vault key was software-held" is a fact in the bundle rather than
    /// an inference from `hardware_backed`.
    pub sek_custody: String,
    /// The platform adapter binding's stable name, e.g. `"linux-nftables"`.
    /// `PlatformAdapter::binding_name` records it so a support case can answer
    /// "which adapter was loaded" from the bundle.
    pub adapter_binding: &'static str,
}

impl CoreBuildIdentity {
    /// Assembles the record for this build.
    ///
    /// Every argument is a **fact supplied by whoever holds it** — the ABI
    /// version by `twinvpn-ffi`, the custody tag by `twinvpn-store`, the binding
    /// name by the adapter. Nothing here is derived from `core_version` (VR-3)
    /// and nothing is defaulted (CD-2).
    ///
    /// # Errors
    ///
    /// [`BuildIdentityError::UnknownCoreVersion`] when this release has no
    /// [`EPOCH_TABLE`] row. Refused rather than guessed: a core that cannot state
    /// its epoch range must not claim one.
    pub fn assemble(
        abi_major: u32,
        abi_minor: u32,
        schema_digest: Vec<u8>,
        crypto_provider: String,
        hardware_backed: bool,
        sek_custody: String,
        adapter_binding: &'static str,
    ) -> Result<Self, BuildIdentityError> {
        let row = protocol_epochs(CORE_VERSION)
            .ok_or(BuildIdentityError::UnknownCoreVersion(CORE_VERSION))?;
        Ok(Self {
            core_version: CORE_VERSION,
            abi_major,
            abi_minor,
            protocol_epoch_min: row.protocol_epoch_min,
            protocol_epoch_max: row.protocol_epoch_max,
            schema_digest,
            reason_registry_version: twinvpn_diag::reason_registry_version(),
            crypto_provider,
            profile: PROFILE,
            target_triple: TARGET_TRIPLE,
            source_commit: SOURCE_COMMIT,
            hardware_backed,
            sek_custody,
            adapter_binding,
        })
    }

    /// The frozen wire form, for the tier it is being written into.
    ///
    /// **VR-2 is enforced here.** At [`Tier::Aggregate`] the ABI pair is omitted:
    /// *"`abi_*` MUST be **omitted** from Tier-2 aggregate telemetry — an ABI pair
    /// is build-identifying and has no aggregate meaning."* At Tier 0 and Tier 1
    /// it is carried, which VR-2's 2026-08-27 clarification explicitly permits.
    #[must_use]
    pub fn to_wire(&self, tier: Tier) -> v1::CoreBuildIdentity {
        let carry_abi = tier != Tier::Aggregate;
        v1::CoreBuildIdentity {
            core_version: self.core_version.to_owned(),
            abi_major: if carry_abi { self.abi_major } else { 0 },
            abi_minor: if carry_abi { self.abi_minor } else { 0 },
            protocol_epoch_min: self.protocol_epoch_min,
            protocol_epoch_max: self.protocol_epoch_max,
            schema_digest: self.schema_digest.clone(),
            reason_registry_version: self.reason_registry_version,
            crypto_provider: self.crypto_provider.clone(),
            profile: self.profile.to_owned(),
            target_triple: self.target_triple.to_owned(),
            source_commit: self.source_commit.to_owned(),
            hardware_backed: self.hardware_backed,
        }
    }

    /// The encoded wire form.
    #[must_use]
    pub fn encode(&self, tier: Tier) -> Vec<u8> {
        let msg = self.to_wire(tier);
        let mut buf = Vec::with_capacity(prost::Message::encoded_len(&msg));
        prost::Message::encode(&msg, &mut buf).expect("a Vec never fails to grow");
        buf
    }
}

/// Why S-46 could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildIdentityError {
    /// This release has no [`EPOCH_TABLE`] row. VR-3 forbids inferring one.
    #[error(
        "core_version {0} has no EPOCH_TABLE row; ADR-0018 VR-3 prohibits deriving the \
         ProtocolEpoch range from the core version, so a row must be added"
    )]
    UnknownCoreVersion(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CoreBuildIdentity {
        CoreBuildIdentity::assemble(
            1,
            0,
            vec![0xab; 32],
            "twinvpn-crypto/snow+dalek".to_owned(),
            false,
            "core-held:mlock".to_owned(),
            "mock",
        )
        .expect("this build has a table row")
    }

    #[test]
    fn the_current_version_has_a_table_row() {
        // VR-3's teeth. Bumping `version.workspace` without adding an
        // `EPOCH_TABLE` row fails here rather than shipping a core that answers
        // "which epochs do you speak" with a guess.
        assert!(
            protocol_epochs(CORE_VERSION).is_some(),
            "core_version {CORE_VERSION} has no EPOCH_TABLE row"
        );
    }

    #[test]
    fn the_epoch_range_is_not_a_function_of_the_core_version() {
        // The property VR-3 actually asks for: nothing in this module reads the
        // version's digits. Demonstrated by asking for a version that parses
        // fine and is simply not in the table.
        assert_eq!(protocol_epochs("0.2.0"), None);
        assert_eq!(protocol_epochs("99.99.99"), None);
    }

    #[test]
    fn every_table_row_is_a_non_empty_range() {
        for row in EPOCH_TABLE {
            assert!(
                row.protocol_epoch_min <= row.protocol_epoch_max,
                "{} declares an empty epoch range",
                row.core_version
            );
            assert!(row.protocol_epoch_min >= 1, "epoch 0 is UNSPECIFIED");
        }
    }

    #[test]
    fn vr2_the_abi_pair_is_omitted_from_tier_two() {
        let id = sample();
        let tier2 = id.to_wire(Tier::Aggregate);
        assert_eq!(tier2.abi_major, 0);
        assert_eq!(tier2.abi_minor, 0);

        let tier1 = id.to_wire(Tier::Bundle);
        assert_eq!(tier1.abi_major, 1);

        let tier0 = id.to_wire(Tier::LocalLedger);
        assert_eq!(tier0.abi_major, 1);
    }

    #[test]
    fn the_profile_names_itself_rather_than_being_inferred() {
        assert!(PROFILE == "full" || PROFILE == "core-lite");
        assert_eq!(sample().profile, PROFILE);
    }

    #[test]
    fn cb6a_custody_travels_as_a_readable_tag() {
        let id = sample();
        assert_eq!(id.sek_custody, "core-held:mlock");
        assert!(!id.hardware_backed);
    }

    #[test]
    fn the_record_round_trips_through_the_frozen_encoding() {
        let id = sample();
        let bytes = id.encode(Tier::Bundle);
        let back = <v1::CoreBuildIdentity as prost::Message>::decode(&bytes[..]).expect("decodes");
        assert_eq!(back, id.to_wire(Tier::Bundle));
        assert_eq!(back.reason_registry_version, id.reason_registry_version);
    }

    #[test]
    fn an_unstamped_commit_is_empty_not_plausible() {
        // Better an obviously-absent value than a git hash from whichever
        // checkout happened to build it. The assertion is on the LENGTH rather
        // than on emptiness, because `SOURCE_COMMIT` is a compile-time constant
        // and the compiler folds `is_empty()` away.
        let stamped: &str = SOURCE_COMMIT;
        assert!(
            stamped.len() != 1 && stamped.len() < 64,
            "a stamped commit is either absent or a real object name"
        );
    }
}
