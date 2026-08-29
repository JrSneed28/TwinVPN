//! **§11.6 step (5c) — install the pairing enrolment record.** Finding **F-2A**.
//!
//! **Authority:** [ADR-0007](../../../../../docs/adr/ADR-0007-device-identity-and-pairing.md)
//! §7.4 (C-D's "always required" authorization), §7.5 (the `OwnerTrustAnchor`,
//! "pinned by every device at enrolment and verified offline thereafter");
//! [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 (the start ordering), §11.9 (`StateDirectory=twinvpn`, mode 0700);
//! ADR-0018 CB-1, CB-2, CB-7, §11.16 (l).
//!
//! # What was missing
//!
//! `twinvpn_core::Core::install_pairing_enrolment` had **no production caller**,
//! so every shipped composition reached `pair.begin` with no enrolment record
//! and refused. The C-B ceremony `twinvpn_core::pairing` implements could be
//! driven by a test and by nothing else — which is finding F-2 exactly, one
//! level up from the one `twinvpn-core` records: the parts existed and the
//! composition root did not call them. This module is that call.
//!
//! It is the same shape as `runtime::open_vault_at_startup`, and for the same
//! reason: a capability that exists on a type and is never invoked by `main` is
//! a capability the product does not have.
//!
//! # CB-1 and CB-2: what is here, and what deliberately is not
//!
//! Everything in this file is **path resolution and file reading**. There is no
//! parsing, no verification, no branch on a TwinVPN domain fact — the octets go
//! straight to `twinvpn_core::pairing::enrol`, which verifies them against the
//! pinned root and proves this device's key under ADR-0007 N-2. CB-1 puts that
//! logic in the core because it is identical on all ten targets; CB-7 leaves the
//! *path* here because obtaining a platform directory is the shell's job.
//!
//! That is also why this shell needs no cryptographic dependency for any of it:
//! [`OwnerMaterial`] is `Vec<u8>` and `String` all the way down.
//!
//! # The files, and why they are files
//!
//! §7.5 makes the `OwnerTrustAnchor` "pinned by every device **at enrolment**".
//! Phase 1 has no C1/C2 transport for that ceremony (W-12) and the vault holds
//! no restored anchor, so the pinning act is **provisioning**: the operator
//! places the Owner's public material in the agent's own 0700 state directory,
//! which ADR-0016 §11.9 already establishes as root-owned and
//! service-exclusive. `services/control-plane` pins its ORK set from
//! configuration in exactly the same way.
//!
//! | Path under `$STATE_DIRECTORY/owner/` | Contents |
//! |---|---|
//! | [`ORK_FILE`] | the pinned `OwnerRootKey` public half, raw dCBOR `COSE_Key` |
//! | [`ANCHOR_FILE`] | the ORK-signed `OwnerTrustAnchor`, raw COSE_Sign1 |
//! | [`DELEGATIONS_DIR`]`/*` | one ORK-signed `OwnerDelegation` each, raw COSE_Sign1 |
//!
//! **Nothing secret is here.** All three hold public verifying keys and signed
//! public statements; CB-5's private material is in the element and nowhere
//! near this directory. Raw octets rather than base16 because a directory of
//! files needs no line format to get wrong.
//!
//! **An absent directory is not an error.** It means no Owner has authorized
//! this device to enrol anyone, which `pair.begin` reports as
//! `AUTH.PAIRING_NOT_AUTHORIZED` — a different fact from the
//! `AUTH.IDENTITY_MISSING` a host with no element gets, and the two must stay
//! different.
//!
//! # What this does NOT do, stated rather than left to be discovered
//!
//! The approver set `twinvpn_core::pairing::enrol` derives is **standing**: the
//! OSKs whose ORK-signed delegation carries `ENROLL`. ADR-0007 §7.4's C-D wants
//! a signature over *this ceremony*, which arrives over C1 and has no transport
//! (W-12). The gap is the core module's to document and this module's to
//! **report**, which [`enrol_at_startup`] does on every start where a chain was
//! pinned — so an operator reads it in the journal rather than inferring it.

use std::path::{Path, PathBuf};

use twinvpn_core::pairing::enrol::OwnerMaterial;

/// The pinned `OwnerRootKey` public half, as raw dCBOR `COSE_Key` octets.
pub const ORK_FILE: &str = "ork.cose-key";

/// The ORK-signed `OwnerTrustAnchor`, as raw COSE_Sign1 octets.
pub const ANCHOR_FILE: &str = "anchor.cose";

/// One raw COSE_Sign1 `OwnerDelegation` per file.
pub const DELEGATIONS_DIR: &str = "delegations";

/// The Owner-material directory beneath the injected state directory.
pub const OWNER_DIR: &str = "owner";

/// The environment variable that supplies the offer's `rendezvous_hint`.
///
/// `pairing_offer.cddl` field 6, bounded by `pairing.max_offer_hint_bytes`. An
/// unset value is the empty string, which the schema admits (`tstr .size
/// (0..64)`): a device with no rendezvous to name says nothing rather than
/// guessing a host.
pub const RENDEZVOUS_HINT_ENV: &str = "TWINVPN_RENDEZVOUS_HINT";

/// Reads whatever Owner material this host has been provisioned with.
///
/// **Every absence is an empty value, never an error.** A host with no
/// `owner/` directory is a host nobody has enrolled yet, and refusing to start
/// over it would make a provisioning step into an outage — ADR-0023 EM-20's
/// rule, one layer up. What each absence costs is decided by the core, which
/// refuses the ceremony rather than the process.
#[must_use]
pub fn load(state_dir: &Path) -> OwnerMaterial {
    let owner = state_dir.join(OWNER_DIR);
    OwnerMaterial {
        ork_pub_cose: std::fs::read(owner.join(ORK_FILE)).unwrap_or_default(),
        anchor: std::fs::read(owner.join(ANCHOR_FILE)).unwrap_or_default(),
        delegations: read_delegations(&owner.join(DELEGATIONS_DIR)),
        rendezvous_hint: std::env::var(RENDEZVOUS_HINT_ENV).unwrap_or_default(),
    }
}

/// Every readable file in the delegation directory, in a **stable order**.
///
/// Sorted by path because `read_dir` yields whatever the filesystem does, and
/// `AnchorChain`'s delegation map is keyed on `osk_id` — so the order only
/// decides which of two delegations naming one `osk_id` wins. Leaving that to
/// directory iteration order would make the pinned power set depend on inode
/// layout, which is the kind of thing that differs between a test host and a
/// router and is found in production.
fn read_delegations(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| Some(e.ok()?.path())).collect();
    paths.sort();
    paths
        .iter()
        .filter(|p| p.is_file())
        .filter_map(|p| std::fs::read(p).ok())
        .collect()
}

/// **The call F-2A was missing.** Installs the record `pair.begin` reads.
///
/// Runs at §11.6 step (5c): after the core exists and its store is open, and
/// **before** the endpoint accepts connections, so no `pair.begin` can observe a
/// half-enrolled core.
///
/// # Why a failure is a warning and not a refusal
///
/// The opposite of `runtime::open_vault_at_startup`, deliberately. PS-18 forbids
/// starting "in a mode that cannot arm enforcement while reporting itself as
/// running" — enforcement, which is what keeps a host from leaking. Pairing is
/// not that: a host that cannot enrol a peer is a host that refuses one
/// operation, and refusing to *start* over it would turn "this router has not
/// been provisioned yet" into a device that will not boot. ADR-0023 EM-20 says
/// so in terms for this host class: invalid configuration at boot "MUST NOT fail
/// open, and MUST NOT brick the host". The core's refusal is the fail-closed
/// half; this is the not-bricked half.
///
/// Every outcome is logged with its registered code, because the alternative is
/// an operator running `twinvpn pair begin`, getting a refusal, and having
/// nothing in the journal that says why.
pub fn enrol_at_startup(core: &twinvpn_core::Core, state_dir: &Path) {
    let material = load(state_dir);
    match core.enrol_for_pairing(material) {
        Ok(report) => {
            tracing::info!(
                target: "twinvpn.pairing",
                anchor_pinned = report.anchor_pinned,
                delegations_installed = report.delegations_installed,
                delegations_rejected = report.delegations_rejected,
                approvers = report.approvers,
                owner_dir = %state_dir.join(OWNER_DIR).display(),
                "the pairing enrolment record is installed; ADR-0007 §7.4 C-B is \
                 performable on this host"
            );
            if report.approvers == 0 {
                tracing::warn!(
                    target: "twinvpn.pairing",
                    specified_code = "AUTH.PAIRING_NOT_AUTHORIZED",
                    owner_dir = %state_dir.join(OWNER_DIR).display(),
                    "no ENROLL-powered OwnerDelegation is pinned, so pair.begin will \
                     refuse AUTH.PAIRING_NOT_AUTHORIZED. This device's identity is \
                     known; what is missing is the Owner's authorization (ADR-0007 \
                     §7.4 C-D)"
                );
            } else {
                // The residual, reported rather than left in a doc comment.
                tracing::warn!(
                    target: "twinvpn.pairing",
                    specified_code = "AUTH.PAIRING_NOT_AUTHORIZED",
                    approvers = report.approvers,
                    "C-D is enforced as a STANDING authorization: an ENROLL-powered OSK \
                     is pinned, not one that approved this ceremony. ADR-0007 §7.4 wants \
                     a per-ceremony approval, which arrives over C1 and has no transport \
                     in this build (W-12)"
                );
            }
        }
        Err(diagnostic) => {
            tracing::warn!(
                target: "twinvpn.pairing",
                reason_code = diagnostic.code().as_str(),
                specified_code = "AUTH.IDENTITY_MISSING",
                "no pairing enrolment record was installed, so pair.begin will refuse. \
                 On a host binding AbsentElement this is ADR-0018 §11.16 (l)'s specified \
                 behaviour and not a defect: there is no element to name this device, and \
                 the core MUST NOT substitute a file-backed signer"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unprovisioned host yields an empty record and reads no error.
    ///
    /// The property that keeps a fresh install bootable: EM-20's "MUST NOT
    /// brick the host", asserted rather than assumed.
    #[test]
    fn an_absent_owner_directory_is_an_empty_material_set_and_not_a_failure() {
        let material = load(Path::new("/nonexistent/twinvpn-state"));
        assert!(material.ork_pub_cose.is_empty());
        assert!(material.anchor.is_empty());
        assert!(material.delegations.is_empty());
    }

    /// The delegation set is read in path order, so the pinned power set does
    /// not depend on directory iteration order.
    #[test]
    fn delegations_are_read_in_a_stable_order() {
        let dir = std::env::temp_dir().join(format!("twinvpn-owner-{}", std::process::id()));
        let delegations = dir.join(DELEGATIONS_DIR);
        std::fs::create_dir_all(&delegations).expect("creates");
        std::fs::write(delegations.join("b.cose"), [2u8]).expect("writes");
        std::fs::write(delegations.join("a.cose"), [1u8]).expect("writes");
        std::fs::write(delegations.join("c.cose"), [3u8]).expect("writes");

        assert_eq!(
            read_delegations(&delegations),
            vec![vec![1u8], vec![2u8], vec![3u8]]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
