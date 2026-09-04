//! CB-5 identity custody and CB-7 Tier-1 storage.
//!
//! **Authority:** [`twinvpn_platform::custody`], ADR-0018 CB-5, CB-6a, CB-7,
//! §11.16 (c) and (l), CD-I4, CD-2; ADR-0020 §11.3 (the two Windows rows), §11.4
//! (the custody-class table), ST-9a, ST-12d, ST-12e, §11.8 (the Windows backup
//! row), §11.9 (`%ProgramData%\TwinVPN\store\` and its ACL); ADR-0016 §11.3
//! O6/O7/O8 and §11.9 (the state-directory ACL); threat-model I4 / TM-13 / TM-14.
//!
//! # CB-5, made structurally impossible rather than documented
//!
//! > The identity key (IK), `OwnerSigningKey` and `OwnerRootKey` may **never** be
//! > held by the core. Operations are vtable calls performed **inside the
//! > element**.
//!
//! The mechanism is a property of the *types*, not of the comments:
//!
//! - [`WindowsIdentityCustody`] has **no field that can hold a private scalar**.
//!   Its whole state is a [`SigningElement`] — a trait object naming *which*
//!   element, never any bytes — and a shutdown latch.
//! - There is **no constructor that accepts key material.** There is no
//!   `from_bytes`, no `from_pfx`, no `from_file`.
//! - There is **no accessor that yields any.** Every method returns a
//!   [`Signature`] or a [`SharedSecret`], both opaque and neither a key.
//! - The `Debug` impl names the element and nothing else.
//!
//! `no_type_in_this_module_can_hold_a_private_scalar` asserts the struct's size,
//! so adding a field to hold a key fails the build rather than a review.
//!
//! # The two Windows backings, and why the difference is declared
//!
//! ADR-0020 §11.3 gives Windows two rows, and this module makes which one is in
//! force a **probe result** rather than a build-time assumption:
//!
//! | Host | Provider | Key | `custody_class` | Record AEAD |
//! |---|---|---|---|---|
//! | TPM 2.0 | Microsoft **Platform** Crypto Provider | `ECDSA_P256`, `NCRYPT_MACHINE_KEY_FLAG`, export **not** allowed, `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG` where VBS is on | `HARDWARE_ATTESTED`, or `HARDWARE_UNATTESTED` where no attestation is obtainable | **`PlatformPerformed`** |
//! | no TPM | Microsoft **Software** KSP, machine key container | as above, minus the isolation flag | `SOFTWARE_LOCAL` | `CoreHeld` |
//!
//! Machine scope is not a preference: ADR-0020 C-4 records that "the service
//! starts before any interactive logon", so a user-scope key would be
//! unavailable at exactly the moment ADR-0022 LC-4 needs it.
//!
//! # ST-9a: two probes, and the minimum wins
//!
//! The identity private half and the vault key set can genuinely differ, so
//! [`CustodyClass::minimum`] takes both and returns the lower under §11.4's
//! ordering — "so the advertised class can never overstate either". That is a
//! pure function and is tested over every combination on this host.
//!
//! # What is target-free here, and what is not
//!
//! **This host is Linux, and nothing in this crate can be linked or run on it.**
//! So the sealing is behind a [`SecretProtector`] the store takes at
//! construction (CD-2), and everything else — the class lattice, the descriptor
//! string, the store-root attributes, the atomic-write ordering, the
//! absent-versus-unavailable distinction, the shutdown behaviour, every error
//! mapping — is ordinary Rust that executes under `cargo test` here. Only
//! [`DpapiNgProtector`] and [`CngElement`] need Windows, and both are as thin as
//! the API allows.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    PlatformError, RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret,
    Signature, StoreRoot, StoreRootAttributes,
};

use crate::oserr::{self, Context, Win32Error};
use crate::shutdown::ShutdownLatch;

/// The CNG provider that fronts a TPM 2.0. ADR-0020 §11.3's first Windows row.
pub const PLATFORM_KEY_STORAGE_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// The CNG provider on a host with no TPM. §11.3's second Windows row.
pub const SOFTWARE_KEY_STORAGE_PROVIDER: &str = "Microsoft Software Key Storage Provider";

/// The machine key container the identity lives in.
///
/// **A decision recorded as one.** No container name is pinned in the corpus.
/// It is deliberately not derived from anything a user can change — a container
/// named after the install path or the machine name would be a different
/// container after a rename, and a renamed machine would silently re-enrol.
pub const IDENTITY_KEY_CONTAINER: &str = "TwinVPN.DeviceIdentity";

/// The vault directory ADR-0020 §11.9 fixes for Windows.
///
/// Documented as a constant because the installer writes the ACL on it and the
/// offline unblock tool has to find it with the service absent. It is **not**
/// discovered by this crate: ST-12e requires the path to be injected, and
/// [`WindowsSecureStore::new`] takes it. The constant is what the *shell* passes.
pub const DEFAULT_STORE_ROOT: &str = r"C:\ProgramData\TwinVPN\store";

/// `S-1-5-18` — `LocalSystem`, the only principal ADR-0020 §11.9 lets open the
/// store.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// The Tier-1 item name of ADR-0020 ST-21's anti-rollback anchor.
///
/// **Defined by `twinvpn-store`**, at `core/crates/twinvpn-store/src/anchor.rs`
/// (`ANCHOR_ITEM`), and repeated here rather than imported: `twinvpn-store`
/// pulls in `twinvpn-crypto` and with it the whole cryptographic graph, which
/// this adapter deliberately does not carry (CD-I2's purpose, and the reason
/// the identity digest here is CNG's own). The string is a *name*, not an
/// encoding, and [`WindowsIdentityCustody`]'s ST-28 guard is its only reader.
const STORE_ANCHOR_ITEM: &str = "twinvpn.store.anchor";

// ---------------------------------------------------------------------------
// The custody class lattice (ADR-0020 §11.4, ST-9a)
// ---------------------------------------------------------------------------

/// ADR-0020 §11.4's class, and its ordering.
///
/// `Ord` is derived from the declaration order, **lowest first**, so
/// [`CustodyClass::minimum`] is `Ord::min` and cannot disagree with the table.
/// Writing the comparison by hand is how the two would drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CustodyClass {
    /// No secure element and no host binding: a file that works wherever it is
    /// copied. **Not reachable on Windows** — even the software KSP binds the
    /// key to the machine — and present only so the ordering is the ADR's whole
    /// ordering rather than a Windows-shaped subset of it.
    SoftwarePortable,
    /// No secure element; the key is machine-bound by DPAPI-NG or the software
    /// KSP. ADR-0020 §11.4: "a disk image **does** clone the key".
    SoftwareLocal,
    /// A secure element, but no attestation was obtainable or its format was
    /// unrecognised. §11.4 names VBS-only Windows here.
    HardwareUnattested,
    /// A secure element, non-exportable, with a verifiable attestation.
    HardwareAttested,
}

impl CustodyClass {
    /// ST-9a: the class advertised is the **minimum** of the two probes.
    ///
    /// > S-54 records **both** probe results, and `custody_class` is the
    /// > **minimum** of the two under the §11.4 ordering, so the advertised
    /// > class can never overstate either.
    #[must_use]
    pub fn minimum(identity: Self, vault: Self) -> Self {
        if identity <= vault {
            identity
        } else {
            vault
        }
    }

    /// Whether ADR-0007's `hardware_backed` claim is true of this class.
    #[must_use]
    pub const fn hardware_backed(self) -> bool {
        matches!(self, Self::HardwareAttested | Self::HardwareUnattested)
    }

    /// The stable, non-localised tag S-54 records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftwarePortable => "SOFTWARE_PORTABLE",
            Self::SoftwareLocal => "SOFTWARE_LOCAL",
            Self::HardwareUnattested => "HARDWARE_UNATTESTED",
            Self::HardwareAttested => "HARDWARE_ATTESTED",
        }
    }
}

/// Which CNG backing a live probe found (ST-9: "a live probe of the Tier-1
/// backend — never from a stored claim").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier1Backend {
    /// The Platform Crypto Provider opened, and an attestation was obtainable.
    PlatformCryptoProvider {
        /// Whether the element produced an attestation this build recognises.
        attested: bool,
    },
    /// The software KSP: machine-bound, but a disk image clones the key.
    SoftwareKsp,
    /// Neither opened. §11.16 (l)'s case: report it, refuse, and **never**
    /// substitute a file-backed signer.
    Absent,
}

impl Tier1Backend {
    /// The class this backing justifies.
    ///
    /// [`Self::Absent`] maps to [`CustodyClass::SoftwareLocal`] and **not** to
    /// something lower, because on this platform an absent element does not mean
    /// a portable key: there is no key at all, the identity operations refuse,
    /// and the vault is still DPAPI-NG-sealed to `S-1-5-18`. Claiming
    /// `SOFTWARE_PORTABLE` would tell a peer the key had been copied off the
    /// machine, which is a different and false statement.
    #[must_use]
    pub const fn custody_class(self) -> CustodyClass {
        match self {
            Self::PlatformCryptoProvider { attested: true } => CustodyClass::HardwareAttested,
            Self::PlatformCryptoProvider { attested: false } => CustodyClass::HardwareUnattested,
            Self::SoftwareKsp | Self::Absent => CustodyClass::SoftwareLocal,
        }
    }

    /// The CNG provider name to open, or `None` where there is none.
    #[must_use]
    pub const fn provider_name(self) -> Option<&'static str> {
        match self {
            Self::PlatformCryptoProvider { .. } => Some(PLATFORM_KEY_STORAGE_PROVIDER),
            Self::SoftwareKsp => Some(SOFTWARE_KEY_STORAGE_PROVIDER),
            Self::Absent => None,
        }
    }

    /// CB-6a: whether the platform key API performs the record AEAD itself.
    ///
    /// ADR-0020 §11.3's AEAD table: **Windows with a TPM is one of the two
    /// targets in ten where mandatory platform AEAD exists**; the software KSP
    /// "offers no non-exportable symmetric AEAD worth the name", so the key is
    /// core-held and ST-12d requires that to be *declared* rather than inferred.
    #[must_use]
    pub const fn record_aead_custody(self) -> RecordAeadCustody {
        match self {
            Self::PlatformCryptoProvider { .. } => RecordAeadCustody::PlatformPerformed,
            Self::SoftwareKsp | Self::Absent => RecordAeadCustody::CoreHeld,
        }
    }
}

/// The DPAPI-NG protection descriptor a Tier-1 item is sealed to.
///
/// ADR-0020 §11.3: "SEK sealed with **DPAPI-NG** `NCryptProtectSecret` to a
/// local descriptor (`SID=S-1-5-18`) whose protector is a TPM-bound key" — and
/// on a host with no TPM, "DPAPI-NG machine descriptor without a TPM protector".
///
/// Built as a string here rather than at the call site so the two forms are one
/// reviewable function with tests, instead of two literals in a `#[cfg(windows)]`
/// block nobody on this host can read the output of.
#[must_use]
pub fn protection_descriptor(backend: Tier1Backend) -> String {
    match backend {
        // `LOCAL=` names a protector CNG resolves against the machine's own key
        // material; combined with the SID it binds the blob to this machine AND
        // to `LocalSystem`. The `AND` is not decoration: a descriptor of the SID
        // alone is unsealable by any process running as `LocalSystem` on any
        // machine that has the roaming key, which on a domain-joined host is not
        // the same set as "this machine".
        Tier1Backend::PlatformCryptoProvider { .. } => {
            format!("SID={LOCAL_SYSTEM_SID} AND LOCAL=machine")
        }
        Tier1Backend::SoftwareKsp | Tier1Backend::Absent => {
            format!("SID={LOCAL_SYSTEM_SID}")
        }
    }
}

/// The store-root attributes this platform can actually stamp.
///
/// # `backup_excluded` is `false`, and that is the honest answer
///
/// ADR-0020 §11.8's Windows row: "**No** — `%ProgramData%` is outside File
/// History and Known Folder Move scope … **None required** for File History …
/// Volume Shadow Copy and full-image backups **do** capture it".
///
/// There is no Windows mechanism to exclude a directory from VSS or from an
/// image backup, so there is no flag to stamp and nothing to re-verify at start.
/// Reporting `true` would put a property in `CoreBuildIdentity` (S-46) that no
/// mechanism enforces, and §11.7's honesty table depends on the opposite being
/// visible: "restore vault + Tier 1 together (whole-machine restore)" is
/// **detected** only by the TPM NV counter, and **not detected at all** on a
/// software-KSP host. A `true` here would hide exactly that.
#[must_use]
pub const fn store_root_attributes() -> StoreRootAttributes {
    StoreRootAttributes {
        backup_excluded: false,
        // Windows has no per-file protection class in the iOS sense. `None`
        // rather than a made-up tag; the ACL is the mechanism and it is reported
        // by `owner_only`.
        protection_class: None,
        // ADR-0020 §11.9: `SYSTEM:F`, `Administrators:F`, `Users` **denied**,
        // inheritance disabled. Written by the installer (ADR-0016 §11.9's
        // "state directory ACL: service SID + `BUILTIN\Administrators` only"),
        // which is why this is a declaration and not an action.
        owner_only: true,
    }
}

// ---------------------------------------------------------------------------
// The identity half (CB-5)
// ---------------------------------------------------------------------------

/// One coordinate of a P-256 point.
const P256_COORDINATE_BYTES: usize = 32;

/// `BCRYPT_ECCKEY_BLOB`'s fixed header: `dwMagic` then `cbKey`, both `ULONG`.
const ECC_BLOB_HEADER_BYTES: usize = 8;

/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC`, `"ECS1"` little-endian.
///
/// Repeated from `windows-sys` because this function is target-free and runs
/// its tests on a Linux host. `custody::platform`'s `const _: () = assert!(..)`
/// checks the two against each other at compile time on Windows, which is the
/// same shape `sys::win` uses for the `oserr` literals.
const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;

/// The constant 26-byte X.509 `SubjectPublicKeyInfo` header of a P-256 key.
///
/// `SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 }, BIT STRING }`,
/// with the bit string's length and its zero unused-bit count. Everything after
/// it is `0x04 || X || Y` — the uncompressed point — so the whole encoding is
/// this prefix plus 65 bytes and there is no length to compute.
///
/// **Byte assembly, not cryptography.** CD-I2 restricts a *cryptographic
/// implementation* to `twinvpn-crypto`; a fixed DER prefix is neither, and
/// ADR-0007 N-2's derivation — which is a real one — is deliberately still not
/// done here (see [`SigningElement::public_identity`]).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, // SEQUENCE, 89 bytes
    0x30, 0x13, // SEQUENCE, 19 bytes: the algorithm identifier
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID 1.2.840.10045.2.1
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
];

/// Re-encodes a CNG `BCRYPT_ECCPUBLIC_BLOB` as X.509 `SubjectPublicKeyInfo`.
///
/// # Why the element vends SPKI rather than the blob
///
/// `IdentityPublic::public_key` is documented as "the element's own encoding",
/// and `twinvpn_core::pairing::enrol::ik_pub_cose_for` can only *prove* an
/// encoding it recognises: a dCBOR `COSE_Key`, or an SPKI it hands to
/// `twinvpn_crypto::cose::es256_cose_key_from_spki`. A raw CNG blob is neither,
/// so a perfectly good TPM key could not be enrolled. Android's element already
/// vends SPKI (`TwinKeystore.identityPublic`), so this is the encoding the
/// corpus already has two readers for rather than a third one.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] where the blob is not a P-256 public
/// key of exactly the declared shape. A provider that returned something else
/// under `BCRYPT_ECCPUBLIC_BLOB` is malfunctioning, and guessing at a partial
/// point would publish an identity nobody can verify.
///
/// Public for the same reason [`protection_descriptor`] is: it is the
/// target-free half of a Windows-only operation, so it is reviewable and
/// testable on a host that has no CNG.
pub fn spki_from_ecc_public_blob(blob: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let point = blob
        .get(ECC_BLOB_HEADER_BYTES..)
        .filter(|point| point.len() == 2 * P256_COORDINATE_BYTES)
        .ok_or_else(|| oserr::unavailable("NCryptExportKey.blob_length"))?;
    // Both `ULONG`, little-endian, and both checked: the magic says the curve
    // and the direction (public, P-256), `cbKey` says the coordinate width. A
    // blob whose header disagrees with its length is not a point to publish.
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let coordinate = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if magic != ECDSA_PUBLIC_P256_MAGIC || coordinate as usize != P256_COORDINATE_BYTES {
        return Err(oserr::unavailable("NCryptExportKey.blob_magic"));
    }
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + 1 + point.len());
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.push(0x04); // uncompressed
    spki.extend_from_slice(point);
    Ok(spki)
}

/// An element that performs identity operations **inside itself**.
///
/// Every method names *which* key and returns a *result*. No method takes key
/// material and no method returns any, so an implementation cannot hand a
/// private scalar to its caller even if it wanted to — CD-I4 ("no type in the
/// workspace can carry an identity private scalar") enforced at the one boundary
/// where it would otherwise be tempting.
pub trait SigningElement: Send + Sync + std::fmt::Debug {
    /// A stable, non-localised name — `"cng-pcp"`, `"cng-software"`, `"absent"`.
    fn name(&self) -> &'static str;

    /// What a live probe found. ST-9 forbids answering from a stored claim.
    fn backend(&self) -> Tier1Backend;

    /// The public identity, if the element has one.
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] where there is no element.
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError>;

    /// Creates the identity key inside the element, if it is not already there.
    ///
    /// **Idempotent, and it is not the decision.** The element performs the
    /// syscalls; whether provisioning may happen at all is ADR-0020 ST-28's
    /// question, and [`WindowsIdentityCustody`] answers it from the Tier-1
    /// anchor before ever calling this. An element must therefore never call
    /// this from its own [`Self::public_identity`] or [`Self::sign`] — that is
    /// exactly the "path from a read to a generation" ST-28 says does not
    /// exist.
    ///
    /// An implementation MUST NOT overwrite an existing container, and MUST NOT
    /// create one on any status other than "no container of that name": every
    /// other failure can mean the identity is still there and merely
    /// unreachable, and replacing one of those is ADR-0007 §7.3's
    /// compromise-indistinguishable case.
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] where there is no element, or
    /// where the element refused to create.
    fn provision(&self) -> Result<(), PlatformError>;

    /// Signs inside the element.
    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError>;

    /// Agrees inside the element.
    ///
    /// §11.16 (c) is explicit that in-element **agree** is not required on every
    /// target. CNG's key-storage providers expose ECDH over the NIST curves and
    /// **not** X25519, so on this platform the honest answer is
    /// [`PlatformError::OsUnsupported`] — a fact the core records, and **not** a
    /// licence to fall back to a private key it does not have.
    fn agree(
        &self,
        key: IdentityKeyRef,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError>;

    /// The element's own attestation blob, if it produces one.
    fn attestation(&self) -> Option<(Vec<u8>, &'static str)>;
}

/// The element on a host where neither CNG provider opened.
///
/// Reports `hardware_backed: false` truthfully and refuses every operation with
/// `AUTH.KEY_UNAVAILABLE`. ADR-0018 §11.16 (l) forbids the alternative in terms:
/// "the core MUST NOT substitute a file-backed signer silently". A refusal the
/// core records is strictly better than a signature it cannot attribute.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentElement;

impl SigningElement for AbsentElement {
    fn name(&self) -> &'static str {
        "absent"
    }

    fn backend(&self) -> Tier1Backend {
        Tier1Backend::Absent
    }

    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        Err(no_element("NCryptOpenStorageProvider"))
    }

    fn provision(&self) -> Result<(), PlatformError> {
        // §11.16 (l) again: a host with no element gets a refusal, never a key
        // this process would then have to hold itself.
        Err(no_element("NCryptCreatePersistedKey"))
    }

    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        Err(no_element("NCryptSignHash"))
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(no_element("NCryptSecretAgreement"))
    }

    fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
        None
    }
}

/// `NTE_BAD_KEYSET` — CNG has no key container of that name — carried through
/// `oserr` so the number is evidence and the name is TwinVPN's.
fn no_element(call: &'static str) -> PlatformError {
    oserr::from_status(Win32Error(oserr::NTE_BAD_KEYSET), call, Context::Identity)
}

/// Windows identity custody.
///
/// **Holds no key material.** See the module documentation for the four
/// structural properties that make that true.
///
/// # ST-28, and why the guard lives here rather than in the element
///
/// ADR-0020 ST-28: "there is no path from 'open the store' to 'generate a key'
/// — the store-open code has no key-generation capability in scope", and
/// §11.19's A-04 records what happens if that structural claim ever weakens:
/// "MUST NOT silently mint a replacement identity would need an explicit
/// runtime check plus a proof test of its own". This type carries that check.
///
/// A bare create-on-`NTE_BAD_KEYSET` inside the element cannot distinguish a
/// first run from a re-imaged host — both present as "no container" — so it
/// would mint a replacement identity for a device that already has one, which
/// ADR-0007 §7.3 calls indistinguishable from a compromise. §11.7's ST-24
/// absence table supplies the discriminator, and it is a *store* fact rather
/// than a key fact:
///
/// | Tier-1 anchor | identity key | this type does |
/// |---|---|---|
/// | absent | absent | provisions — first run or re-enrolment |
/// | present | absent | refuses; the identity was destroyed independently |
/// | either | present | nothing; the open succeeded |
/// | unreadable | — | refuses; never create on a store you could not read |
///
/// So the decision needs the vault root, which is why this type holds one: the
/// element holds a backend discriminator and stays the syscall marshalling it
/// was written as, and the rule that governs it is ordinary Rust that runs its
/// tests on a Linux host.
///
/// **The refusal is `AUTH.KEY_UNAVAILABLE`, not `AUTH.IDENTITY_MISSING`.** The
/// seam has no [`PlatformError`] that maps to the latter — `error.rs`'s table
/// has no such arm — and inventing one would be a reason code this adapter is
/// not the owner of. ADR-0007 N-7 names both codes for this condition and the
/// core is where the choice belongs: `pairing::enrol` already turns an identity
/// it cannot prove into `AUTH.IDENTITY_MISSING`.
pub struct WindowsIdentityCustody {
    element: Arc<dyn SigningElement>,
    shutdown: ShutdownLatch,
    /// The vault root, for the ST-28 anchor read and nothing else.
    ///
    /// A path, injected (CB-7 / ST-12e) exactly as [`WindowsSecureStore`]'s is.
    /// It is the one field this type has ever grown, and it holds no secret —
    /// `no_type_in_this_module_can_hold_a_private_scalar` is updated for it
    /// deliberately rather than worked around.
    store_root: PathBuf,
}

impl std::fmt::Debug for WindowsIdentityCustody {
    /// Names the element and nothing else.
    ///
    /// A derived `Debug` would walk into whatever an element implementation
    /// holds, and `ownership.md` §6 rule 11 makes a derive that reaches a secret
    /// exactly the accident to prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsIdentityCustody")
            .field("element", &self.element.name())
            .finish_non_exhaustive()
    }
}

impl WindowsIdentityCustody {
    /// Binds an element.
    ///
    /// There is deliberately no other constructor. In particular there is no
    /// `from_bytes`, `from_pfx` or `from_file`: the type cannot be given a
    /// private key because no function accepts one.
    #[must_use]
    pub fn new(
        element: Arc<dyn SigningElement>,
        shutdown: ShutdownLatch,
        store_root: PathBuf,
    ) -> Self {
        Self {
            element,
            shutdown,
            store_root,
        }
    }

    /// The element's stable name, for `CoreBuildIdentity` (S-46).
    #[must_use]
    pub fn element_name(&self) -> &'static str {
        self.element.name()
    }

    /// The identity half of ST-9a's two probes.
    #[must_use]
    pub fn custody_class(&self) -> CustodyClass {
        self.element.backend().custody_class()
    }

    /// The ST-28 guard: provisions once, or explains why it must not.
    ///
    /// Takes the element's own refusal and returns it unchanged wherever
    /// creation is not permitted, so a caller that could not be helped is left
    /// with the OS status it started with rather than a second, vaguer one.
    /// See the type documentation for the table this implements.
    fn provision_under_st28(&self, refusal: PlatformError) -> Result<(), PlatformError> {
        // Only "the element has no key" is a provisioning question at all. A
        // shutdown, a busy TPM reported as `Transient`, an unsupported host —
        // none of those says the identity is absent, and creating on one of
        // them would replace an identity that still exists.
        if !matches!(refusal, PlatformError::IdentityKeyUnavailable(_)) {
            return Err(refusal);
        }
        // ST-24: `Err` is not `absent`. A store we could not read is the one
        // case where both branches are wrong, so neither is taken.
        if anchor_present(&self.store_root)? {
            return Err(refusal);
        }
        self.element.provision()?;
        // ADR-0015: one INFO line, because a device minting its identity is the
        // most consequential thing this adapter ever does and a support case
        // needs to be able to date it. The container and the element name, and
        // nothing drawn from the key — the public half is not logged either,
        // since `enrol` is where an identity becomes readable evidence.
        tracing::info!(
            target: "twinvpn.platform",
            container = IDENTITY_KEY_CONTAINER,
            element = self.element.name(),
            "the device had no identity key and no Tier-1 anchor, so one was created (ADR-0020 ST-28)"
        );
        Ok(())
    }
}

/// Whether ADR-0020 ST-21's anti-rollback anchor is on this host.
///
/// Deliberately **presence only**. [`WindowsSecureStore::secure_item_read`]'s
/// semantics are the ones that matter — "'Absent' is a normal first-run state
/// and not an error … absent enrols and unavailable must not" — and ST-24's
/// table asks whether the item is *there*, never what is in it. Reading it
/// properly would mean unsealing through DPAPI-NG, which would make a momentary
/// protector failure look like an absent anchor unless it were carefully
/// mapped; asking the filesystem cannot make that mistake.
///
/// # Errors
///
/// Any error that is not `NotFound`, mapped through the crate's one vocabulary
/// as a store failure. `AUTH.KEY_STORE_UNAVAILABLE` is TRANSIENT/WARN, which is
/// the honest class: an unreadable vault is a retry, not a re-enrolment.
fn anchor_present(root: &Path) -> Result<bool, PlatformError> {
    let path = root
        .join(WindowsSecureStore::TIER1_DIR)
        .join(STORE_ANCHOR_ITEM);
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(&e, "GetFileAttributesW(store.anchor)")),
    }
}

impl IdentityCustody for WindowsIdentityCustody {
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // ADR-0023 EM-22 E4: "at first boot the device generates its
            // identity". Reached lazily, and never from the ADR-0016 §11.6
            // start sequence — Microsoft's `NCryptCreatePersistedKey` page:
            // "A service must not call this function from its StartService
            // function … a deadlock can occur". This runs on the core's
            // executor, long after the SCM was told `Running`.
            match self.element.public_identity() {
                Ok(identity) => Ok(identity),
                Err(refusal) => {
                    self.provision_under_st28(refusal)?;
                    self.element.public_identity()
                }
            }
        })
    }

    fn identity_sign<'a>(
        &'a self,
        key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // The same guard, because a signature is the other caller that
            // opens the container. One rule, both doors: a device whose first
            // operation happens to be a signature must not take a different
            // path from one whose first operation is a read.
            match self.element.sign(key, message) {
                Ok(signature) => Ok(signature),
                // Only this device's own identity key has a container to
                // create. The two `Owner` keys are the `Owner`'s device's, and
                // a refusal for one of them is not a provisioning question.
                Err(refusal) if !matches!(key, IdentityKeyRef::Identity { .. }) => Err(refusal),
                Err(refusal) => {
                    self.provision_under_st28(refusal)?;
                    self.element.sign(key, message)
                }
            }
        })
    }

    fn identity_agree<'a>(
        &'a self,
        key: IdentityKeyRef,
        peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.element.agree(key, peer)
        })
    }

    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let (attestation, format) = match self.element.attestation() {
                Some((blob, tag)) => (Some(blob), Some(tag)),
                None => (None, None),
            };
            Ok(IdentityAttestation {
                hardware_backed: self.element.backend().custody_class().hardware_backed(),
                attestation,
                format,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// The store half (CB-7)
// ---------------------------------------------------------------------------

/// Seals and unseals a Tier-1 item.
///
/// A trait rather than a direct DPAPI-NG call, for the reason the module
/// documentation gives: it is the one part of the store that cannot execute on
/// the host this crate was written on, so it is the one part behind an
/// injection. Production binds [`DpapiNgProtector`]; nothing else can, because
/// [`WindowsSecureStore::new`] constructs it and the alternative constructor is
/// `#[cfg(test)]`.
pub trait SecretProtector: Send + Sync {
    /// A stable, non-localised name for S-46.
    fn name(&self) -> &'static str;

    /// Seals plaintext to this machine's `LocalSystem` descriptor.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError>;

    /// Unseals a blob this machine sealed.
    ///
    /// A blob from **another** machine fails here, which is the mechanism behind
    /// ADR-0020 §11.7's "restore vault + Tier 1 together" row: on a TPM host the
    /// protector does not resolve and the unseal refuses.
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, PlatformError>;
}

/// Tier-1 secure storage and the vended vault directory.
///
/// # Whole-blob items in files, sealed by DPAPI-NG
///
/// CB-7 describes the shape: "whole-blob atomic replacement, which is the shape
/// Keychain / Keystore / DPAPI / libsecret actually have". ADR-0020 §11.3 says
/// where the protection comes from — `NCryptProtectSecret` to a local descriptor
/// — and §11.3's "ANCH stored **beside** it" says where the ciphertext lives.
///
/// So an item is a file under `<store_root>\tier1\<name>` whose contents are the
/// DPAPI-NG blob. The confidentiality is the seal's; the ACL of §11.9 is
/// defence in depth on top of it, not instead of it.
///
/// # What the atomic replacement costs, stated
///
/// `std::fs::rename` on Windows is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`,
/// which is atomic **within a volume** — and the store root is one directory, so
/// the temp file and its target are always on the same volume by construction.
/// The `sync_all` before the rename is `FlushFileBuffers`, which is ADR-0020
/// §11.5's "explicit durability barrier". What neither gives is a barrier on the
/// *directory entry*: Windows has no `fsync(dirfd)`, so a power loss between the
/// rename and the metadata flush can leave the previous item in place. That is a
/// **rollback of one item**, which ADR-0020 L4/L5 already classify and the anchor
/// already detects; it is not a torn item, which is the failure the atomicity is
/// there to prevent.
pub struct WindowsSecureStore {
    root: PathBuf,
    protector: Arc<dyn SecretProtector>,
    backend: Tier1Backend,
    shutdown: ShutdownLatch,
}

impl std::fmt::Debug for WindowsSecureStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsSecureStore")
            .field("protector", &self.protector.name())
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl WindowsSecureStore {
    /// The subdirectory Tier-1 items live in, beneath the vended root.
    ///
    /// Separate from the Tier-2 vault the core writes so that an ACL audit has
    /// one directory to look at, and so an operator can see at a glance which
    /// files are the sealed ones.
    pub const TIER1_DIR: &'static str = "tier1";

    /// Binds the store to a vault directory.
    ///
    /// The path is **injected at construction, never discovered** — ST-12e in
    /// terms: "the core MUST receive `store_root` as an injected value whose
    /// platform attributes are already applied, and MUST NOT derive, probe for,
    /// or fall back to a path of its own choosing". [`DEFAULT_STORE_ROOT`] is
    /// what the *shell* passes; this constructor does not reach for it.
    #[must_use]
    pub fn new(root: PathBuf, backend: Tier1Backend, shutdown: ShutdownLatch) -> Self {
        Self {
            root,
            protector: Arc::new(DpapiNgProtector::new(backend)),
            backend,
            shutdown,
        }
    }

    /// Binds a store with an explicit protector.
    ///
    /// `#[cfg(test)]` and nothing else. A production build has no path to a
    /// protector that does not seal, which is what keeps "the SEK was written in
    /// the clear" out of the set of things that can happen by accident.
    #[cfg(test)]
    #[must_use]
    pub fn with_protector(
        root: PathBuf,
        backend: Tier1Backend,
        protector: Arc<dyn SecretProtector>,
        shutdown: ShutdownLatch,
    ) -> Self {
        Self {
            root,
            protector,
            backend,
            shutdown,
        }
    }

    /// The vault half of ST-9a's two probes.
    #[must_use]
    pub const fn custody_class(&self) -> CustodyClass {
        self.backend.custody_class()
    }

    /// The vault directory this store was constructed with.
    ///
    /// The same path [`SecureStore::store_root`] vends, without the `async` and
    /// without the side effect of creating the directory — for the shell's start
    /// sequence, which reports the configured path in a diagnostic before it has
    /// decided whether the store is usable. It is an accessor for an injected
    /// value and not a discovery: ST-12e's rule is about where the path *comes
    /// from*, and it came from the constructor.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the Tier-1 directory beneath the vended root.
    ///
    /// **It does not write the ACL.** ADR-0020 §11.9 and ADR-0016 §11.9 put the
    /// state-directory ACL with the installer, and a service that rewrote its
    /// own ACL at every start would be able to widen it — which is the opposite
    /// of what an ACL an administrator audited is for.
    ///
    /// # Errors
    ///
    /// The OS error, named. A vault directory that cannot be created is a
    /// startup failure.
    pub fn prepare(&self) -> Result<(), PlatformError> {
        fs::create_dir_all(self.root.join(Self::TIER1_DIR))
            .map_err(|e| io_error(&e, "CreateDirectoryW(store_root)"))
    }

    /// Where one item's ciphertext lives.
    ///
    /// [`SecureItemKey`] already restricts the name to `[a-z0-9_.-]` and 128
    /// bytes, so no path component can escape the directory and no name can be a
    /// Windows device name such as `con` or `nul` — those contain no dot-less
    /// reserved spelling this charset can produce in isolation, and any that did
    /// would still be confined to the joined directory. The join is safe because
    /// the seam's type made it safe, not because of a second check here.
    #[must_use]
    pub fn item_path(&self, key: &SecureItemKey) -> PathBuf {
        self.root.join(Self::TIER1_DIR).join(key.as_str())
    }

    /// The temporary path one atomic write goes through.
    ///
    /// A sibling in the same directory, so the rename is within a volume. The
    /// leading dot keeps it out of an alphabetical listing of real items and the
    /// `.tmp` suffix says what it is; neither is a security property.
    #[must_use]
    pub fn temp_path(&self, key: &SecureItemKey) -> PathBuf {
        self.root
            .join(Self::TIER1_DIR)
            .join(format!(".{}.tmp", key.as_str()))
    }
}

/// One `io::Error` mapped through the crate's single vocabulary.
///
/// `raw_os_error` is a `WIN32_ERROR` on Windows and an `errno` on this host. The
/// mapping table in [`crate::oserr`] is keyed on Windows numbers, so a value
/// read on Linux lands on the `_` arm and reports
/// `AUTH.KEY_STORE_UNAVAILABLE` — which is the right answer for a store failure
/// either way, and is why the tests below assert the *code* rather than the
/// number.
fn io_error(err: &std::io::Error, call: &'static str) -> PlatformError {
    let status = Win32Error(u32::try_from(err.raw_os_error().unwrap_or(0)).unwrap_or(0));
    oserr::from_status(status, call, Context::SecureStore)
}

impl SecureStore for WindowsSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            match fs::read(self.item_path(key)) {
                // "Absent" is a normal first-run state and not an error — the
                // distinction matters because absent enrols and unavailable
                // must not.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(io_error(&e, "ReadFile(secure_item)")),
                Ok(sealed) => Ok(Some(SecureItem::new(self.protector.unseal(&sealed)?))),
            }
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // Seal FIRST. A failure here must leave the previous item exactly
            // where it was, and a temp file that has already been created is a
            // half-written state a crash could be caught in.
            let sealed = self.protector.seal(value.as_bytes())?;

            let temp = self.temp_path(key);
            let path = self.item_path(key);
            let mut file = fs::File::create(&temp)
                .map_err(|e| io_error(&e, "CreateFileW(secure_item.tmp)"))?;
            file.write_all(&sealed)
                .map_err(|e| io_error(&e, "WriteFile(secure_item.tmp)"))?;
            // ADR-0020 §11.5's explicit durability barrier — `FlushFileBuffers`
            // on Windows. Before the rename, not after: a rename that published
            // unflushed bytes is exactly the torn item this ordering prevents.
            file.sync_all()
                .map_err(|e| io_error(&e, "FlushFileBuffers(secure_item.tmp)"))?;
            drop(file);

            fs::rename(&temp, &path).map_err(|e| {
                // Leave nothing behind on failure. A stale temp file is not
                // dangerous — it is sealed — but it would accumulate.
                let _ = fs::remove_file(&temp);
                io_error(&e, "MoveFileExW(secure_item)")
            })
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            match fs::remove_file(self.item_path(key)) {
                Ok(()) => Ok(()),
                // Idempotent.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io_error(&e, "DeleteFileW(secure_item)")),
            }
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.prepare()?;
            Ok(StoreRoot {
                path: self.root.clone(),
                attributes: store_root_attributes(),
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        // CB-6a and ST-12d: declared per target, never inferred, so "this
        // device's vault key was software-held" is a readable fact in the bundle
        // rather than something a reader has to work out.
        self.backend.record_aead_custody()
    }
}

/// Whether a path looks like a prepared store root.
///
/// Used by the shell's start sequence to say "the installer did not create the
/// store" as its own condition rather than discovering it as a write failure
/// three steps later.
///
/// The ROOT, not the Tier-1 directory beneath it: ADR-0020 §11.9 puts the root
/// and its ACL with the installer (`TwinVPN.wxs`'s `StoreDirectory` creates
/// exactly that), and [`WindowsSecureStore::prepare`] creates `tier1` on the
/// service's own first use. Checking for `tier1` here refused every fresh
/// install before the service had a chance to create it.
#[must_use]
pub fn store_root_prepared(root: &Path) -> bool {
    root.is_dir()
}

// ---------------------------------------------------------------------------
// The Windows syscall shim
// ---------------------------------------------------------------------------

pub use platform::{CngElement, DpapiNgProtector};

#[cfg(windows)]
mod platform;

#[cfg(not(windows))]
mod platform {
    //! The non-Windows counterparts.
    //!
    //! They exist so the target-free layers above can be compiled and tested on
    //! the host this crate was written on. **Every one refuses.** A stub that
    //! returned plaintext from `seal` would make a passing test on this host
    //! mean nothing, and a stub that signed would be the file-backed signer
    //! §11.16 (l) forbids.

    use super::{
        no_element, IdentityKeyRef, IdentityPublic, PeerPublicKey, PlatformError, SecretProtector,
        SharedSecret, Signature, SigningElement, Tier1Backend,
    };
    use crate::oserr::{self, Context, Win32Error};

    /// The CNG-backed element, on a host that is not Windows.
    #[derive(Debug, Clone, Copy)]
    pub struct CngElement {
        backend: Tier1Backend,
    }

    impl CngElement {
        /// Binds an element to a probed backend.
        #[must_use]
        pub const fn new(backend: Tier1Backend) -> Self {
            Self { backend }
        }

        /// TEST ONLY: the same, under a caller-named container.
        ///
        /// Present here only so the API does not change shape with the target —
        /// a call that compiles for Windows must compile here. Off Windows
        /// there is still no container and every operation still refuses.
        #[cfg(any(test, feature = "test-support"))]
        #[must_use]
        pub const fn new_for_test(backend: Tier1Backend, _container: &'static str) -> Self {
            Self { backend }
        }

        /// The live probe. Off Windows there is no CNG, so there is no element.
        #[must_use]
        pub const fn probe() -> Tier1Backend {
            Tier1Backend::Absent
        }

        /// TEST ONLY: deletes the container. There is none here.
        ///
        /// # Errors
        ///
        /// Always. See [`Self::new_for_test`].
        #[cfg(any(test, feature = "test-support"))]
        pub fn delete_identity_key_for_test(&self) -> Result<(), PlatformError> {
            Err(no_element("NCryptDeleteKey"))
        }
    }

    impl SigningElement for CngElement {
        fn name(&self) -> &'static str {
            "cng-unavailable"
        }
        fn backend(&self) -> Tier1Backend {
            self.backend
        }
        fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
            Err(no_element("NCryptOpenStorageProvider"))
        }
        fn provision(&self) -> Result<(), PlatformError> {
            Err(no_element("NCryptCreatePersistedKey"))
        }
        fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
            Err(no_element("NCryptSignHash"))
        }
        fn agree(
            &self,
            _key: IdentityKeyRef,
            _peer: &PeerPublicKey,
        ) -> Result<SharedSecret, PlatformError> {
            Err(no_element("NCryptSecretAgreement"))
        }
        fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
            None
        }
    }

    /// DPAPI-NG, on a host that does not have it.
    #[derive(Debug, Clone, Copy)]
    pub struct DpapiNgProtector {
        backend: Tier1Backend,
    }

    impl DpapiNgProtector {
        /// Binds a protector to a probed backend.
        #[must_use]
        pub const fn new(backend: Tier1Backend) -> Self {
            Self { backend }
        }
    }

    impl SecretProtector for DpapiNgProtector {
        fn name(&self) -> &'static str {
            "dpapi-ng-unavailable"
        }

        fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
            let _ = self.backend;
            Err(oserr::from_status(
                Win32Error(oserr::ERROR_NOT_SUPPORTED),
                "NCryptProtectSecret",
                Context::SecureStore,
            ))
        }

        fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, PlatformError> {
            Err(oserr::from_status(
                Win32Error(oserr::ERROR_NOT_SUPPORTED),
                "NCryptUnprotectSecret",
                Context::SecureStore,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A counter rather than a clock: CD-3 bans a clock read here.
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_root() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "twinvpn-win-store-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        path
    }

    /// A protector that offers **no protection**, for testing the file layer.
    ///
    /// It exists only under `#[cfg(test)]` and is reachable only through
    /// `with_protector`, which is itself `#[cfg(test)]`. The framing is
    /// deliberate: `seal` prefixes a marker so a test can prove the store wrote
    /// the *sealed* bytes and not the plaintext, which is the one property a
    /// transparent protector can still check.
    #[derive(Debug)]
    struct MarkerProtector {
        fail_seal: bool,
    }

    const MARKER: &[u8] = b"SEALED:";

    impl SecretProtector for MarkerProtector {
        fn name(&self) -> &'static str {
            "test-marker"
        }
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
            if self.fail_seal {
                return Err(oserr::from_status(
                    Win32Error(oserr::NTE_DEVICE_NOT_READY),
                    "NCryptProtectSecret",
                    Context::SecureStore,
                ));
            }
            let mut out = MARKER.to_vec();
            out.extend_from_slice(plaintext);
            Ok(out)
        }
        fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, PlatformError> {
            sealed
                .strip_prefix(MARKER)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    oserr::from_status(
                        Win32Error(oserr::NTE_BAD_KEYSET),
                        "NCryptUnprotectSecret",
                        Context::SecureStore,
                    )
                })
        }
    }

    fn store(root: PathBuf, backend: Tier1Backend) -> WindowsSecureStore {
        WindowsSecureStore::with_protector(
            root,
            backend,
            Arc::new(MarkerProtector { fail_seal: false }),
            ShutdownLatch::new(),
        )
    }

    // -- the class lattice --------------------------------------------------

    #[test]
    fn st9a_the_advertised_class_is_the_minimum_and_can_never_overstate_either_probe() {
        use CustodyClass::{HardwareAttested, HardwareUnattested, SoftwareLocal, SoftwarePortable};
        let all = [
            SoftwarePortable,
            SoftwareLocal,
            HardwareUnattested,
            HardwareAttested,
        ];
        // Every combination, both orders: the minimum is symmetric and is never
        // higher than either input.
        for identity in all {
            for vault in all {
                let min = CustodyClass::minimum(identity, vault);
                assert_eq!(min, CustodyClass::minimum(vault, identity));
                assert!(min <= identity && min <= vault, "{identity:?} {vault:?}");
                assert!(min == identity || min == vault);
            }
        }
        // The case the rule exists for: a TPM-backed IK beside a software vault
        // key must not advertise hardware backing.
        assert_eq!(
            CustodyClass::minimum(HardwareAttested, SoftwareLocal),
            SoftwareLocal
        );
    }

    #[test]
    fn the_class_ordering_is_the_adrs_ordering() {
        // §11.4's table, top to bottom. If the enum is ever reordered, the
        // derived `Ord` changes and `minimum` starts returning the wrong answer
        // silently — which is why this is asserted rather than assumed.
        assert!(CustodyClass::HardwareAttested > CustodyClass::HardwareUnattested);
        assert!(CustodyClass::HardwareUnattested > CustodyClass::SoftwareLocal);
        assert!(CustodyClass::SoftwareLocal > CustodyClass::SoftwarePortable);
    }

    #[test]
    fn hardware_backed_is_true_of_exactly_the_two_element_classes() {
        assert!(CustodyClass::HardwareAttested.hardware_backed());
        assert!(CustodyClass::HardwareUnattested.hardware_backed());
        assert!(!CustodyClass::SoftwareLocal.hardware_backed());
        assert!(!CustodyClass::SoftwarePortable.hardware_backed());
    }

    #[test]
    fn each_backend_declares_the_class_and_the_aead_custody_adr_0020_gives_it() {
        let tpm = Tier1Backend::PlatformCryptoProvider { attested: true };
        assert_eq!(tpm.custody_class(), CustodyClass::HardwareAttested);
        assert_eq!(
            tpm.record_aead_custody(),
            RecordAeadCustody::PlatformPerformed
        );
        assert_eq!(tpm.provider_name(), Some(PLATFORM_KEY_STORAGE_PROVIDER));

        // VBS-only Windows: an element, but no attestation this build accepts.
        let vbs = Tier1Backend::PlatformCryptoProvider { attested: false };
        assert_eq!(vbs.custody_class(), CustodyClass::HardwareUnattested);
        assert_eq!(
            vbs.record_aead_custody(),
            RecordAeadCustody::PlatformPerformed
        );

        let ksp = Tier1Backend::SoftwareKsp;
        assert_eq!(ksp.custody_class(), CustodyClass::SoftwareLocal);
        assert_eq!(
            ksp.record_aead_custody(),
            RecordAeadCustody::CoreHeld,
            "the software KSP offers no non-exportable symmetric AEAD worth the name"
        );
        assert_eq!(ksp.provider_name(), Some(SOFTWARE_KEY_STORAGE_PROVIDER));

        assert_eq!(Tier1Backend::Absent.provider_name(), None);
    }

    #[test]
    fn an_absent_element_is_never_reported_as_a_portable_key() {
        // `SOFTWARE_PORTABLE` says the key is a file that works wherever it is
        // copied. On Windows with no element there is no key at all and the
        // vault is still machine-sealed, so claiming portability would be a
        // different and false statement to a peer.
        assert_eq!(
            Tier1Backend::Absent.custody_class(),
            CustodyClass::SoftwareLocal
        );
    }

    // -- the protection descriptor ------------------------------------------

    #[test]
    fn the_descriptor_names_local_system_and_binds_to_the_machine_where_it_can() {
        let tpm = protection_descriptor(Tier1Backend::PlatformCryptoProvider { attested: true });
        assert!(tpm.contains("SID=S-1-5-18"));
        assert!(
            tpm.contains("LOCAL=machine"),
            "a descriptor of the SID alone is unsealable by any LocalSystem \
             process on any machine holding the roaming key"
        );

        let ksp = protection_descriptor(Tier1Backend::SoftwareKsp);
        assert_eq!(ksp, "SID=S-1-5-18");
        assert!(!ksp.contains("LOCAL="), "no TPM protector to bind to");

        // Every form names LocalSystem, in every backend. ADR-0020 §11.9: the
        // LocalSystem service is the only opener.
        for backend in [
            Tier1Backend::PlatformCryptoProvider { attested: true },
            Tier1Backend::PlatformCryptoProvider { attested: false },
            Tier1Backend::SoftwareKsp,
            Tier1Backend::Absent,
        ] {
            assert!(protection_descriptor(backend).contains(LOCAL_SYSTEM_SID));
        }
    }

    // -- the store root ------------------------------------------------------

    #[test]
    fn the_store_root_declares_only_the_attributes_windows_actually_has() {
        let attributes = store_root_attributes();
        assert!(attributes.owner_only);
        assert_eq!(attributes.protection_class, None);
        assert!(
            !attributes.backup_excluded,
            "ADR-0020 §11.8: %ProgramData% needs no File History exclusion and \
             HAS no VSS or image-backup exclusion. Claiming one would hide \
             §11.7's 'whole-machine restore is not detected without a TPM' row"
        );
    }

    #[tokio::test]
    async fn the_vended_root_is_the_injected_path_and_never_a_discovered_one() {
        // ST-12e. A store that reached for `DEFAULT_STORE_ROOT` would be ambient
        // state, and on a machine whose installer chose another volume it would
        // be the wrong directory.
        let root = temp_root();
        let store = store(root.clone(), Tier1Backend::SoftwareKsp);
        let vended = store.store_root().await.expect("vends");
        assert_eq!(vended.path, root);
        assert_ne!(vended.path, PathBuf::from(DEFAULT_STORE_ROOT));
        assert!(store_root_prepared(&root));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unprepared_store_root_is_a_distinguishable_condition() {
        assert!(!store_root_prepared(&temp_root()));
    }

    // -- the item lifecycle --------------------------------------------------

    #[tokio::test]
    async fn a_tier_one_item_round_trips_and_absent_is_not_an_error() {
        let root = temp_root();
        let store = store(root.clone(), Tier1Backend::SoftwareKsp);
        store.prepare().expect("prepares");
        let key = SecureItemKey::new("sek.v1").expect("valid");

        // Absent is a normal first-run state: it enrols, where unavailable
        // must not.
        assert!(store.secure_item_read(&key).await.expect("reads").is_none());

        store
            .secure_item_write_atomic(&key, &SecureItem::new(vec![7u8; 32]))
            .await
            .expect("writes");
        let read = store
            .secure_item_read(&key)
            .await
            .expect("reads")
            .expect("present");
        assert_eq!(read.as_bytes(), &[7u8; 32]);

        store.secure_item_delete(&key).await.expect("deletes");
        store.secure_item_delete(&key).await.expect("idempotent");
        assert!(store.secure_item_read(&key).await.expect("reads").is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn what_reaches_the_disk_is_the_sealed_blob_and_never_the_plaintext() {
        let root = temp_root();
        let store = store(root.clone(), Tier1Backend::SoftwareKsp);
        store.prepare().expect("prepares");
        let key = SecureItemKey::new("k-bind").expect("valid");
        let secret = b"the-shared-binding-secret".to_vec();
        store
            .secure_item_write_atomic(&key, &SecureItem::new(secret.clone()))
            .await
            .expect("writes");

        let on_disk = fs::read(store.item_path(&key)).expect("exists");
        assert!(
            on_disk.starts_with(MARKER),
            "the store wrote unsealed bytes"
        );
        assert_ne!(on_disk, secret);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_seal_that_fails_leaves_the_previous_item_exactly_where_it_was() {
        // ADR-0020 ST-39/L-ladder: recovery must not lose an item it never
        // received. Sealing before the temp file is created is what makes this
        // true — a protector failure must not be able to truncate the old value.
        let root = temp_root();
        let key = SecureItemKey::new("sek.v1").expect("valid");

        let good = store(root.clone(), Tier1Backend::SoftwareKsp);
        good.prepare().expect("prepares");
        good.secure_item_write_atomic(&key, &SecureItem::new(vec![1u8; 16]))
            .await
            .expect("writes");

        let failing = WindowsSecureStore::with_protector(
            root.clone(),
            Tier1Backend::SoftwareKsp,
            Arc::new(MarkerProtector { fail_seal: true }),
            ShutdownLatch::new(),
        );
        let err = failing
            .secure_item_write_atomic(&key, &SecureItem::new(vec![2u8; 16]))
            .await
            .expect_err("the seal failed");
        // A store condition, not a missing identity — see
        // `a_dpapi_ng_failure_is_a_store_condition_and_not_a_missing_identity`.
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");

        // The old value is intact, and no temp file was left behind.
        let read = good
            .secure_item_read(&key)
            .await
            .expect("reads")
            .expect("present");
        assert_eq!(read.as_bytes(), &[1u8; 16]);
        assert!(!failing.temp_path(&key).exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_item_sealed_by_another_machine_is_refused_rather_than_returned() {
        // ADR-0020 §11.7: "restore vault + Tier 1 together" is detected on a TPM
        // host because the protector does not resolve. The store must surface
        // that as an error and never as an absent item, because absent enrols.
        let root = temp_root();
        let store = store(root.clone(), Tier1Backend::SoftwareKsp);
        store.prepare().expect("prepares");
        let key = SecureItemKey::new("anchor").expect("valid");
        fs::write(store.item_path(&key), b"a blob from somewhere else").expect("writes");

        let err = store
            .secure_item_read(&key)
            .await
            .expect_err("the unseal failed");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        assert!(
            err.os_detail().is_some(),
            "the HRESULT reaches a Tier-1 bundle whichever code it carries"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// **A defect this file found and `oserr.rs` fixed.**
    ///
    /// DPAPI-NG *is* NCrypt: `NCryptProtectSecret` and `NCryptUnprotectSecret`
    /// fail with the same `NTE_*` HRESULTs a key operation does.
    /// [`crate::oserr::from_status`] used to match those **before** it consulted
    /// [`Context`], so a Tier-1 *store* failure was reported as
    /// `AUTH.KEY_UNAVAILABLE` — the identity key is gone — rather than as
    /// `AUTH.KEY_STORE_UNAVAILABLE`, the store could not be reached, even though
    /// the caller passed `Context::SecureStore`.
    ///
    /// The two have different classes in the frozen registry:
    /// `AUTH.KEY_UNAVAILABLE` is `PERSISTENT`/`ERROR`, `AUTH.KEY_STORE_UNAVAILABLE`
    /// is `TRANSIENT`/`WARN`. So a locked or momentarily unavailable DPAPI-NG
    /// protector read to the core as a permanently missing identity, which routes
    /// ADR-0020's recovery ladder to the wrong rung: L4 ("anchor absent ⇒
    /// re-enrolment") instead of a retry.
    ///
    /// The `NTE_*` arm is context-sensitive now. What is **not** fixed and is
    /// still reported: ADR-0020 §11.12's own name for the condition,
    /// `STORE.KEYSTORE_UNAVAILABLE`, is not in
    /// `contracts/registry/reason_codes.json` at all, so `AUTH.KEY_STORE_UNAVAILABLE`
    /// is a substitution — it carries the right class and the right remediation
    /// and loses the `STORE` domain.
    #[tokio::test]
    async fn a_dpapi_ng_failure_is_a_store_condition_and_not_a_missing_identity() {
        for status in [
            oserr::NTE_BAD_KEYSET,
            oserr::NTE_NOT_FOUND,
            oserr::NTE_DEVICE_NOT_READY,
        ] {
            assert_eq!(
                oserr::from_status(
                    Win32Error(status),
                    "NCryptUnprotectSecret",
                    Context::SecureStore,
                )
                .reason_code()
                .as_str(),
                "AUTH.KEY_STORE_UNAVAILABLE",
                "{status:#x}"
            );
            // ...and the same status from a key operation is still the identity
            // condition, which is what makes the context the disambiguator
            // rather than a blanket re-mapping.
            assert_eq!(
                oserr::from_status(Win32Error(status), "NCryptSignHash", Context::Identity)
                    .reason_code()
                    .as_str(),
                "AUTH.KEY_UNAVAILABLE",
                "{status:#x}"
            );
        }
        // A non-NCrypt store failure reaches the store code too.
        assert_eq!(
            oserr::from_status(
                Win32Error(oserr::ERROR_ACCESS_DENIED),
                "CreateFileW",
                Context::SecureStore
            )
            .reason_code()
            .as_str(),
            "AUTH.KEY_STORE_UNAVAILABLE"
        );
    }

    #[tokio::test]
    async fn the_write_publishes_through_a_sibling_temp_file_in_the_same_directory() {
        // `MoveFileExW` is atomic within a volume, and a temp file in the same
        // directory is on the same volume by construction. A temp file in
        // `%TEMP%` would be a cross-volume move, which is a copy — and a copy is
        // not atomic.
        let root = temp_root();
        let store = store(root.clone(), Tier1Backend::SoftwareKsp);
        let key = SecureItemKey::new("sek.v1").expect("valid");
        assert_eq!(
            store.temp_path(&key).parent(),
            store.item_path(&key).parent()
        );
        assert!(store
            .temp_path(&key)
            .starts_with(root.join(WindowsSecureStore::TIER1_DIR)));
    }

    #[tokio::test]
    async fn the_store_refuses_new_work_after_shutdown() {
        let latch = ShutdownLatch::new();
        let store = WindowsSecureStore::with_protector(
            temp_root(),
            Tier1Backend::SoftwareKsp,
            Arc::new(MarkerProtector { fail_seal: false }),
            latch.clone(),
        );
        latch.begin();
        let key = SecureItemKey::new("sek.v1").expect("valid");
        for outcome in [
            store.secure_item_read(&key).await.err(),
            store.secure_item_delete(&key).await.err(),
            store.store_root().await.err(),
        ] {
            assert!(matches!(outcome, Some(PlatformError::ShuttingDown)));
        }
    }

    #[test]
    fn the_aead_custody_is_declared_from_the_probe_and_not_from_the_build() {
        let root = temp_root();
        assert_eq!(
            store(
                root.clone(),
                Tier1Backend::PlatformCryptoProvider { attested: true }
            )
            .record_aead_custody(),
            RecordAeadCustody::PlatformPerformed
        );
        assert_eq!(
            store(root, Tier1Backend::SoftwareKsp).record_aead_custody(),
            RecordAeadCustody::CoreHeld
        );
    }

    // -- the identity half ---------------------------------------------------

    #[test]
    fn no_type_in_this_module_can_hold_a_private_scalar() {
        // CD-I4, asserted rather than asserted-in-prose. `WindowsIdentityCustody`
        // is one `Arc<dyn SigningElement>`, one `ShutdownLatch` (itself an
        // `Arc`) and one `PathBuf`, and nothing else. Adding a field to hold a
        // key changes this number and fails here.
        //
        // **The `PathBuf` was added deliberately and this line with it.** It is
        // the vault root the ADR-0020 ST-28 guard reads the Tier-1 anchor from
        // — a path, injected by the shell under CB-7, holding no secret. The
        // assertion is updated rather than relaxed so that the *next* field
        // still has to be argued for here.
        assert_eq!(
            std::mem::size_of::<WindowsIdentityCustody>(),
            std::mem::size_of::<Arc<dyn SigningElement>>()
                + std::mem::size_of::<ShutdownLatch>()
                + std::mem::size_of::<PathBuf>()
        );
    }

    #[test]
    fn the_debug_impls_name_the_mechanism_and_nothing_else() {
        let custody =
            WindowsIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new(), temp_root());
        let text = format!("{custody:?}");
        assert!(text.contains("absent"));
        assert!(!text.contains("key"), "not even a field name");

        let store = store(temp_root(), Tier1Backend::SoftwareKsp);
        let text = format!("{store:?}");
        assert!(text.contains("test-marker"));
        assert!(!text.contains("secret"));
    }

    #[tokio::test]
    async fn a_host_with_no_element_reports_false_and_refuses_rather_than_substituting() {
        // §11.16 (l): "the core MUST NOT substitute a file-backed signer
        // silently". Refusing is the specified behaviour, and the attestation
        // still answers so S-46 records the truth.
        let custody =
            WindowsIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new(), temp_root());
        let attestation = custody.identity_attestation().await.expect("answers");
        assert!(!attestation.hardware_backed);
        assert_eq!(attestation.attestation, None);
        assert_eq!(attestation.format, None);

        let err = custody
            .identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"x")
            .await
            .expect_err("no element");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        // The ST-28 guard runs on the refusal — the store root above is a fresh
        // temporary directory, so there is no anchor and provisioning is
        // permitted — and the element refuses that too. The detail therefore
        // names the *last* thing that was tried, which is the honest one: on a
        // host with no element the operator's problem is that nothing can be
        // created, not that one signature failed.
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("NCryptCreatePersistedKey")
        );
        assert_eq!(custody.element_name(), "absent");
        assert_eq!(custody.custody_class(), CustodyClass::SoftwareLocal);
    }

    #[tokio::test]
    async fn in_element_agreement_is_refused_as_a_platform_fact_and_not_worked_around() {
        // §11.16 (c): in-element `agree` is not required on every target, and
        // CNG's key-storage providers offer ECDH over the NIST curves and not
        // X25519. Refusing is the fact the core records; falling back to a key
        // this process does not have is not available and must not look like it.
        let custody = WindowsIdentityCustody::new(
            Arc::new(CngElement::new(Tier1Backend::Absent)),
            ShutdownLatch::new(),
            temp_root(),
        );
        let err = custody
            .identity_agree(
                IdentityKeyRef::Identity { generation: 0 },
                &PeerPublicKey(vec![0u8; 32]),
            )
            .await
            .expect_err("no in-element agreement");
        assert!(
            err.os_detail().is_some(),
            "the detail reaches a Tier-1 bundle"
        );
    }

    #[tokio::test]
    async fn the_identity_refuses_new_work_after_shutdown() {
        let latch = ShutdownLatch::new();
        let custody =
            WindowsIdentityCustody::new(Arc::new(AbsentElement), latch.clone(), temp_root());
        latch.begin();
        match custody.public_identity().await {
            Err(PlatformError::ShuttingDown) => {}
            other => panic!("expected ShuttingDown, got {other:?}"),
        }
    }

    // -- the export encoding (ADR-0007 N-2's input) --------------------------

    /// The X and Y of one P-256 public key, and the SPKI OpenSSL 3 writes for
    /// it — `openssl ec -pubout -outform DER`, captured 2026-09-03.
    ///
    /// A **known answer from an independent tool**, which is the only kind of
    /// vector worth having for hand-assembled DER: asserting the prefix against
    /// itself would pass with every byte of it wrong.
    const VECTOR_X: [u8; 32] = [
        0x1c, 0x07, 0x89, 0xdf, 0xf4, 0x85, 0x29, 0x30, 0x16, 0x42, 0xda, 0x61, 0x97, 0xdc, 0x40,
        0xeb, 0xa4, 0xdf, 0xf0, 0x84, 0xff, 0x86, 0x9c, 0x7f, 0x76, 0xaa, 0x55, 0x84, 0x95, 0x7a,
        0xd5, 0x23,
    ];
    const VECTOR_Y: [u8; 32] = [
        0xb8, 0x42, 0xc2, 0x86, 0x88, 0xe3, 0x79, 0xc3, 0x58, 0x17, 0x37, 0xd2, 0x38, 0xf0, 0x66,
        0x61, 0x86, 0x04, 0x87, 0x14, 0x47, 0x95, 0x35, 0xa4, 0x9a, 0xbd, 0x80, 0x38, 0xc9, 0x6c,
        0xc0, 0xff,
    ];
    const VECTOR_SPKI: [u8; 91] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1c, 0x07, 0x89,
        0xdf, 0xf4, 0x85, 0x29, 0x30, 0x16, 0x42, 0xda, 0x61, 0x97, 0xdc, 0x40, 0xeb, 0xa4, 0xdf,
        0xf0, 0x84, 0xff, 0x86, 0x9c, 0x7f, 0x76, 0xaa, 0x55, 0x84, 0x95, 0x7a, 0xd5, 0x23, 0xb8,
        0x42, 0xc2, 0x86, 0x88, 0xe3, 0x79, 0xc3, 0x58, 0x17, 0x37, 0xd2, 0x38, 0xf0, 0x66, 0x61,
        0x86, 0x04, 0x87, 0x14, 0x47, 0x95, 0x35, 0xa4, 0x9a, 0xbd, 0x80, 0x38, 0xc9, 0x6c, 0xc0,
        0xff,
    ];

    fn ecc_public_blob(magic: u32, coordinate: usize) -> Vec<u8> {
        let mut blob = Vec::with_capacity(8 + 64);
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&u32::try_from(coordinate).expect("fits").to_le_bytes());
        blob.extend_from_slice(&VECTOR_X);
        blob.extend_from_slice(&VECTOR_Y);
        blob
    }

    #[test]
    fn the_exported_blob_becomes_the_spki_an_independent_tool_writes_for_it() {
        let spki = spki_from_ecc_public_blob(&ecc_public_blob(
            ECDSA_PUBLIC_P256_MAGIC,
            P256_COORDINATE_BYTES,
        ))
        .expect("a well-formed P-256 public blob");
        assert_eq!(spki, VECTOR_SPKI.to_vec());
        // Stated separately because these are the two properties
        // `twinvpn_crypto::cose::es256_cose_key_from_spki` depends on and the
        // ones a wrong constant would break silently.
        assert_eq!(spki.len(), P256_SPKI_PREFIX.len() + 1 + 64);
        assert_eq!(spki[P256_SPKI_PREFIX.len()], 0x04, "uncompressed point");
    }

    #[test]
    fn a_blob_that_is_not_a_p256_public_point_is_refused_rather_than_published() {
        // Each of the three ways a provider can disagree with itself. Publishing
        // a truncated or foreign point would put an identity on the wire that
        // no peer can verify and that nothing downstream would notice.
        for blob in [
            ecc_public_blob(ECDSA_PUBLIC_P256_MAGIC, 48), // P-384's width
            ecc_public_blob(0x3253_4345, P256_COORDINATE_BYTES), // "ECS2": P-384
            ecc_public_blob(ECDSA_PUBLIC_P256_MAGIC, P256_COORDINATE_BYTES)[..40].to_vec(),
            Vec::new(),
        ] {
            let err = spki_from_ecc_public_blob(&blob).expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        }
    }

    // -- ST-28: the one guard between a read and a generation ----------------

    /// An element with no key until it is told to make one, and a count of how
    /// often it was told.
    ///
    /// The ST-28 table is a rule about *when* [`SigningElement::provision`] is
    /// called, so the thing under test is the call itself. A real CNG element
    /// could not answer that question on this host.
    #[derive(Debug, Default)]
    struct CountingElement {
        provisions: AtomicU32,
        /// What the element says before it has a key. `None` is "no container
        /// of that name", which is the only refusal ST-28 lets act.
        refusal: Option<PlatformError>,
    }

    impl CountingElement {
        fn provisioned(&self) -> u32 {
            self.provisions.load(Ordering::Relaxed)
        }
    }

    impl SigningElement for CountingElement {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn backend(&self) -> Tier1Backend {
            Tier1Backend::SoftwareKsp
        }
        fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
            if self.provisioned() == 0 {
                return Err(self
                    .refusal
                    .clone()
                    .unwrap_or_else(|| no_element("NCryptOpenKey")));
            }
            Ok(IdentityPublic {
                device_id: twinvpn_types::DeviceId::from_array([7u8; 32]),
                identity_id: twinvpn_types::IdentityId::from_array([7u8; 32]),
                generation: 0,
                public_key: VECTOR_SPKI.to_vec(),
            })
        }
        fn provision(&self) -> Result<(), PlatformError> {
            self.provisions.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
            Err(no_element("NCryptSignHash"))
        }
        fn agree(
            &self,
            _key: IdentityKeyRef,
            _peer: &PeerPublicKey,
        ) -> Result<SharedSecret, PlatformError> {
            Err(no_element("NCryptSecretAgreement"))
        }
        fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
            None
        }
    }

    fn write_anchor(root: &Path) {
        let tier1 = root.join(WindowsSecureStore::TIER1_DIR);
        fs::create_dir_all(&tier1).expect("creates the Tier-1 directory");
        fs::write(tier1.join(STORE_ANCHOR_ITEM), b"sealed").expect("writes the anchor");
    }

    #[tokio::test]
    async fn st28_provisions_once_where_the_device_has_no_tier1_state_at_all() {
        // ADR-0020 §11.7's "ANCH absent and IK absent" row, which §1.2's
        // reading makes a *first* creation and not a replacement: a device with
        // no Tier-1 state is by definition entering enrolment (EM-22 E4, "at
        // first boot the device generates its identity").
        let element = Arc::new(CountingElement::default());
        let custody =
            WindowsIdentityCustody::new(element.clone(), ShutdownLatch::new(), temp_root());

        custody
            .public_identity()
            .await
            .expect("provisions and reads");
        assert_eq!(element.provisioned(), 1);
        // And exactly once: the second call finds a key and never reaches the
        // guard, which is what makes this safe to put on a hot path.
        custody.public_identity().await.expect("reads");
        assert_eq!(element.provisioned(), 1);
    }

    #[tokio::test]
    async fn st28_refuses_to_mint_a_replacement_where_the_anchor_outlived_the_key() {
        // §11.7's "ANCH present, IK absent" row: a restored image or a wiped
        // TPM, which ADR-0007 §7.3 says is indistinguishable from a compromise
        // if the device answers it by minting a new identity. Re-enrolment is
        // the answer, and it is the core's to start.
        let root = temp_root();
        write_anchor(&root);
        let element = Arc::new(CountingElement::default());
        let custody = WindowsIdentityCustody::new(element.clone(), ShutdownLatch::new(), root);

        let err = custody.public_identity().await.expect_err("refuses");
        assert_eq!(element.provisioned(), 0, "no replacement identity");
        // The element's own refusal, unchanged, so the OS status survives.
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert_eq!(err.os_detail().map(|d| d.call), Some("NCryptOpenKey"));
    }

    #[tokio::test]
    async fn st28_never_creates_on_a_store_it_could_not_read() {
        // The fourth row, and the one an "absent means create" reading gets
        // wrong: `Err` is not `absent`. A vault we cannot read is a retry —
        // `AUTH.KEY_STORE_UNAVAILABLE` is TRANSIENT/WARN — and not a licence to
        // decide the device is new.
        // A root the OS cannot even look at. An interior NUL is the one
        // provocation both hosts refuse identically and neither reports as
        // `NotFound` — a file where `tier1` should be does not work, because
        // Windows answers that with `ERROR_PATH_NOT_FOUND`, which Rust maps to
        // `NotFound` and this guard would then read as "no anchor". It stands
        // in for the real conditions (a denied ACL, a dead volume), which need
        // host state a unit test cannot make portably.
        let root = PathBuf::from("this\0is not a path");
        let element = Arc::new(CountingElement::default());
        let custody = WindowsIdentityCustody::new(element.clone(), ShutdownLatch::new(), root);

        let err = custody.public_identity().await.expect_err("refuses");
        assert_eq!(element.provisioned(), 0);
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
    }

    #[tokio::test]
    async fn st28_only_a_missing_key_is_a_provisioning_question() {
        // The element half of the same rule, and the one `custody::platform`
        // enforces again on the raw status: a busy TPM, a denied provider or a
        // shutdown all mean the identity may still exist. Creating on one of
        // them replaces a live identity.
        let element = Arc::new(CountingElement {
            refusal: Some(PlatformError::Transient(None)),
            ..CountingElement::default()
        });
        let custody =
            WindowsIdentityCustody::new(element.clone(), ShutdownLatch::new(), temp_root());

        let err = custody.public_identity().await.expect_err("refuses");
        assert_eq!(element.provisioned(), 0);
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_BUSY");

        // Nor is a signature by a key this device does not own. The two `Owner`
        // keys live on the `Owner`'s device, so "no such container" is the
        // truth about them and not something to fix by creating anything.
        let owner = Arc::new(CountingElement::default());
        let custody = WindowsIdentityCustody::new(owner.clone(), ShutdownLatch::new(), temp_root());
        let err = custody
            .identity_sign(IdentityKeyRef::OwnerRoot, &[0u8; 32])
            .await
            .expect_err("refuses");
        assert_eq!(owner.provisioned(), 0);
        assert_eq!(err.os_detail().map(|d| d.call), Some("NCryptSignHash"));
    }

    #[test]
    fn every_error_this_module_produces_is_a_registered_code() {
        // `ownership.md` §6 rule 12. The set is small and closed, so it is
        // enumerable rather than argued.
        for code in [
            no_element("probe").reason_code().as_str(),
            io_error(
                &std::io::Error::from_raw_os_error(
                    i32::try_from(oserr::ERROR_ACCESS_DENIED).expect("fits"),
                ),
                "probe",
            )
            .reason_code()
            .as_str(),
        ] {
            assert!(
                matches!(code, "AUTH.KEY_UNAVAILABLE" | "AUTH.KEY_STORE_UNAVAILABLE"),
                "unexpected code {code}"
            );
        }
    }
}
