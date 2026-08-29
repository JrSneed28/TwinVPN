//! CB-5 secret custody and CB-7 storage — the two places the seam inverts.
//!
//! **Authority:** ADR-0018 CB-5 (the identity authentication path), CB-6a (the
//! declared per-target AEAD fact), CB-7 (where the store splits), §11.16 (c),
//! ADR-0007 N-5, ADR-0020, threat-model I4/TM-14.
//!
//! # CB-5, made structural rather than documented
//!
//! > The identity key (IK), `OwnerSigningKey` and `OwnerRootKey` may **never** be
//! > held by the core. Operations are vtable calls performed **inside the
//! > element**. Holding one means an attacker who reads core memory can *act as*
//! > this `Device`, and the compromise **outlives the device** rather than ending
//! > at revocation (TM-14).
//!
//! The mechanism here is that **no method in [`IdentityCustody`] returns private
//! key material, and no type it mentions can hold a scalar.** A key is named by
//! [`IdentityKeyRef`], which is an enum of *which key*, not bytes; the operations
//! return a signature or a [`SharedSecret`], never a key. There is no
//! `export`, no `raw`, and no `Deref<Target = [u8]>` anywhere in this module.
//! CD-I4 says it as an invariant — "no type in the workspace can carry an
//! identity private scalar" — and this module is where the trait surface has to
//! make it true.
//!
//! # What is NOT here, deliberately
//!
//! The **L-DATA static X25519 (TK)** does not appear. CB-5 row 2 and ADR-0018
//! §11.16 (c) are explicit that TK is hardware-*wrapped* and unsealed into
//! `twinvpn-crypto`'s locked allocator, precisely because platform key APIs
//! largely do not offer X25519 ECDH — and an earlier wording that read as
//! requiring in-element `agree` would have contradicted ADR-0007 N-5.
//!
//! **Corrected 2026-08-29.** This paragraph used to end "TK reaches the core as
//! a sealed blob through [`SecureStore`]", which put the sealed TK in **Tier 1**
//! and contradicted `twinvpn-store`'s `namespace.rs`, which put it in Tier 2
//! `identity/`. Two production modules, two tiers, one key —
//! `docs/implementation/ownership.md` §11.2 **G-17**. The ruling is §11.4
//! **D-6** and `namespace.rs` was the right one:
//!
//! - the **sealed TK blob** is a **Tier-2 `identity/` record**, because ADR-0020
//!   ST-1's rule 1 admits to Tier 1 only a value never readable by the process,
//!   and N-5 requires TK to be unsealed *into* locked core memory;
//! - the **TK wrapping key** is the **Tier-1** item — which is what ST-1 already
//!   named in the words "the `TunnelStaticKey` wrapping key", and it is
//!   `twinvpn_crypto::tk::TK_WRAP_ITEM`. That one *does* come through
//!   [`SecureStore`], which is what the old sentence was half-remembering.
//!
//! So [`SecureStore`] carries TK's **wrapping key** and never TK. Generation,
//! sealing and unsealing are all `core-security`'s, in `twinvpn_crypto::tk`, and
//! **`tw_host_vtable` gains no wrap or unwrap entry** — there is no ABI change
//! here.
//!
//! The residual is stated, not argued away: **TM-14 — TK extraction from process
//! memory is undefended.** D-6 does not move it, and putting the sealed blob in
//! Tier 2 rather than Tier 1 does not move it either: the *unsealed* key was
//! always going to be in core memory, which is what B-09 buys PB-1 and PB-2
//! with.

use futures_core::future::BoxFuture;
use twinvpn_types::{DeviceId, IdentityId};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::PlatformError;

/// Which element-resident key an operation names.
///
/// An enum, not a handle carrying bytes. The core can say *which* key to use and
/// can say nothing else about it — there is no constructor that takes key
/// material and no accessor that yields any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentityKeyRef {
    /// The device identity key (IK) of the given generation.
    ///
    /// Generation is explicit because ADR-0007 rotation creates a new
    /// `DeviceIdentity` at `generation + 1` while `device_id` is unchanged, and
    /// `T_IK_OVERLAP` means two generations are live at once. "The identity key"
    /// without a generation is ambiguous exactly when it matters.
    Identity {
        /// Which generation.
        generation: u32,
    },
    /// The `OwnerSigningKey`.
    OwnerSigning,
    /// The `OwnerRootKey`.
    OwnerRoot,
}

/// A signature produced inside the element.
///
/// Opaque bytes with a redacted `Debug`. It is not secret, but it is
/// authentication material, and a `Debug` that dumps it into a log makes a
/// support bundle a replay corpus.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wraps signature bytes. Called by an adapter.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The signature bytes, for verification or transmission.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(<{} B>)", self.0.len())
    }
}

/// A shared secret produced by an element-resident agreement.
///
/// # Why the bytes can be taken at all
///
/// A shared secret has to reach a KDF, and the KDF is in `twinvpn-crypto`. What
/// this type provides is that taking them is **explicit, consuming, and
/// greppable**: [`SharedSecret::expose_for_kdf`] is the only accessor, it is
/// named for its one legitimate use, and it consumes `self` so the value cannot
/// be used twice. There is no `Clone`, no `Copy`, and no `Debug` that shows a
/// byte. The taken bytes come back inside a `Zeroizing`, so the caller's copy
/// scrubs itself too rather than the guarantee ending at this type's boundary.
///
/// The scrub is `zeroize`'s volatile write with a compiler fence, not an
/// elidable `fill(0)`. `zeroize` is memory hygiene and implements no
/// cryptography, so CD-I2 does not restrict it to `twinvpn-crypto` — see the
/// exemption and its reasoning in `core/xtask/src/checks.rs`.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Wraps agreement output. Called by an adapter.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Takes the bytes, consuming the secret.
    ///
    /// Named for its one legitimate destination so that every use of a shared
    /// secret outside a KDF is visible in a `grep`. The result is `Zeroizing`,
    /// so the scrub follows the bytes instead of stopping at this type.
    #[must_use]
    pub fn expose_for_kdf(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.0))
    }

    /// The secret's length, which is not secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedSecret(<{} B redacted>)", self.0.len())
    }
}

/// A peer's public key, as supplied to an agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPublicKey(pub Vec<u8>);

/// The public half of an element-resident identity, and its attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct IdentityPublic {
    /// The `device_id` — SHA-256 of the generation-0 identity key.
    pub device_id: DeviceId,
    /// The `identity_id` of the current generation.
    pub identity_id: IdentityId,
    /// The current generation number.
    pub generation: u32,
    /// The public key bytes, in the element's own encoding.
    pub public_key: Vec<u8>,
}

/// What the platform truthfully reports about its key custody.
///
/// ADR-0018 §11.16 (l): the capability "reports `hardware_backed` **truthfully
/// per target**, so S-46 records it rather than the core assuming it. On a target
/// with no secure element the residual is TM-13's, unchanged; **the core MUST NOT
/// substitute a file-backed signer silently.**"
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct IdentityAttestation {
    /// Whether the private half is genuinely element-resident.
    ///
    /// A `false` here is a *fact to record*, never a reason to refuse — a
    /// container, a VM and row 8/9 of the build matrix all have no element, and
    /// TwinVPN runs there with TM-13's residual stated.
    pub hardware_backed: bool,
    /// The element's own attestation blob, when it produces one.
    pub attestation: Option<Vec<u8>>,
    /// The attestation format, as a stable non-localised tag.
    pub format: Option<&'static str>,
}

/// The identity-operation vtable (CB-5).
///
/// Every method performs its work **inside the element**. None of them returns
/// private key material, and no type in this trait's signature can hold a
/// private scalar.
pub trait IdentityCustody: Send + Sync {
    /// The public identity, its generation, and its identifiers.
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>>;

    /// Signs `message` with an element-resident key.
    ///
    /// ADR-0018 §11.16 (c): `identity_sign` is "performed inside the element (IK,
    /// ES256, never exported)".
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] — a locked device, a revoked
    /// entitlement, or an element that has lost its backing. `AUTH.KEY_UNAVAILABLE`
    /// is the registered code, per ADR-0018 §11.6.
    fn identity_sign<'a>(
        &'a self,
        key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>>;

    /// Performs an element-resident key agreement.
    ///
    /// # Not required on every target
    ///
    /// ADR-0018 §11.16 (c) is explicit that in-element **agree** is *not*
    /// required — TK is hardware-wrapped rather than element-resident precisely
    /// because platform key APIs largely do not offer X25519 ECDH. An adapter
    /// that cannot do this returns [`PlatformError::OsUnsupported`], which is a
    /// fact the core records; it is **not** a licence for the core to fall back
    /// to a private key it does not have.
    fn identity_agree<'a>(
        &'a self,
        key: IdentityKeyRef,
        peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>>;

    /// The truthful hardware-backing report (§11.16 (l)).
    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>>;
}

/// A Tier-1 secure item's name.
///
/// Whole-blob, per item — CB-7's table. Not a path and not a query: the platform
/// stores (Keychain, Keystore, DPAPI, libsecret) are key-value, and pretending
/// otherwise would put a query engine on the shell's side of the line CB-7 draws.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureItemKey(String);

impl SecureItemKey {
    /// The cap. Every platform store accepts at least this.
    pub const MAX_BYTES: usize = 128;

    /// Names an item.
    ///
    /// # Errors
    ///
    /// [`PlatformError::SecureStoreUnavailable`] on an empty, over-cap or
    /// non-`[a-z0-9_.-]` name — the intersection every platform store accepts.
    pub fn new(name: &str) -> Result<Self, PlatformError> {
        let ok = !name.is_empty()
            && name.len() <= Self::MAX_BYTES
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            });
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(PlatformError::SecureStoreUnavailable(None))
        }
    }

    /// The item name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Tier-1 secure item's contents.
///
/// Redacted `Debug`, `zeroize` scrub on drop, no `Clone`. The items CB-7 puts
/// here are the SEK, `K_bind` and the S-53 anchor — every one of them a secret,
/// which is why the scrub is a volatile write rather than a store the optimiser
/// may drop.
#[derive(ZeroizeOnDrop)]
pub struct SecureItem(Vec<u8>);

impl SecureItem {
    /// Wraps item contents.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The contents.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The contents, consuming the item.
    ///
    /// `Zeroizing`, so the SEK does not outlive its use in a plain `Vec` the
    /// caller forgot about.
    #[must_use]
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.0))
    }
}

impl core::fmt::Debug for SecureItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureItem(<{} B redacted>)", self.0.len())
    }
}

/// The vault directory, vended by the shell with its platform attributes already
/// applied.
///
/// CB-7: "what genuinely has no stable C-callable form is … *obtaining* the vault
/// directory and stamping its platform attributes — on iOS the app-group
/// container URL, the file protection class, and the backup-exclusion flag are
/// Objective-C APIs."
///
/// **Ordinary file I/O beneath this path is core-side and is deliberately absent
/// from [`SecureStore`]**: "ordinary file I/O over a path that has already been
/// vended is POSIX on all ten targets, so by CB-1 it belongs in the core."
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct StoreRoot {
    /// The directory, already created with its attributes applied.
    pub path: std::path::PathBuf,
    /// The platform attributes the shell stamped on it, declared so the core can
    /// record them in S-46 rather than assume them.
    pub attributes: StoreRootAttributes,
}

/// The declared attributes of a vended [`StoreRoot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct StoreRootAttributes {
    /// Whether the directory is excluded from platform backup.
    pub backup_excluded: bool,
    /// The file-protection class, as a stable non-localised tag, where the
    /// platform has one.
    pub protection_class: Option<&'static str>,
    /// Whether the directory is readable only by this user or service account.
    pub owner_only: bool,
}

/// CB-6a: whether the platform key API performs the record AEAD itself.
///
/// > "Where the platform key API can perform the record AEAD itself, it **MUST**;
/// > where it cannot, the key is core-held and that MUST be recorded in
/// > `CoreBuildIdentity` (S-46) and surfaced in the diagnostic bundle, so 'this
/// > device's vault key was software-held' is a readable fact rather than an
/// > inference."
///
/// The honest aggregate from ADR-0020's survey: **mandatory platform AEAD exists
/// on 2 of 10 targets** — Android Keystore and Windows with a TPM. The
/// software-held path is the common case, and ADR-0018 CB-6a calls it that rather
/// than "the fallback".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAeadCustody {
    /// The platform performs the record AEAD; no key is core-held.
    PlatformPerformed,
    /// The key is unsealed into the core's locked allocator. **The common case**,
    /// and a declared per-target fact rather than a silent degradation.
    CoreHeld,
}

/// Tier-1 secure storage and the vended store root (CB-7).
pub trait SecureStore: Send + Sync {
    /// Reads a Tier-1 item.
    ///
    /// `Ok(None)` means "absent", which is a normal first-run state and not an
    /// error — the distinction matters because "absent" enrols and "unavailable"
    /// must not.
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>>;

    /// Writes a Tier-1 item **atomically**.
    ///
    /// Atomic per item: a torn write of the SEK would make the whole vault
    /// unreadable, and ADR-0020's recovery ladder cannot recover a key it never
    /// received.
    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;

    /// Deletes a Tier-1 item. Idempotent.
    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;

    /// The vended vault directory, with its attributes already applied.
    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>>;

    /// Who performs the record AEAD on this target (CB-6a).
    fn record_aead_custody(&self) -> RecordAeadCustody;
}
