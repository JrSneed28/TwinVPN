//! The CNG and DPAPI-NG syscall shim. **`#[cfg(windows)]`, and never executed.**
//!
//! **Authority:** ADR-0020 §11.3's two Windows rows, ST-9, ST-12d; ADR-0018
//! CB-5, §11.16 (c) and (l), CD-I2, DP-4; ADR-0016 §11.3 O6/O7.
//!
//! This is the only part of [`super`] that needs Windows, and it is deliberately
//! the thinnest thing that can carry the two operations the seam names. Every
//! decision — which class a backing justifies, which descriptor string to seal
//! to, how an item reaches the disk — is one module up and runs its tests on a
//! Linux host. What is here is the marshalling, and **it has never been
//! executed**: `make cross-check` type-checks it against the real `windows-sys`
//! and proves nothing about its behaviour.
//!
//! # Two things the seam asks for that this platform cannot give literally
//!
//! Both are stated here rather than worked around, and both are in this domain's
//! report to the integration lead:
//!
//! 1. **`identity_sign` takes a `message`; `NCryptSignHash` takes a *hash*.**
//!    ES256 signs a SHA-256 digest, and computing one here would need a
//!    cryptographic dependency CD-I2 restricts to `twinvpn-crypto`. So
//!    [`CngElement::sign`] **requires the caller to pass a 32-byte digest** and
//!    refuses anything else by name. Refusing is the safe direction: signing the
//!    wrong bytes produces a signature that verifies against nothing and looks
//!    like a key problem.
//!
//! 2. **`IdentityPublic::device_id` is "SHA-256 of the generation-0 identity
//!    key", and this crate has no hash.** It uses **CNG's own** `BCryptHash`,
//!    which is a platform primitive reached by syscall rather than a crate in
//!    the workspace graph — the same shape as reaching the platform CSPRNG from
//!    a `twinvpn-platform-*` crate. That reading of CD-I2 is a judgement, and it
//!    is flagged as one.

use windows_sys::Win32::Foundation::{HWND, NTSTATUS};
use windows_sys::Win32::Security::Cryptography::{
    BCryptHash, NCryptCloseProtectionDescriptor, NCryptCreateProtectionDescriptor, NCryptExportKey,
    NCryptFreeBuffer, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptProtectSecret, NCryptSignHash, NCryptUnprotectSecret, BCRYPT_ALG_HANDLE,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_SHA256_ALGORITHM, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_KEY_STORAGE_PROVIDER, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};
use windows_sys::Win32::Security::NCRYPT_DESCRIPTOR_HANDLE;

use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, PlatformError, SharedSecret, Signature,
};
use twinvpn_types::{DeviceId, IdentityId};

use super::{
    protection_descriptor, SecretProtector, SigningElement, Tier1Backend, IDENTITY_KEY_CONTAINER,
};
use crate::oserr::{self, Context, Win32Error};

/// The digest width `identity_sign` requires. See the module documentation.
///
/// A `u32` because that is what `NCryptSignHash` takes: keeping the constant in
/// the API's own width means the length reaches the call with no cast, and a
/// cast is where a width bug hides.
const ES256_DIGEST_BYTES: u32 = 32;

/// The largest sealed blob this shim will accept back from DPAPI-NG.
///
/// **A bound recorded as one.** `ownership.md` §6 rule 10 requires every
/// allocation an untrusted input can drive to be bounded, and the length here
/// comes from the OS rather than from us. A Tier-1 item is the SEK, `K_bind` or
/// the S-53 anchor — ADR-0020 ST-21 caps the anchor at 512 bytes and the others
/// are key-sized — so 64 KiB is four orders of magnitude of headroom and still
/// refuses a corrupt length outright.
const MAX_SEALED_BYTES: u32 = 64 * 1024;

/// A NUL-terminated UTF-16 buffer, for the `PCWSTR` parameters.
///
/// Returned as an owned `Vec` the caller keeps alive across the call: handing
/// `as_ptr()` of a temporary to a `system` function is the classic use-after-free
/// in this FFI, and naming the buffer makes the lifetime visible at every site.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Maps an `HRESULT` or `NTSTATUS` through the crate's one vocabulary.
fn status(code: i32, call: &'static str, context: Context) -> PlatformError {
    oserr::from_status(Win32Error::from_i32(code), call, context)
}

/// An open CNG provider handle that closes itself.
///
/// A guard rather than a `defer` at each call site: several of the functions
/// below have three or four early returns, and a leaked `NCRYPT_PROV_HANDLE` is
/// a handle leak in a service that runs for months.
struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a provider handle this type obtained from a
        // successful `NCryptOpenStorageProvider` and has not closed; the guard
        // is the only owner and `Drop` runs once.
        unsafe {
            let _ = NCryptFreeObject(self.0);
        }
    }
}

/// An open CNG key handle that closes itself.
struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: as `Provider` — a handle from a successful `NCryptOpenKey`,
        // uniquely owned, closed once.
        unsafe {
            let _ = NCryptFreeObject(self.0);
        }
    }
}

/// Opens one of the two providers ADR-0020 §11.3 names.
fn open_provider(backend: Tier1Backend) -> Result<Provider, PlatformError> {
    let name = match backend {
        Tier1Backend::PlatformCryptoProvider { .. } => MS_PLATFORM_KEY_STORAGE_PROVIDER,
        Tier1Backend::SoftwareKsp => MS_KEY_STORAGE_PROVIDER,
        Tier1Backend::Absent => {
            return Err(oserr::from_status(
                Win32Error(oserr::NTE_BAD_KEYSET),
                "NCryptOpenStorageProvider",
                Context::Identity,
            ))
        }
    };
    let mut handle: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: `handle` is a live, uniquely-borrowed out-parameter of the
    // declared type; `name` is one of `windows-sys`' own static wide literals,
    // NUL-terminated by construction. The call writes at most one handle and
    // retains no pointer.
    let rc = unsafe { NCryptOpenStorageProvider(&raw mut handle, name, 0) };
    if rc != 0 {
        return Err(status(rc, "NCryptOpenStorageProvider", Context::Identity));
    }
    Ok(Provider(handle))
}

/// Opens the machine-scope identity key container.
///
/// `NCRYPT_MACHINE_KEY_FLAG` is not a preference: ADR-0020 C-4 records that "the
/// service starts before any interactive logon", so a user-scope key would be
/// unavailable at exactly the moment ADR-0022 LC-4 needs it.
fn open_identity_key(provider: &Provider) -> Result<Key, PlatformError> {
    let name = wide(IDENTITY_KEY_CONTAINER);
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: `provider.0` is an open provider handle for the whole call;
    // `name` is a live NUL-terminated UTF-16 buffer that outlives the call;
    // `key` is a live out-parameter. The call retains no pointer.
    let rc = unsafe {
        NCryptOpenKey(
            provider.0,
            &raw mut key,
            name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    if rc != 0 {
        return Err(status(rc, "NCryptOpenKey", Context::Identity));
    }
    Ok(Key(key))
}

/// SHA-256, through the platform's own hash rather than a crate.
///
/// See the module documentation for why this reading of CD-I2 is a judgement:
/// `BCryptHash` is a syscall into the OS, not a cryptographic dependency in the
/// workspace's graph, and it is reached from the one crate CB-3 and DP-4 already
/// designate for platform primitives.
fn sha256(input: &[u8]) -> Result<[u8; 32], PlatformError> {
    let mut out = [0u8; 32];
    let algorithm: BCRYPT_ALG_HANDLE = BCRYPT_SHA256_ALGORITHM
        .cast::<core::ffi::c_void>()
        .cast_mut();
    // SAFETY: `input` and `out` are live slices whose true byte lengths are
    // passed; `BCryptHash` with a pseudo-handle algorithm identifier writes at
    // most `out.len()` bytes and retains no pointer. The pseudo-handle form is
    // the documented one-shot interface and needs no provider to close.
    let rc: NTSTATUS = unsafe {
        BCryptHash(
            algorithm,
            core::ptr::null(),
            0,
            input.as_ptr(),
            u32::try_from(input.len()).unwrap_or(u32::MAX),
            out.as_mut_ptr(),
            u32::try_from(out.len()).unwrap_or(0),
        )
    };
    if rc != 0 {
        return Err(status(rc, "BCryptHash", Context::Identity));
    }
    Ok(out)
}

/// The CNG-backed identity element.
///
/// Holds a **backend discriminator and nothing else** — no handle cached across
/// calls, and certainly no key. Handles are opened per operation and closed by
/// their guards, which costs a provider open per signature and buys the property
/// that a suspended or restarted CNG service cannot leave this type holding a
/// stale handle it would then report as a key failure.
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

    /// ST-9's live probe: which backing this host actually has.
    ///
    /// Tries the Platform Crypto Provider first, then the software KSP, and
    /// reports [`Tier1Backend::Absent`] if neither opens. It asks each backend
    /// *what it is* and never reads key material, which is ST-9b's shape.
    ///
    /// `attested` is reported `false` until an attestation is actually obtained
    /// and its format recognised, because §11.4 makes `HARDWARE_ATTESTED` mean
    /// "the platform produced an attestation the approving OSK device verified"
    /// — claiming it from the provider's mere presence would be the overstatement
    /// ST-9a exists to prevent.
    #[must_use]
    pub fn probe() -> Tier1Backend {
        let pcp = Tier1Backend::PlatformCryptoProvider { attested: false };
        if open_provider(pcp).is_ok() {
            return pcp;
        }
        if open_provider(Tier1Backend::SoftwareKsp).is_ok() {
            return Tier1Backend::SoftwareKsp;
        }
        Tier1Backend::Absent
    }
}

impl SigningElement for CngElement {
    fn name(&self) -> &'static str {
        match self.backend {
            Tier1Backend::PlatformCryptoProvider { .. } => "cng-pcp",
            Tier1Backend::SoftwareKsp => "cng-software",
            Tier1Backend::Absent => "absent",
        }
    }

    fn backend(&self) -> Tier1Backend {
        self.backend
    }

    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        let provider = open_provider(self.backend)?;
        let key = open_identity_key(&provider)?;

        // Two calls: the first sizes the blob, the second fills it. The size is
        // the OS's and is bounded before the allocation (`ownership.md` §6
        // rule 10) — a public key blob that claims 64 KiB is a malfunctioning
        // provider, not a key.
        let mut needed: u32 = 0;
        // SAFETY: `key.0` is an open key handle; the output pointer is null and
        // the length zero, which is the documented sizing form; `needed` is a
        // live out-parameter.
        let rc = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                &raw mut needed,
                0,
            )
        };
        if rc != 0 {
            return Err(status(rc, "NCryptExportKey", Context::Identity));
        }
        if needed == 0 || needed > MAX_SEALED_BYTES {
            return Err(oserr::unavailable("NCryptExportKey.length"));
        }
        let mut blob = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: `blob` is a live, uniquely-borrowed buffer of exactly
        // `needed` bytes and that length is what is passed; the call writes at
        // most that many and retains no pointer.
        let rc = unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                core::ptr::null(),
                blob.as_mut_ptr(),
                needed,
                &raw mut written,
                0,
            )
        };
        if rc != 0 {
            return Err(status(rc, "NCryptExportKey", Context::Identity));
        }
        blob.truncate(written as usize);

        // The generation-0 digest IS the `device_id`; the current generation's
        // digest is the `identity_id`. This build holds one generation, so the
        // two coincide — and that is a fact about this build, not about the
        // model: ADR-0007 rotation creates a new `DeviceIdentity` at
        // `generation + 1` while `device_id` is unchanged, and a build that
        // rotates must keep the generation-0 digest rather than recomputing.
        let digest = sha256(&blob)?;
        Ok(IdentityPublic {
            device_id: DeviceId::from_array(digest),
            identity_id: IdentityId::from_array(digest),
            generation: 0,
            public_key: blob,
        })
    }

    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError> {
        // See the module documentation: `NCryptSignHash` signs a digest, and
        // hashing here would need a cryptographic dependency CD-I2 restricts.
        // Refusing anything that is not already a SHA-256 digest is the safe
        // direction — a signature over the wrong bytes verifies against nothing
        // and presents as a key failure nobody can diagnose.
        let width = u32::try_from(message.len()).unwrap_or(u32::MAX);
        if width != ES256_DIGEST_BYTES {
            return Err(oserr::unavailable("identity_sign.digest_width"));
        }
        // Only the identity key has a container in this build; the two Owner
        // keys are the `Owner`'s device's, not this one's.
        if !matches!(key, IdentityKeyRef::Identity { .. }) {
            return Err(oserr::from_status(
                Win32Error(oserr::NTE_BAD_KEYSET),
                "NCryptOpenKey(owner)",
                Context::Identity,
            ));
        }

        let provider = open_provider(self.backend)?;
        let key = open_identity_key(&provider)?;

        let mut needed: u32 = 0;
        // SAFETY: `message` is a live slice of the passed length; the signature
        // pointer is null and its length zero, the documented sizing form.
        let rc = unsafe {
            NCryptSignHash(
                key.0,
                core::ptr::null(),
                message.as_ptr(),
                ES256_DIGEST_BYTES,
                core::ptr::null_mut(),
                0,
                &raw mut needed,
                0,
            )
        };
        if rc != 0 {
            return Err(status(rc, "NCryptSignHash", Context::Identity));
        }
        if needed == 0 || needed > MAX_SEALED_BYTES {
            return Err(oserr::unavailable("NCryptSignHash.length"));
        }
        let mut signature = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: both slices are live and uniquely borrowed, and their true
        // lengths are passed; the call writes at most `needed` bytes into
        // `signature` and retains no pointer.
        let rc = unsafe {
            NCryptSignHash(
                key.0,
                core::ptr::null(),
                message.as_ptr(),
                ES256_DIGEST_BYTES,
                signature.as_mut_ptr(),
                needed,
                &raw mut written,
                0,
            )
        };
        if rc != 0 {
            return Err(status(rc, "NCryptSignHash", Context::Identity));
        }
        signature.truncate(written as usize);
        Ok(Signature::new(signature))
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        // ADR-0018 §11.16 (c): in-element `agree` is not required on every
        // target. CNG's key-storage providers offer ECDH over the NIST curves
        // and **not** X25519, which is what ADR-0007 N-5 needs, so the honest
        // answer is a platform fact the core records — never a licence to fall
        // back to a private key this process does not have.
        Err(oserr::from_status(
            Win32Error(oserr::ERROR_NOT_SUPPORTED),
            "NCryptSecretAgreement(X25519)",
            Context::Identity,
        ))
    }

    fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
        // A TPM attestation is an `NCryptGetProperty` of the PCP key-attestation
        // blob plus an AIK the approving OSK device can verify — ADR-0007 N-6's
        // whole ceremony, which this build does not carry. Reporting `None` is
        // what keeps `custody_class` at `HARDWARE_UNATTESTED`, which §11.4 says
        // "a peer MUST NOT treat as evidence". Claiming an attestation format we
        // cannot produce would be the overstatement ST-9c makes security-relevant.
        None
    }
}

/// DPAPI-NG sealing, bound to the machine's `LocalSystem` descriptor.
#[derive(Debug, Clone, Copy)]
pub struct DpapiNgProtector {
    backend: Tier1Backend,
}

impl DpapiNgProtector {
    /// Binds a protector to a probed backend.
    ///
    /// The backend decides the descriptor: ADR-0020 §11.3 seals to a descriptor
    /// "whose protector is a TPM-bound key" where a TPM exists, and to a machine
    /// descriptor without one where it does not.
    #[must_use]
    pub const fn new(backend: Tier1Backend) -> Self {
        Self { backend }
    }

    /// Opens the descriptor this protector seals to.
    fn descriptor(&self) -> Result<Descriptor, PlatformError> {
        let text = wide(&protection_descriptor(self.backend));
        let mut handle: NCRYPT_DESCRIPTOR_HANDLE = core::ptr::null_mut();
        // SAFETY: `text` is a live NUL-terminated UTF-16 buffer that outlives
        // the call; `handle` is a live out-parameter. The call retains no
        // pointer into `text`.
        let rc = unsafe { NCryptCreateProtectionDescriptor(text.as_ptr(), 0, &raw mut handle) };
        if rc != 0 {
            return Err(status(
                rc,
                "NCryptCreateProtectionDescriptor",
                Context::SecureStore,
            ));
        }
        Ok(Descriptor(handle))
    }
}

/// An open protection descriptor that closes itself.
struct Descriptor(NCRYPT_DESCRIPTOR_HANDLE);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: a handle from a successful `NCryptCreateProtectionDescriptor`,
        // uniquely owned by this guard and closed once.
        unsafe {
            let _ = NCryptCloseProtectionDescriptor(self.0);
        }
    }
}

/// Copies a CNG-allocated buffer into a `Vec` and frees the original.
///
/// `NCryptProtectSecret` and `NCryptUnprotectSecret` allocate with
/// `LocalAlloc` and hand the caller the pointer; `NCryptFreeBuffer` is what
/// releases it. Doing the copy and the free in one place is what keeps a leak
/// out of the four early-return paths in each caller.
///
/// # Safety
///
/// `pointer` must be a CNG-allocated buffer of at least `length` bytes that the
/// caller has not already freed, and must not be used again afterwards.
unsafe fn take_cng_buffer(pointer: *mut u8, length: u32) -> Result<Vec<u8>, PlatformError> {
    if pointer.is_null() {
        return Err(oserr::unavailable("NCrypt.buffer"));
    }
    if length > MAX_SEALED_BYTES {
        // Free it before refusing: a bound that leaked the buffer it refused
        // would turn a corrupt length into a memory leak.
        // SAFETY: the caller's contract — a CNG-allocated, not-yet-freed buffer.
        unsafe { NCryptFreeBuffer(pointer.cast::<core::ffi::c_void>()) };
        return Err(oserr::unavailable("NCrypt.buffer.length"));
    }
    // SAFETY: the caller's contract guarantees `pointer` is valid for `length`
    // bytes; the slice is read once and does not outlive the free below.
    let copied = unsafe { core::slice::from_raw_parts(pointer, length as usize) }.to_vec();
    // SAFETY: as above, and the pointer is not used after this.
    unsafe { NCryptFreeBuffer(pointer.cast::<core::ffi::c_void>()) };
    Ok(copied)
}

impl SecretProtector for DpapiNgProtector {
    fn name(&self) -> &'static str {
        match self.backend {
            Tier1Backend::PlatformCryptoProvider { .. } => "dpapi-ng-tpm",
            Tier1Backend::SoftwareKsp | Tier1Backend::Absent => "dpapi-ng-machine",
        }
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let descriptor = self.descriptor()?;
        let mut blob: *mut u8 = core::ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: `descriptor.0` is an open descriptor for the whole call;
        // `plaintext` is a live slice whose true length is passed; the two
        // out-parameters are live. `HWND` is null because `NCRYPT_SILENT_FLAG`
        // forbids any UI — a service has no desktop to show one on, and a
        // prompt here would hang the start sequence.
        let rc = unsafe {
            NCryptProtectSecret(
                descriptor.0,
                NCRYPT_SILENT_FLAG,
                plaintext.as_ptr(),
                u32::try_from(plaintext.len()).unwrap_or(u32::MAX),
                core::ptr::null(),
                core::ptr::null_mut::<core::ffi::c_void>() as HWND,
                &raw mut blob,
                &raw mut length,
            )
        };
        if rc != 0 {
            return Err(status(rc, "NCryptProtectSecret", Context::SecureStore));
        }
        // SAFETY: the call succeeded, so `blob` is a CNG-allocated buffer of
        // `length` bytes that has not been freed, and it is not used after.
        unsafe { take_cng_buffer(blob, length) }
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, PlatformError> {
        // §6 rule 9: the declared length is checked BEFORE anything
        // proportional to it is allocated. A blob larger than any Tier-1 item
        // can be is a corrupt file, and refusing it is cheaper and safer than
        // handing it to the OS.
        if sealed.len() > MAX_SEALED_BYTES as usize {
            return Err(oserr::unavailable("NCryptUnprotectSecret.length"));
        }
        let mut descriptor: NCRYPT_DESCRIPTOR_HANDLE = core::ptr::null_mut();
        let mut plain: *mut u8 = core::ptr::null_mut();
        let mut length: u32 = 0;
        // SAFETY: `sealed` is a live slice whose true length is passed; the
        // three out-parameters are live and uniquely borrowed. The call writes
        // a descriptor handle this function closes and a buffer it frees.
        let rc = unsafe {
            NCryptUnprotectSecret(
                &raw mut descriptor,
                NCRYPT_SILENT_FLAG,
                sealed.as_ptr(),
                u32::try_from(sealed.len()).unwrap_or(u32::MAX),
                core::ptr::null(),
                core::ptr::null_mut::<core::ffi::c_void>() as HWND,
                &raw mut plain,
                &raw mut length,
            )
        };
        // The descriptor is returned whether or not the unseal succeeded, so it
        // is closed on both paths. Wrapping it before the error check is what
        // makes that true without a second free at each return.
        let _descriptor = Descriptor(descriptor);
        if rc != 0 {
            // This is the mechanism behind ADR-0020 §11.7's "restore vault +
            // Tier 1 together" row: on a TPM host the protector does not
            // resolve on different hardware and the unseal refuses here.
            return Err(status(rc, "NCryptUnprotectSecret", Context::SecureStore));
        }
        // SAFETY: the call succeeded, so `plain` is a CNG-allocated buffer of
        // `length` bytes that has not been freed, and it is not used after.
        unsafe { take_cng_buffer(plain, length) }
    }
}
