//! The [`KeystoreElement`] half of [`super::JvmHost`].
//!
//! **Authority:** ADR-0018 CB-5, CB-6a, CB-7, §11.16 (c) and (l); ADR-0007 N-5
//! and N-6; ADR-0020 §11's Android rows; ADR-0022 LC-15.
//!
//! Split from `jvm.rs` only for the 500-line rule; it is one object on the Java
//! side, because on Android identity custody and Tier-1 storage are one platform
//! object.
//!
//! **`#[cfg(target_os = "android")]`. `cargo check`ed by `make cross-check`;
//! never linked, never run.**

use jni::objects::JValue;

use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, PlatformError, SecureItemKey, SharedSecret,
    Signature,
};
use twinvpn_types::{DeviceId, IdentityId};

use super::{describe_pending_exception, from_java_bytes, to_java_bytes, JvmHost};
use crate::hostcall::{KeystoreElement, SecurityLevel};
use crate::oserr::{self, Context};

/// The identifier of an element-resident key, as one integer.
///
/// **Not a domain fact**: it names *which key*, exactly as
/// [`IdentityKeyRef`] does, and carries no key material. §10.4's prohibition is
/// about `ConnectionState`, `reason_code` classes, policy verdicts and candidate
/// priorities; "which of three keys" is none of those, and the alternative —
/// three separate JNI methods — is the same fact spelled worse.
const fn key_tag(key: IdentityKeyRef) -> i32 {
    match key {
        IdentityKeyRef::Identity { .. } => 0,
        IdentityKeyRef::OwnerSigning => 1,
        IdentityKeyRef::OwnerRoot => 2,
        // `IdentityKeyRef` is `#[non_exhaustive]`. A variant this build does not
        // know is refused by the Kotlin side rather than silently mapped onto
        // the identity key, which would sign with the wrong one.
        _ => -1,
    }
}

fn key_generation(key: IdentityKeyRef) -> i32 {
    match key {
        // ADR-0007 rotation creates a new `DeviceIdentity` at `generation + 1`;
        // a generation beyond `i32::MAX` is unreachable in any product lifetime,
        // and saturating is the honest narrowing rather than a wrap.
        IdentityKeyRef::Identity { generation } => i32::try_from(generation).unwrap_or(i32::MAX),
        _ => 0,
    }
}

impl KeystoreElement for JvmHost {
    fn name(&self) -> &'static str {
        "android-keystore"
    }

    fn security_level(&self) -> SecurityLevel {
        // A failure to ask is reported as `Absent`, which is the fail-safe
        // direction: it reports `hardware_backed: false` truthfully rather than
        // claiming a backing we could not confirm (§11.16 (l)).
        self.call(
            "securityLevel",
            "()I",
            &[],
            Context::Identity,
            |_, value| {
                value
                    .i()
                    .map_err(|_| oserr::unavailable("securityLevel", libc::EPROTO))
            },
        )
        .map_or(SecurityLevel::Absent, |level| match level {
            0 => SecurityLevel::StrongBox,
            1 => SecurityLevel::TrustedEnvironment,
            2 => SecurityLevel::Software,
            _ => SecurityLevel::Absent,
        })
    }

    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        let encoded = self
            .call(
                "identityPublic",
                "()[B",
                &[],
                Context::Identity,
                |env, value| {
                    let object = value
                        .l()
                        .map_err(|_| oserr::unavailable("identityPublic", libc::EPROTO))?;
                    from_java_bytes(env, object)
                },
            )?
            .ok_or(PlatformError::IdentityKeyUnavailable(None))?;
        decode_identity_public(&encoded)
    }

    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError> {
        let tag = key_tag(key);
        if tag < 0 {
            return Err(PlatformError::IdentityKeyUnavailable(None));
        }
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable("identitySign", libc::ESRCH))?;
        let payload = to_java_bytes(&mut env, message)?;
        let outcome = env.call_method(
            &self.host,
            "identitySign",
            "(II[B)[B",
            &[
                JValue::Int(tag),
                JValue::Int(key_generation(key)),
                JValue::Object(&payload),
            ],
        );
        let Ok(value) = outcome else {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                "identitySign",
                Context::Identity,
            ));
        };
        let object = value
            .l()
            .map_err(|_| oserr::unavailable("identitySign", libc::EPROTO))?;
        let bytes = from_java_bytes(&mut env, object)?
            .ok_or(PlatformError::IdentityKeyUnavailable(None))?;
        Ok(Signature::new(bytes))
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        // ADR-0018 §11.16 (c) and ADR-0007 N-5: in-element agree is NOT required.
        // Android Keystore offers ECDH on P-256 from API 31 and never offers
        // X25519, and `docs/networking.md` §5.2 sets this product's floor at API
        // 26. `OsUnsupported` is a fact the core records; it is not a licence to
        // fall back to a private key the core does not have.
        Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
            0,
            "KeyAgreement.ECDH",
        ))))
    }

    fn attestation(&self) -> Option<Vec<u8>> {
        self.call(
            "attestation",
            "()[B",
            &[],
            Context::Identity,
            |env, value| {
                let object = value
                    .l()
                    .map_err(|_| oserr::unavailable("attestation", libc::EPROTO))?;
                from_java_bytes(env, object)
            },
        )
        .ok()
        .flatten()
    }

    fn item_read(&self, key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable("itemRead", libc::ESRCH))?;
        let name = env
            .new_string(key.as_str())
            .map_err(|_| oserr::unavailable("itemRead", libc::ENOMEM))?;
        let outcome = env.call_method(
            &self.host,
            "itemRead",
            "(Ljava/lang/String;)[B",
            &[JValue::Object(&name)],
        );
        let Ok(value) = outcome else {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                "itemRead",
                Context::SecureStore,
            ));
        };
        let object = value
            .l()
            .map_err(|_| oserr::unavailable("itemRead", libc::EPROTO))?;
        // `null` is ABSENT, which is a normal first-run state; a throw is
        // UNAVAILABLE. The distinction matters because absent enrols and
        // unavailable must not.
        from_java_bytes(&mut env, object)
    }

    fn item_write_atomic(&self, key: &SecureItemKey, value: &[u8]) -> Result<(), PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable("itemWrite", libc::ESRCH))?;
        let name = env
            .new_string(key.as_str())
            .map_err(|_| oserr::unavailable("itemWrite", libc::ENOMEM))?;
        let payload = to_java_bytes(&mut env, value)?;
        let outcome = env.call_method(
            &self.host,
            "itemWrite",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&name), JValue::Object(&payload)],
        );
        if outcome.is_err() {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                "itemWrite",
                Context::SecureStore,
            ));
        }
        Ok(())
    }

    fn item_delete(&self, key: &SecureItemKey) -> Result<(), PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable("itemDelete", libc::ESRCH))?;
        let name = env
            .new_string(key.as_str())
            .map_err(|_| oserr::unavailable("itemDelete", libc::ENOMEM))?;
        let outcome = env.call_method(
            &self.host,
            "itemDelete",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&name)],
        );
        if outcome.is_err() {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                "itemDelete",
                Context::SecureStore,
            ));
        }
        Ok(())
    }
}

/// Decodes the identity blob the Kotlin side assembles.
///
/// Layout: `device_id (32) ‖ identity_id (32) ‖ generation (u32 BE) ‖ spki`.
/// Every length is fixed but the trailing key is not, so the total is bounded
/// before anything is read — the same rule [`super::wire`] follows.
fn decode_identity_public(encoded: &[u8]) -> Result<IdentityPublic, PlatformError> {
    const FIXED: usize = 32 + 32 + 4;
    /// A P-256 SPKI is ~91 bytes; 512 is generous and is the point at which the
    /// shim is malfunctioning rather than verbose.
    const MAX_SPKI: usize = 512;

    if encoded.len() < FIXED || encoded.len() > FIXED + MAX_SPKI {
        return Err(oserr::unavailable("identityPublic", libc::EBADMSG));
    }
    let mut device = [0u8; 32];
    device.copy_from_slice(&encoded[..32]);
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&encoded[32..64]);
    let generation = u32::from_be_bytes([encoded[64], encoded[65], encoded[66], encoded[67]]);
    Ok(IdentityPublic {
        device_id: DeviceId::from_array(device),
        identity_id: IdentityId::from_array(identity),
        generation,
        public_key: encoded[FIXED..].to_vec(),
    })
}
