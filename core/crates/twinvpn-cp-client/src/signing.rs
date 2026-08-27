//! Per-message signing, as a call **out** through platform custody.
//!
//! **Authority:** ADR-0001 §11 item 3 (L-CONTROL carries end-to-end per-message
//! signatures by `DeviceIdentityKey`), `docs/protocol.md` §3 (Rule A / Rule B),
//! ADR-0018 CB-5 / **I4** (identity private keys stay inside the platform
//! element), `contracts/proto/twinvpn/v1/identity.proto` (the secret-field
//! prohibition).
//!
//! # There is no private scalar in this crate, and there cannot be one
//!
//! Signing is [`twinvpn_platform::custody::IdentityCustody::identity_sign`],
//! which "performs its work **inside the element**", returns an opaque
//! [`twinvpn_platform::custody::Signature`], and has **no type in its signature
//! that could hold a private scalar**. This module is the only place in the
//! crate that signs, it holds no key material of its own, and the key is named
//! by [`twinvpn_platform::custody::IdentityKeyRef`] — an enum, not a handle
//! carrying bytes.
//!
//! Generation is explicit in that enum because `T_IK_OVERLAP` means two
//! generations are live at once, and "the identity key" without a generation is
//! ambiguous exactly when it matters.
//!
//! # Rule A and Rule B are not both set
//!
//! protocol.md §3: *exactly one* of the two authentication modes applies to any
//! given message.
//!
//! - **Rule A** — channel-authenticated. `channel_binding` is set; no
//!   per-message signature exists. This is every ordinary C1 request.
//! - **Rule B** — transitively forwarded. `signed_payload` + `detached_sig` +
//!   `signer_key_id` are set, and the verifier verifies over **the exact
//!   received octets** and MUST NOT re-serialize.
//!
//! [`AuthMode`] makes "both" unrepresentable, and [`build_auth`] is a total
//! function over it — so a message cannot acquire a signature by accident, and
//! a Rule-B carrier cannot lose one.

use twinvpn_platform::custody::{IdentityCustody, IdentityKeyRef};
use twinvpn_platform::PlatformError;
use twinvpn_schema::v1;
use twinvpn_types::{ChannelBinding, Identifier, SignerKeyId};

use crate::error::CpError;
use crate::octets::ReceivedOctets;

/// Which of protocol.md §3's two rules a message travels under.
#[derive(Debug)]
pub enum AuthMode<'a> {
    /// Rule A. The message travels only over the mutually authenticated channel
    /// between its origin and its final consumer.
    ChannelAuthenticated {
        /// The RFC 9266 `tls-exporter` value of this connection.
        binding: &'a ChannelBinding,
    },
    /// Rule B. The message is forwarded, stored or reconstructed by a third
    /// party, so it carries its own signature.
    Signed {
        /// The channel binding is still carried: a Rule-B statement travelling
        /// on C1 is *also* on an authenticated channel, and ADR-0002 N-2's check
        /// applies to it too. What Rule B adds is that the channel is no longer
        /// the *only* thing vouching for the content.
        binding: &'a ChannelBinding,
        /// The deterministic-CBOR COSE_Sign1 payload, **as octets**. Never a
        /// protobuf message: protobuf has no normative canonical encoding, so a
        /// protobuf representation of a signed statement would be a second byte
        /// representation of a thing that must have exactly one.
        payload: &'a ReceivedOctets,
        /// Which element-resident key signs.
        key: IdentityKeyRef,
        /// The signer's `DeviceKey` fingerprint.
        signer_key_id: &'a SignerKeyId,
        /// The statement's own bounded lifetime. Mandatory on a signed
        /// statement (ADR-0003 B2).
        not_before_ms: u64,
        /// The upper bound.
        not_after_ms: u64,
    },
}

/// Builds the `Auth` field for one outbound message.
///
/// For Rule A this is pure. For Rule B it calls out to the element and awaits a
/// signature that this process never sees the key for.
///
/// # Errors
///
/// [`CpError::KeyUnavailable`] when the element refuses — a locked device, a
/// revoked entitlement, an element that lost its backing. `AUTH.KEY_UNAVAILABLE`
/// is the registered code, and it is **never** a licence to fall back to a
/// key we do not have.
pub async fn build_auth(
    custody: &dyn IdentityCustody,
    mode: AuthMode<'_>,
) -> Result<v1::Auth, CpError> {
    match mode {
        AuthMode::ChannelAuthenticated { binding } => Ok(v1::Auth {
            channel_binding: binding.as_bytes().to_vec(),
            ..Default::default()
        }),
        AuthMode::Signed {
            binding,
            payload,
            key,
            signer_key_id,
            not_before_ms,
            not_after_ms,
        } => {
            // The signature covers THESE BYTES VERBATIM. `payload.as_slice()` is
            // what arrived or what was canonically produced elsewhere; nothing
            // between here and the element re-encodes it.
            let signature = custody
                .identity_sign(key, payload.as_slice())
                .await
                .map_err(|e| map_custody_error(&e))?;
            Ok(v1::Auth {
                channel_binding: binding.as_bytes().to_vec(),
                detached_sig: signature.as_bytes().to_vec(),
                signed_payload: payload.as_slice().to_vec(),
                signer_key_id: signer_key_id.as_str().to_owned(),
                not_before_ms,
                not_after_ms,
            })
        }
    }
}

/// Maps a custody refusal onto a registered code.
///
/// Everything the element can refuse with lands on `AUTH.KEY_UNAVAILABLE` or
/// `AUTH.KEY_STORE_UNAVAILABLE`, both of which `PlatformError` already declares —
/// so this is a narrowing, not a second taxonomy.
fn map_custody_error(err: &PlatformError) -> CpError {
    match err {
        PlatformError::IdentityKeyUnavailable(_) | PlatformError::SecureStoreUnavailable(_) => {
            CpError::KeyUnavailable
        }
        // Anything else is still a failure to obtain a signature, and a message
        // that cannot be signed is not sent. Reporting it as the same registered
        // condition is honest: the observable fact is "we have no signature".
        _ => CpError::KeyUnavailable,
    }
}

/// Whether a signature is required for this message to mean anything.
///
/// The C1 rows `protocol.md` §16 marks `A + B` — revocation admission, pairing
/// confirmation, key rotation, policy authorship — plus the advertisement
/// withdrawals, which carry a `SignedStatement` of their own.
#[must_use]
pub const fn requires_signature(command: crate::idempotency::Command) -> bool {
    use crate::idempotency::Command;
    matches!(
        command,
        Command::RevokeDevice
            | Command::CompletePairing
            | Command::RotateDeviceCredential
            | Command::RevokePairing
            | Command::PutPolicy
            | Command::PutRouteAdvertisement
            | Command::WithdrawRouteAdvertisement
            | Command::PutExitNodeOffer
            | Command::WithdrawExitNodeOffer
    )
}

#[cfg(test)]
mod tests {
    use super::{build_auth, requires_signature, AuthMode};
    use crate::idempotency::Command;
    use crate::octets::ReceivedOctets;
    use twinvpn_platform::custody::IdentityKeyRef;
    use twinvpn_platform::mock::{MockAdapter, MockOptions};
    use twinvpn_platform::PlatformAdapter;
    use twinvpn_types::{ChannelBinding, SignerKeyId};

    fn block_on<F>(env: &twinvpn_env::Env, fut: F) -> F::Output
    where
        F: core::future::Future + Send,
        F::Output: Send,
    {
        let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = std::sync::Arc::clone(&cell);
        env.runtime().block_on(Box::pin(async move {
            let out = fut.await;
            *sink.lock().expect("not poisoned") = Some(out);
        }));
        let mut guard = cell.lock().expect("not poisoned");
        guard.take().expect("the future completed")
    }

    #[test]
    fn rule_a_carries_a_binding_and_no_signature() {
        let env = crate::testing::test_env();
        let adapter = MockAdapter::new(&MockOptions::default());
        let binding = ChannelBinding::from_array([0x33; 32]);
        let auth = block_on(
            &env,
            build_auth(
                adapter.identity(),
                AuthMode::ChannelAuthenticated { binding: &binding },
            ),
        )
        .expect("rule A is pure");
        assert_eq!(auth.channel_binding.len(), 32);
        assert!(
            auth.detached_sig.is_empty() && auth.signed_payload.is_empty(),
            "protocol.md §3: exactly ONE of the two modes applies"
        );
        assert_eq!(adapter.identity_mock().sign_calls(), 0);
    }

    #[test]
    fn rule_b_signs_the_received_octets_verbatim() {
        let env = crate::testing::test_env();
        let adapter = MockAdapter::new(&MockOptions::default());
        adapter.identity_mock().allow_insecure_stub_signer();
        let binding = ChannelBinding::from_array([0x44; 32]);
        let payload = ReceivedOctets::from_wire(&[0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0]);
        let signer = SignerKeyId::new("twk1deadbeef").expect("valid");

        let auth = block_on(
            &env,
            build_auth(
                adapter.identity(),
                AuthMode::Signed {
                    binding: &binding,
                    payload: &payload,
                    key: IdentityKeyRef::Identity { generation: 0 },
                    signer_key_id: &signer,
                    not_before_ms: 1_000,
                    not_after_ms: 2_000,
                },
            ),
        )
        .expect("the stub signer answers");

        assert_eq!(
            auth.signed_payload,
            payload.as_slice(),
            "the signature covers THESE BYTES VERBATIM"
        );
        assert!(!auth.detached_sig.is_empty());
        assert_eq!(auth.signer_key_id, "twk1deadbeef");
        assert_eq!(auth.not_after_ms, 2_000, "a bounded lifetime is mandatory");
        assert_eq!(adapter.identity_mock().sign_calls(), 1);
    }

    #[test]
    fn an_unavailable_element_is_a_registered_refusal_not_a_fallback() {
        let env = crate::testing::test_env();
        let adapter = MockAdapter::new(&MockOptions::default());
        adapter.identity_mock().allow_insecure_stub_signer();
        adapter.identity_mock().set_unavailable(true);
        let binding = ChannelBinding::from_array([0x55; 32]);
        let payload = ReceivedOctets::from_wire(&[1, 2, 3]);
        let signer = SignerKeyId::new("twk1abc").expect("valid");

        let err = block_on(
            &env,
            build_auth(
                adapter.identity(),
                AuthMode::Signed {
                    binding: &binding,
                    payload: &payload,
                    key: IdentityKeyRef::Identity { generation: 0 },
                    signer_key_id: &signer,
                    not_before_ms: 0,
                    not_after_ms: 1,
                },
            ),
        )
        .expect_err("the element refused");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
    }

    #[test]
    fn the_rule_b_command_set_is_protocol_md_16s() {
        // §16 rows 4, 6, 8, 25, 27, 29 are `A + B`; the rest of C1 is `A`.
        for command in [
            Command::RevokeDevice,
            Command::CompletePairing,
            Command::RotateDeviceCredential,
            Command::PutPolicy,
            Command::PutRouteAdvertisement,
            Command::PutExitNodeOffer,
        ] {
            assert!(requires_signature(command), "{}", command.as_str());
        }
        for command in [
            Command::DiscoverPeers,
            Command::PublishPresence,
            Command::SubscribeEvents,
            Command::GetStateDocument,
            Command::UpdateDeviceMetadata,
            Command::BeginPairing,
        ] {
            assert!(!requires_signature(command), "{}", command.as_str());
        }
    }
}
