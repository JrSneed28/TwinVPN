//! Device lifecycle: register, update, **revoke**, rotate.
//!
//! **Authority:** `docs/protocol.md` §8.1, §8.3, §8.4;
//! `contracts/proto/twinvpn/v1/control_commands.proto`; ADR-0007 N-2, N-21,
//! N-22, N-25; ADR-0008 §11.3; ADR-0009 §11.2 E-1; `architecture.md` §4.5.
//!
//! # `RevokeDevice` is the strongest requirement in TwinVPN
//!
//! Two signers with two authorities, and this service holds only one of them:
//!
//! > *(1) PEER REFUSAL is LOCAL and takes effect the instant a device verifies
//! > this statement, WHATEVER ITS PROVENANCE … (2) `trust_epoch` ADVANCE is
//! > totally ordered. The `Owner` AUTHORIZES by signing; the control-plane shard
//! > writer ASSIGNS the epoch number at admission under its fenced lease.*
//!
//! [`revoke`] is written in that order and cannot be written in the other:
//! `tx.revoke` — the only thing that assigns an epoch — is reached **after**
//! `verify::admit` has returned an `Owner`-authority `Verified`. There is no
//! branch on which an unverified statement reaches the numbering.
//!
//! A well-formed wrapper authorizes nothing: `RevokeDeviceResponse` carries a
//! `RevocationEntry` *containing* the `Owner` statement, and the entry is built
//! here from the **received octets** of that statement, never re-encoded.

use twinvpn_schema::v1;
use twinvpn_service_common::forward::Verbatim;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::event::DurableEvent;
use crate::model::{DeviceRecord, PairingState};
use crate::verify::{self, StatementKind};
use crate::{Command, NetTx};

use super::addressing;
use super::{fixed, mutation_result, record, require_not_revoked, require_quorum, Ctx, Outcome};
use twinvpn_schema::v1::control_event::Event as EventBody;

/// Wraps received octets for verification and forwarding.
fn opaque(statement: Option<&v1::SignedStatement>) -> Result<Verbatim, ServiceError> {
    let s = statement.ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    verify::opaque_statement(bytes::Bytes::from(s.cose_sign1.clone()))
        .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))
}

/// `RegisterDevice` — `CEREMONY`, **linearizable** on
/// `(twinnet_id, device_pubkey)`.
///
/// `device_id_echo` is an **echo, never an assignment**: it is copied from the
/// `DeviceIdentity` the device presented. This service never computes one, and
/// there is no branch here that could return a different value — which is what
/// keeps identity self-certifying and S-08's address derivation intact.
///
/// # Errors
///
/// `PROTO.MALFORMED_MESSAGE` on a malformed identity; `AUTH.IDENTITY_MISMATCH`
/// when a generation-0 identity's `device_id` and `identity_id` disagree;
/// `AUTH.BINDING_INVALID` / `AUTH.KEY_UNAVAILABLE` when the enrolment proof does
/// not verify against the `Owner` chain; `CONTROL.QUORUM_UNAVAILABLE` when this
/// E-1-class write cannot reach quorum.
pub fn register(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::RegisterDeviceRequest,
) -> Result<Outcome, ServiceError> {
    require_quorum(ctx, Command::RegisterDevice)?;

    let identity = req
        .identity
        .as_ref()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_IDENTITY_MISSING))?;
    let device_id = fixed::<32>("device_id_bytes", &identity.device_id)?;
    let identity_id = fixed::<32>("identity_id_bytes", &identity.identity_id)?;

    // protocol.md §8.1: `device_id` is the generation-0 `identity_id`. A
    // generation-0 record where the two disagree is not self-certifying, and
    // admitting it would let a device claim a name it did not derive.
    if identity.generation == 0 && device_id != identity_id {
        return Err(codes::bare(twinvpn_types::codes::AUTH_IDENTITY_MISMATCH));
    }
    if identity.identity_public_key.is_empty() {
        return Err(codes::bare(twinvpn_types::codes::AUTH_IDENTITY_MISSING));
    }
    // ADR-0007 N-4: the IK-signed TunnelKeyBinding is what binds the X25519 key
    // to the hardware-held identity key. This service warehouses it verbatim;
    // the *peer* verifies it. Its absence is still refused, because a record
    // with no binding is one no peer can ever admit.
    if identity.tunnel_key_binding.is_none() {
        return Err(codes::bare(twinvpn_types::codes::AUTH_BINDING_INVALID));
    }

    // The Owner-scoped enrolment credential. "There is no owner ACCOUNT;
    // authorization is a key held by a device."
    let proof = opaque(req.enrollment_proof.as_ref())?;
    verify::admit(
        ctx.verifier,
        &proof,
        StatementKind::OwnerDelegation,
        ctx.now_ms,
        verify::SignerKey::OwnerAnchors,
    )?;

    // Linearizable admission. A duplicate enrol finds the SAME row — "device_id
    // is derived from the public key, so a duplicate enroll is naturally the
    // *same* device" — and returns it rather than minting a second.
    if let Some(existing) = tx
        .state()
        .device_by_public_key(&identity.identity_public_key)
    {
        if existing.revoked {
            return Err(codes::device_revoked(tx.state().trust_epoch));
        }
        let resp = response(ctx, existing, tx.state().trust_epoch, 0);
        return Ok(record(&resp, 0, set_replay));
    }

    // ADR-0010 §11.1 derives the v6 IID from `DeviceKey_pub` — the COSE_Key
    // octets, the same input `device_id` is derived from — so the address this
    // service records is the one the device computes for itself.
    let alloc = addressing::allocate(tx.state(), &device_id, &identity.identity_public_key)?;

    // `RegisterDeviceRequest` carries no label: the Owner names a device, and
    // `UpdateDeviceMetadata` is where that happens. A device that could name
    // itself at enrolment could claim another device's DNS label before its
    // Owner ever saw it.
    let membership_epoch = tx.state().devices.len() as u64 + 1;
    let device = v1::Device {
        device_id: device_id.to_vec(),
        twinnet_id: ctx.twinnet_id.to_owned(),
        identity: Some(identity.clone()),
        label: String::new(),
        platform: req.platform.clone(),
        roles: req.declared_roles.clone(),
        capabilities: req.capabilities.clone(),
        protocol_version: req.protocol_version,
        twinnet_address_v4: Some(v1::IPv4Address {
            octets: alloc.v4.to_vec(),
        }),
        twinnet_address_v6: Some(v1::IPv6Address {
            octets: alloc.v6.to_vec(),
            zone_index: 0,
        }),
        membership_epoch,
        version: 1,
        created_at_ms: ctx.now_ms,
        revoked: false,
    };

    let net_seq = tx.append(&DurableEvent::new(EventBody::DeviceRegistered(
        v1::DeviceRegistered {
            device: Some(device.clone()),
        },
    ))?)?;

    let record_row = DeviceRecord {
        device_id,
        identity_id,
        identity_public_key: identity.identity_public_key.clone(),
        generation: identity.generation,
        tk_generation: identity.tk_generation,
        label: String::new(),
        version: 1,
        membership_epoch,
        twinnet_addr_v4: alloc.v4,
        twinnet_addr_v6: alloc.v6,
        encoded: {
            use prost::Message;
            device.encode_to_vec()
        },
        revoked: false,
        net_seq,
        created_at_ms: ctx.now_ms,
    };
    tx.put_device(record_row.clone());
    tx.consume_v4_offset(alloc.v4_offset);

    let resp = response(ctx, &record_row, tx.state().trust_epoch, net_seq);
    Ok(record(&resp, net_seq, set_replay))
}

fn set_replay(m: &mut v1::RegisterDeviceResponse) {
    if let Some(r) = m.result.as_mut() {
        r.idempotent_replay = true;
    }
}

fn response(
    ctx: &Ctx<'_>,
    device: &DeviceRecord,
    revocation_epoch: u64,
    net_seq: u64,
) -> v1::RegisterDeviceResponse {
    v1::RegisterDeviceResponse {
        // AN ECHO, NEVER AN ASSIGNMENT.
        device_id_echo: device.device_id.to_vec(),
        twinnet_id: ctx.twinnet_id.to_owned(),
        assigned_twinnet_addr_v4: Some(v1::IPv4Address {
            octets: device.twinnet_addr_v4.to_vec(),
        }),
        assigned_twinnet_addr_v6: Some(v1::IPv6Address {
            octets: device.twinnet_addr_v6.to_vec(),
            zone_index: 0,
        }),
        coordination_endpoints: ctx.coordination_endpoints.to_vec(),
        result: Some(mutation_result(net_seq, revocation_epoch)),
        error: None,
    }
}

fn normalise_label(label: &str) -> String {
    label.trim().to_ascii_lowercase()
}

/// `UpdateDeviceMetadata` — `DECLARATIVE`, `MONOTONIC`, guarded by `if_version`.
///
/// Addresses and identity are **not** mutable here: addresses are immutable for
/// the device's life (S-08) and identity changes go through
/// [`rotate_credential`].
///
/// # Errors
///
/// The interim precondition code on a version mismatch; `AUTH.PEER_UNTRUSTED`
/// for an unknown device; `AUTH.QUOTA_EXCEEDED` for a label already taken —
/// uniqueness matters because the label becomes a DNS label (ADR-0011 §11.3).
pub fn update_metadata(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::UpdateDeviceMetadataRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let device_id = fixed::<32>("device_id_bytes", &req.device_id)?;

    // A device updates its own record. Anything else is a device writing another
    // device's membership row, which S-02 does not permit even to this service's
    // callers.
    if device_id != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }

    let current = tx
        .state()
        .devices
        .get(&device_id)
        .cloned()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED))?;

    check_precondition(req.precondition.as_ref(), current.version)?;

    let label = normalise_label(&req.label);
    if !label.is_empty() && tx.state().label_taken_by_other(&label, &device_id) {
        return Err(codes::bare(twinvpn_types::codes::AUTH_QUOTA_EXCEEDED));
    }

    let mut device = decode_device(&current)?;
    device.label.clone_from(&label);
    device.platform.clone_from(&req.platform);
    device.roles.clone_from(&req.declared_roles);
    device.capabilities.clone_from(&req.capabilities);
    device.protocol_version = req.protocol_version;
    device.version = current.version + 1;

    let net_seq = tx.append(&DurableEvent::new(EventBody::DeviceMetadataUpdated(
        v1::DeviceMetadataUpdated {
            device: Some(device.clone()),
        },
    ))?)?;

    let updated = DeviceRecord {
        label,
        version: device.version,
        encoded: {
            use prost::Message;
            device.encode_to_vec()
        },
        net_seq,
        ..current
    };
    tx.put_device(updated);

    let resp = v1::UpdateDeviceMetadataResponse {
        device: Some(device),
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// `RevokeDevice` — the two-signer ceremony. See the module docs.
///
/// # Errors
///
/// `AUTH.KEY_UNAVAILABLE` when no `Owner` anchor is bound (fail closed);
/// `AUTH.UNEXPECTED_DELEGATION` when the statement verified against something
/// other than the `Owner` chain; `CONTROL.QUORUM_UNAVAILABLE` when this
/// E-1-class write cannot reach quorum.
pub fn revoke(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::RevokeDeviceRequest,
) -> Result<Outcome, ServiceError> {
    require_quorum(ctx, Command::RevokeDevice)?;
    let target = fixed::<32>("device_id_bytes", &req.target_device_id)?;

    // STEP 1 — AUTHORIZE. The Owner signs; this service cannot. `SignerKey`
    // fixes the key set to the pinned OwnerTrustAnchor, `verify::admit` refuses
    // a device key before any signature arithmetic, and a control plane with no
    // anchor configured cannot revoke at all. That last one is the correct
    // failure, not a gap: admitting an unverifiable revocation would be this
    // service granting authority it does not have.
    let statement = opaque(req.revocation_statement.as_ref())?;
    let verified = verify::admit(
        ctx.verifier,
        &statement,
        StatementKind::RevocationStatement,
        ctx.now_ms,
        verify::SignerKey::OwnerAnchors,
    )?;

    // ADR-0008 N-7: re-revoking is a no-op. The revoked set never shrinks and
    // the epoch does not advance twice for one device, so a retry outside the
    // dedup window is still safe.
    if tx.state().is_revoked(&target) {
        let resp = revoke_response(&verified, tx.state().trust_epoch, 0, tx.state().trust_epoch);
        return Ok(record(&resp, 0, set_revoke_replay));
    }

    // STEP 2 — ORDER. Only now, and only under the fenced lease.
    let trust_epoch = tx.revoke(target);

    // The wrapper is built AROUND the received octets. Nothing is re-encoded:
    // W-4, and `Auth.signed_payload`'s own rule.
    let entry = v1::SignedStatement {
        cose_sign1: verified.octets.as_bytes().to_vec(),
        statement_type: v1::SignedStatementType::RevocationStatement as i32,
    };

    let net_seq = tx.append(&DurableEvent::new(EventBody::DeviceRevoked(
        v1::DeviceRevoked {
            revocation_entry: Some(entry.clone()),
            trust_epoch,
            trust_epoch_bundle: None,
        },
    ))?)?;

    // architecture.md §4.5 item 1: enforcement is at the peer. The peer set
    // event is what removes the device from every other device's cached view.
    tx.append(&DurableEvent::new(EventBody::PeerRemoved(
        v1::PeerRemoved {
            peer_device_id: target.to_vec(),
            reason_code: twinvpn_types::codes::AUTH_DEVICE_REVOKED
                .as_str()
                .to_owned(),
        },
    ))?)?;

    let resp = revoke_response(&verified, trust_epoch, net_seq, trust_epoch);
    Ok(record(&resp, net_seq, set_revoke_replay))
}

fn set_revoke_replay(m: &mut v1::RevokeDeviceResponse) {
    if let Some(r) = m.result.as_mut() {
        r.idempotent_replay = true;
    }
}

fn revoke_response(
    verified: &verify::Verified,
    trust_epoch: u64,
    net_seq: u64,
    revocation_epoch: u64,
) -> v1::RevokeDeviceResponse {
    v1::RevokeDeviceResponse {
        revocation_entry: Some(v1::SignedStatement {
            cose_sign1: verified.octets.as_bytes().to_vec(),
            statement_type: v1::SignedStatementType::RevocationStatement as i32,
        }),
        trust_epoch,
        result: Some(mutation_result(net_seq, revocation_epoch)),
        error: None,
    }
}

/// `RotateDeviceCredential` — `CEREMONY`, `MONOTONIC` per counter.
///
/// Two distinct statements with different semantics (ADR-0007 N-21):
/// `IdentitySuccession` is **dual-signed** and creates a new `DeviceIdentity` at
/// `generation + 1` without changing `device_id`; `TunnelKeyBinding` is IK-signed
/// and rotates the X25519 key without changing `DeviceIdentity`.
///
/// # Errors
///
/// The interim precondition code when a counter does not strictly advance —
/// ADR-0007 N-22 makes both monotone, and "a duplicate rotation MUST NOT create
/// a second successor identity".
pub fn rotate_credential(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::RotateDeviceCredentialRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let device_id = fixed::<32>("device_id_bytes", &req.device_id)?;
    if device_id != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }
    let current = tx
        .state()
        .devices
        .get(&device_id)
        .cloned()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED))?;

    let rotation = req
        .rotation
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;

    let (kind, statement) = match rotation {
        v1::rotate_device_credential_request::Rotation::IdentitySuccession(s) => {
            (StatementKind::IdentitySuccession, s)
        }
        v1::rotate_device_credential_request::Rotation::TunnelKeyBinding(s) => {
            (StatementKind::TunnelKeyBinding, s)
        }
    };
    let octets = opaque(Some(statement))?;
    // The device's OWN key, as this service recorded it. A rotation is a
    // device speaking about itself, so nothing else could be the signer — and
    // for an `IdentitySuccession` this is the OLD key, which is one half of
    // ADR-0007 N-21's dual signature. The NEW key's half is verified by the
    // peer that pins it; this service cannot, because it does not hold the
    // successor until this very command commits. Recorded in README.md §7.
    let signer = super::caller_key(tx, ctx)?.to_vec();
    let verified = verify::admit(
        ctx.verifier,
        &octets,
        kind,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    let mut device = decode_device(&current)?;
    let mut identity = device
        .identity
        .clone()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_IDENTITY_MISSING))?;

    let (generation, tk_generation) = if kind == StatementKind::IdentitySuccession {
        {
            let next = current.generation + 1;
            identity.generation = next;
            // N-2/N-21: the successor keeps `device_id`. Changing it would break
            // S-08's immutable allocation on every rotation.
            identity.device_id = current.device_id.to_vec();
            (next, current.tk_generation)
        }
    } else {
        {
            let next = current.tk_generation + 1;
            identity.tk_generation = next;
            identity.tunnel_key_binding = Some(v1::SignedStatement {
                cose_sign1: verified.octets.as_bytes().to_vec(),
                statement_type: v1::SignedStatementType::TunnelKeyBinding as i32,
            });
            (current.generation, next)
        }
    };

    device.identity = Some(identity.clone());
    device.version = current.version + 1;

    let net_seq = tx.append(&DurableEvent::new(EventBody::DeviceCredentialRotated(
        v1::DeviceCredentialRotated {
            device_id: device_id.to_vec(),
            rotation_statement: Some(v1::SignedStatement {
                cose_sign1: verified.octets.as_bytes().to_vec(),
                statement_type: statement.statement_type,
            }),
            identity: Some(identity.clone()),
        },
    ))?)?;

    tx.put_device(DeviceRecord {
        generation,
        tk_generation,
        version: device.version,
        encoded: {
            use prost::Message;
            device.encode_to_vec()
        },
        net_seq,
        ..current
    });

    let resp = v1::RotateDeviceCredentialResponse {
        identity: Some(identity),
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// ADR-0008 N-2's conditional write, on a `DECLARATIVE` mutation.
///
/// # Errors
///
/// The interim precondition code. A missing precondition is refused, not
/// treated as "unconditional": N-2 says *every* mutating request is conditional,
/// and an unconditional write is the lost-update the whole mechanism exists to
/// stop.
pub fn check_precondition(
    precondition: Option<&v1::VersionPrecondition>,
    current: u64,
) -> Result<(), ServiceError> {
    match precondition.and_then(|p| p.precondition.as_ref()) {
        Some(v1::version_precondition::Precondition::IfVersion(v)) if *v == current => Ok(()),
        Some(v1::version_precondition::Precondition::IfVersion(v)) => {
            Err(codes::precondition_failed(*v, current))
        }
        Some(v1::version_precondition::Precondition::IfAbsent(true)) if current == 0 => Ok(()),
        Some(v1::version_precondition::Precondition::IfAbsent(_)) => {
            Err(codes::precondition_failed(0, current))
        }
        None => Err(codes::precondition_failed(0, current)),
    }
}

/// Decodes a stored membership row back into its wire form.
fn decode_device(record: &DeviceRecord) -> Result<v1::Device, ServiceError> {
    use prost::Message;
    v1::Device::decode(record.encoded.as_slice()).map_err(|_| {
        ServiceError::from_diagnostic(twinvpn_types::Diagnostic::invariant_violated(
            crate::COMPONENT,
            "stored_device_row_does_not_decode",
        ))
    })
}

/// Whether a pairing may still be acted on. Re-exported for `pairing`.
#[must_use]
pub const fn is_actionable(state: PairingState) -> bool {
    matches!(state, PairingState::Pending)
}

#[cfg(test)]
mod tests {
    use super::check_precondition;
    use twinvpn_schema::v1;

    fn if_version(v: u64) -> v1::VersionPrecondition {
        v1::VersionPrecondition {
            precondition: Some(v1::version_precondition::Precondition::IfVersion(v)),
        }
    }

    #[test]
    fn an_unconditional_mutation_is_refused() {
        // ADR-0008 N-2: EVERY mutating request is conditional. Treating a
        // missing precondition as "unconditional" is the lost update the
        // mechanism exists to stop.
        let err = check_precondition(None, 3).expect_err("no precondition");
        assert_eq!(err.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    }

    #[test]
    fn a_stale_or_future_version_is_refused_and_the_exact_one_is_accepted() {
        assert!(check_precondition(Some(&if_version(3)), 3).is_ok());
        assert!(check_precondition(Some(&if_version(2)), 3).is_err());
        assert!(check_precondition(Some(&if_version(4)), 3).is_err());
    }

    #[test]
    fn if_absent_only_matches_absence() {
        let absent = v1::VersionPrecondition {
            precondition: Some(v1::version_precondition::Precondition::IfAbsent(true)),
        };
        assert!(check_precondition(Some(&absent), 0).is_ok());
        assert!(check_precondition(Some(&absent), 1).is_err());
    }
}
