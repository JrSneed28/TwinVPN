//! Route advertisements and exit-node offers: **the whole desired set, never a
//! delta**, under a monotone epoch.
//!
//! **Authority:** `docs/protocol.md` §13.1 and §13.3, §7 ("a coordination
//! service that could mint routes could redirect an `Owner`'s traffic for a
//! subnet to an attacker-controlled device"), `architecture.md` §5 rows S-16 and
//! the `ExitNode` row, ADR-0008 §11.3 (`DECLARATIVE`), ADR-0009 §5 row S-16.
//!
//! # Two properties, and they are different properties
//!
//! 1. **Whole-state.** `control_commands.proto`: named `Put`, not `Advertise`,
//!    "because it is whole-state: the request carries the complete set the
//!    advertiser wants in force, not a delta to add." A withdrawal is a
//!    **higher epoch with an empty prefix set**, so it travels through the same
//!    monotone ordering and cannot be reordered ahead of the advertisement it
//!    withdraws. [`crate::NetTx::put_route_set`] therefore *replaces*; there is
//!    no add and no remove.
//! 2. **Device-authored.** The advertiser signs. This service warehouses the
//!    received octets and publishes an event *about* them; it never authors one.
//!    [`crate::verify::StatementKind::RouteAdvertisement`] requires
//!    `SigningAuthority::Device`, so a statement that verified against the
//!    `Owner` chain — which is what a compromised control plane minting routes
//!    would produce — is refused with `AUTH.UNEXPECTED_DELEGATION`.

use twinvpn_schema::v1;
use twinvpn_service_common::forward::Verbatim;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::event::DurableEvent;
use crate::verify::{self, StatementKind};
use crate::NetTx;
use twinvpn_schema::v1::control_event::Event as EventBody;

use super::{fixed, mutation_result, record, require_not_revoked, Ctx, Outcome};

fn opaque(statement: Option<&v1::SignedStatement>) -> Result<Verbatim, ServiceError> {
    let s = statement.ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    verify::opaque_statement(bytes::Bytes::from(s.cose_sign1.clone()))
        .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))
}

/// Applies `routing.max_prefixes_per_advertisement` and the canonical-prefix
/// rule to one family's list.
///
/// A non-canonical prefix is **rejected, never normalized** — normalizing
/// attacker input is how a `10.7.0.1/24` becomes a `10.7.0.0/24` nobody
/// authorised.
fn check_prefixes(prefixes: &[v1::RoutePrefix]) -> Result<(), ServiceError> {
    twinvpn_schema::Reject::check_max(
        "routing.max_prefixes_per_advertisement",
        prefixes.len(),
        twinvpn_schema::limits::MAX_PREFIXES_PER_ADVERTISEMENT,
    )
    .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
    for p in prefixes {
        let prefix = p
            .prefix
            .as_ref()
            .ok_or_else(|| codes::bare(twinvpn_types::codes::PROTO_MALFORMED_MESSAGE))?;
        twinvpn_schema::validate::ip_prefix(prefix)
            .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
    }
    Ok(())
}

/// `PutRouteAdvertisement` — `DECLARATIVE`, monotone `advertisement_epoch`.
///
/// # Errors
///
/// `PROTO.MALFORMED_MESSAGE` past `routing.max_prefixes_per_advertisement` or on
/// a non-canonical prefix; `AUTH.PEER_UNTRUSTED` when the advertiser is not the
/// caller; the interim precondition code on a non-advancing epoch;
/// `AUTH.UNEXPECTED_DELEGATION` when the statement did not chain to a device key.
pub fn put_route(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::PutRouteAdvertisementRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let ad = req
        .advertisement
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let advertiser = fixed::<32>("device_id_bytes", &ad.advertiser_device_id)?;

    // S-16: "the advertiser is the single writer". A device advertising another
    // device's routes is the second writer I8 forbids, and it is refused here
    // rather than resolved later.
    if advertiser != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }

    // Bound the attacker-driven allocation before anything proportional to the
    // declared set size happens (ownership.md §6 rules 9 and 10). Both families
    // are validated with the same validator and the same cap: ADR-0010 R1 —
    // there is no v4 path and a separate v6 path.
    check_prefixes(&ad.prefixes_v4)?;
    check_prefixes(&ad.prefixes_v6)?;

    let octets = opaque(ad.signed.as_ref())?;
    let signer = super::caller_key(tx, ctx)?;
    let verified = verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::RouteAdvertisement,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    tx.put_route_set(
        advertiser,
        ad.advertisement_epoch,
        verified.octets.as_bytes().to_vec(),
    )?;

    // The event carries the advertisement as it arrived. N-5: independently
    // applicable — a receiver can act on it, or ignore it and re-read
    // declaratively, with no predecessor.
    let net_seq = tx.append(&DurableEvent::new(EventBody::RouteAdvertised(
        v1::RouteAdvertised {
            advertisement: Some(ad.clone()),
        },
    ))?)?;

    let resp = v1::PutRouteAdvertisementResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// `WithdrawRouteAdvertisement` — a **higher** epoch with an empty set.
///
/// # Errors
///
/// As [`put_route`].
pub fn withdraw_route(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::WithdrawRouteAdvertisementRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let advertiser = fixed::<32>("device_id_bytes", &req.advertiser_device_id)?;
    if advertiser != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }
    let octets = opaque(req.signed.as_ref())?;
    let signer = super::caller_key(tx, ctx)?;
    verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::RouteAdvertisement,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    tx.put_route_set(advertiser, req.advertisement_epoch, Vec::new())?;

    let net_seq = tx.append(&DurableEvent::new(EventBody::RouteWithdrawn(
        v1::RouteWithdrawn {
            advertiser_device_id: advertiser.to_vec(),
            advertisement_epoch: req.advertisement_epoch,
            signed: req.signed.clone(),
        },
    ))?)?;

    let resp = v1::WithdrawRouteAdvertisementResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// `PutExitNodeOffer` — `DECLARATIVE`, monotone `offer_epoch`.
///
/// # Errors
///
/// As [`put_route`], with `StatementKind::ExitNodeOffer`.
pub fn put_offer(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::PutExitNodeOfferRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let offer = req
        .offer
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let offerer = fixed::<32>("device_id_bytes", &offer.device_id)?;
    if offerer != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }
    let octets = opaque(offer.signed.as_ref())?;
    let signer = super::caller_key(tx, ctx)?;
    let verified = verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::ExitNodeOffer,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    tx.put_offer(
        offerer,
        offer.offer_epoch,
        verified.octets.as_bytes().to_vec(),
    )?;

    let net_seq = tx.append(&DurableEvent::new(EventBody::ExitNodeAdvertised(
        v1::ExitNodeAdvertised {
            offer: Some(offer.clone()),
        },
    ))?)?;

    let resp = v1::PutExitNodeOfferResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// `WithdrawExitNodeOffer` — a **higher** epoch.
///
/// # Errors
///
/// As [`put_offer`].
pub fn withdraw_offer(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::WithdrawExitNodeOfferRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let offerer = fixed::<32>("device_id_bytes", &req.device_id)?;
    if offerer != ctx.caller {
        return Err(codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED));
    }
    let octets = opaque(req.signed.as_ref())?;
    let signer = super::caller_key(tx, ctx)?;
    verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::ExitNodeOffer,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    tx.put_offer(offerer, req.offer_epoch, Vec::new())?;

    let net_seq = tx.append(&DurableEvent::new(EventBody::ExitNodeWithdrawn(
        v1::ExitNodeWithdrawn {
            device_id: offerer.to_vec(),
            offer_epoch: req.offer_epoch,
            signed: req.signed.clone(),
        },
    ))?)?;

    let resp = v1::WithdrawExitNodeOfferResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}
