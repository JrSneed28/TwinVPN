//! Forward-verbatim: carrying a message through a hop without losing what this
//! build does not understand.
//!
//! **Authority:** ADR-0003 §11 B1 (unknown fields MUST be **preserved and
//! forwarded**), `contracts/docs/phase1-conflicts.md` CF-2, `core/README.md` §8
//! and `twinvpn-schema`'s measured
//! `unknown_fields_are_dropped_by_prost_0_13`.
//!
//! # The trap this module exists to close
//!
//! `prost` 0.13 **discards unknown fields on decode and cannot re-emit them.**
//! `core-foundation` measured it rather than assuming it. CF-2 states the
//! consequence:
//!
//! > Any language chosen for a component that *forwards* a message it does not
//! > fully understand — the coordination service, the rendezvous, a relay
//! > carrying an opaque `CALL` — must use a runtime with preserve-and-forward.
//!
//! Rust with `prost` is not such a runtime. So the forwarding rule cannot be
//! "use a preserving runtime"; it has to be **"do not decode-then-re-encode"**.
//! Three of the four server domains forward: the control plane relays events it
//! did not author, the rendezvous carries an opaque `CALL` body, and a relay
//! carries a leg it must never interpret. Each rediscovering this independently
//! is the R-31 divergence this crate exists to prevent, and two of the three
//! would rediscover it as a compatibility bug in production rather than as a
//! constraint at design time.
//!
//! # The shape of the fix
//!
//! [`Verbatim`] holds the **exact received octets**. [`Forwarded`] pairs those
//! octets with a decoded *view* used only for inspection — routing, authorising,
//! counting — and forwards the octets, never the view.
//!
//! There is deliberately no `view_mut()` and no `encode()`. The one way to
//! produce different bytes is
//! [`Forwarded::rewrite_dropping_unknown_fields`], whose name is the
//! documentation: calling it is a decision to discard everything this build does
//! not know about, and a reviewer sees it at the call site.
//!
//! This is the same rule `Auth.signed_payload` already states — "the verifier
//! MUST verify over the exact received octets of `signed_payload` and MUST NOT
//! re-serialize" — generalised from one field to any forwarded message.
//!
//! # Two framings, because B4 has none
//!
//! The first version of this module applied `twinvpn_schema::depth::check` to
//! every `Verbatim`. That was wrong for one consumer and wrong in a way that
//! mattered more than an API mismatch. `depth::check` is a **protobuf record
//! scan**; a relay `DATA` payload is an unmodified WireGuard L-DATA datagram —
//! AEAD ciphertext with a fixed binary header (ADR-0001 §11, ADR-0005 C2) — so
//! `Verbatim` rejected essentially all real relay traffic. `relay-plane`
//! measured it.
//!
//! The deeper defect is that requiring the bytes to parse as protobuf put a
//! protobuf parser on the **B4 packet path**, which ADR-0003 R7 forbids
//! outright:
//!
//! > B4 MUST have **zero** serialization framework in the packet path.
//!
//! and §11's table restates as a property, not a preference:
//!
//! > **No serialization framework.** … A serialization library MUST NOT appear
//! > in the packet path. Relay framing is a length + opaque-bytes header only.
//!
//! `contracts/README.md` records *why* that is worth a rule: B4's schema
//! artifact is "**absent by design**", so "the highest-rate path is immune to
//! serialization bugs by construction". A primitive that quietly reintroduced
//! the parser would have removed that immunity while looking like the safe
//! choice — which is worse than an obvious mistake, because nothing fails until
//! it is a packet-path bug.
//!
//! So [`Verbatim`] carries a [`Framing`], and the two constructors say which:
//!
//! | Constructor | [`Framing`] | Checks applied | Belongs on |
//! |---|---|---|---|
//! | [`Verbatim::from_received`] | `ProtobufRecords` | size cap **and** depth cap | B1 (C1/C2/C7), B3 (C4) |
//! | [`Verbatim::from_opaque`] | `Opaque` | size cap **only** | B4 (C5/C6) and any ciphertext leg |
//!
//! `from_received` keeps its name, its signature and its behaviour, so the
//! control plane and the rendezvous cannot silently lose the depth guard by
//! anyone's inaction. The opaque mode is a differently named constructor rather
//! than a boolean parameter, because `from_received(bytes, channel, false)` at a
//! call site tells a reviewer nothing and `from_opaque(bytes, channel)` tells
//! them everything.
//!
//! **A `Channel` variant would have been the other reasonable shape**, and it is
//! not available here: `Channel` lives in `twinvpn-schema`, is owned by
//! `core-foundation`, and enumerates the two envelope **cap families** of
//! `limits.json` — it is a bounds selector, not a framing selector, and B4 has no
//! entry in `limits.json` to add. Framing is therefore a `twinvpn-service-common`
//! concept, declared here.
//!

use bytes::Bytes;
use twinvpn_schema::{depth, Channel, Reject};

/// What structure, if any, the carried octets are assumed to have.
///
/// This is the ADR-0003 §11 boundary class expressed as a type. It selects the
/// *checks*, not the bounds — the byte cap comes from [`Channel`] either way,
/// because an attacker-driven allocation must be bounded on every boundary
/// (`ownership.md` §6 rules 9 and 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framing {
    /// **B1 and B3.** A length-delimited protobuf record sequence.
    ///
    /// The nesting-depth cap of `limits.json` applies and is enforced on the raw
    /// octets before `prost` allocates or recurses (ADR-0003 §11: "Depth limit 8,
    /// size limit 64 KiB, enforced before parse"; C4 gets 4 and 1200 B, "the
    /// smallest safe parser on a pre-authentication, attacker-reachable path").
    ProtobufRecords,

    /// **B4, and any ciphertext leg.** No structure at all.
    ///
    /// ADR-0003 R7: "B4 MUST have **zero** serialization framework in the packet
    /// path." No record scan runs, because there is no record sequence and
    /// because running one would be the violation. A relay forwarding a WireGuard
    /// L-DATA datagram must not be able to say anything about its contents — that
    /// is I1 in the code as well as in the crypto (`twinvpn-crypto` gives a relay
    /// no decrypt operation; this gives it no parser).
    Opaque,
}

impl Framing {
    /// A stable token, for a `Debug` rendering and for evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Framing::ProtobufRecords => "protobuf_records",
            Framing::Opaque => "opaque",
        }
    }

    /// Whether this framing runs the nesting-depth scan.
    #[must_use]
    pub const fn checks_depth(self) -> bool {
        matches!(self, Framing::ProtobufRecords)
    }
}

/// The exact octets a message arrived as.
///
/// Built through [`Verbatim::from_received`] (B1/B3, size **and** depth) or
/// [`Verbatim::from_opaque`] (B4, size only). Either way the byte cap is applied
/// **before** anything proportional to a declared length is allocated
/// (`ownership.md` §6 rules 9 and 10). `Bytes` is reference-counted, so
/// forwarding through several hops copies nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Verbatim {
    bytes: Bytes,
    channel: Channel,
    framing: Framing,
}

impl Verbatim {
    /// Validates and retains `bytes` as a **protobuf record sequence**.
    ///
    /// The B1/B3 constructor, and the default: applying the depth cap is the
    /// behaviour a control-plane or rendezvous forwarder must not lose by
    /// accident, so it keeps the unqualified name. For a ciphertext leg or
    /// anything else with no structure, use [`Verbatim::from_opaque`].
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`] or [`Reject::DepthExceeded`], each carrying the
    /// `limits.json` bound it violated. Never a truncation, never a pad.
    pub fn from_received(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        Self::with_framing(bytes, channel, Framing::ProtobufRecords)
    }

    /// Bounds and retains `bytes` with **no structural assumption whatsoever**.
    ///
    /// The B4 constructor. The only check is `channel`'s byte cap; no record
    /// scan, no depth check, no framework — ADR-0003 R7 puts zero serialization
    /// machinery on the packet path, and `contracts/README.md` records the
    /// consequence that makes it worth a rule: "the highest-rate path is immune
    /// to serialization bugs by construction".
    ///
    /// Use this for a relay `DATA` payload (an unmodified WireGuard L-DATA
    /// datagram), for a COSE_Sign1 `signed_payload` being carried rather than
    /// verified, and for anything else whose bytes this process is not entitled
    /// to interpret.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`] only, carrying the `limits.json` bound it
    /// violated. Never a truncation, never a pad.
    pub fn from_opaque(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        Self::with_framing(bytes, channel, Framing::Opaque)
    }

    /// The general form, for a caller whose framing is genuinely a runtime value.
    ///
    /// Prefer [`Verbatim::from_received`] or [`Verbatim::from_opaque`] at a fixed
    /// call site: a named constructor is legible in a diff and a `Framing` held in
    /// a variable is not.
    ///
    /// # Errors
    ///
    /// As the constructor the `framing` selects.
    pub fn with_framing(bytes: Bytes, channel: Channel, framing: Framing) -> Result<Self, Reject> {
        // The size cap first and always. It is the bound that stops an
        // attacker-driven allocation, and it is the only check B4 gets.
        let limit = channel.max_bytes();
        if bytes.len() > limit {
            return Err(Reject::SizeExceeded {
                parser_id: channel.parser_id(),
                observed: bytes.len(),
                limit,
            });
        }
        if framing.checks_depth() {
            depth::check(&bytes, channel)?;
        }
        Ok(Self {
            bytes,
            channel,
            framing,
        })
    }

    /// The octets, unchanged.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The octets, cheaply cloned for the next hop.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    /// Consumes the wrapper, yielding the octets.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// The channel whose caps were applied.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// Which framing discipline this value was built under.
    ///
    /// Worth asking now that there are two: it answers "was this depth-checked,
    /// or is it opaque octets?" without reading the bytes.
    #[must_use]
    pub const fn framing(&self) -> Framing {
        self.framing
    }

    /// The length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the message is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for Verbatim {
    /// Length, channel and framing. **Never the octets.**
    ///
    /// The octets of a forwarded message are, by construction, content this
    /// process is not entitled to interpret — a relay's leg is ciphertext (I1),
    /// a rendezvous `CALL` body is opaque. Rendering them would be exactly the
    /// payload capture ADR-0015 O-12 forbids.
    ///
    /// The framing token is metadata about the container, not about the content,
    /// and it is the one question a reader of a log now has that they did not
    /// have before: which discipline did this value go through.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Verbatim({} B on {}, {}, <not rendered>)",
            self.bytes.len(),
            self.channel.parser_id(),
            self.framing.as_str()
        )
    }
}

/// A message decoded **for inspection** while its original octets are retained
/// for forwarding.
///
/// ```text
///   received octets ──┬──▶ decode ──▶ view()   inspect: route, authorise, count
///                     └────────────────────────▶ forward()   the ORIGINAL octets
/// ```
#[derive(Clone)]
pub struct Forwarded<M> {
    verbatim: Verbatim,
    view: M,
}

impl<M: prost::Message + Default> Forwarded<M> {
    /// Validates, retains and decodes.
    ///
    /// The caps are applied to the raw octets first, so a hostile declared length
    /// never reaches `prost`.
    ///
    /// Always [`Framing::ProtobufRecords`]: this type exists to hold a decoded
    /// *view*, so there is nothing it could mean on a B4 payload. A component
    /// carrying opaque octets holds a [`Verbatim`] from
    /// [`Verbatim::from_opaque`] and no view at all — which is the stronger
    /// position, not a lesser one.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`], [`Reject::DepthExceeded`] or
    /// [`Reject::Unparseable`].
    pub fn decode(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        let verbatim = Verbatim::from_received(bytes, channel)?;
        let view = M::decode(verbatim.as_bytes()).map_err(|_| Reject::Unparseable {
            parser_id: channel.parser_id(),
        })?;
        Ok(Self { verbatim, view })
    }

    /// The decoded view.
    ///
    /// **Advisory.** It is missing every field this build does not know about.
    /// Read it to decide *what to do*; never to decide *what to send*.
    #[must_use]
    pub const fn view(&self) -> &M {
        &self.view
    }

    /// The original octets.
    #[must_use]
    pub const fn verbatim(&self) -> &Verbatim {
        &self.verbatim
    }

    /// The octets to put on the next hop: **the ones that arrived**.
    #[must_use]
    pub fn forward(&self) -> Bytes {
        self.verbatim.to_bytes()
    }

    /// Consumes the wrapper, yielding the octets to forward.
    #[must_use]
    pub fn into_forwarded(self) -> Bytes {
        self.verbatim.into_bytes()
    }

    /// Re-encodes after mutating the view, **discarding every field this build
    /// does not understand**.
    ///
    /// The name is the whole point. ADR-0003 §11 B1 requires unknown fields to
    /// be preserved and forwarded; `prost` 0.13 cannot, so a component that
    /// genuinely must alter a message it forwards is choosing to break that
    /// requirement for this message. That is sometimes correct — a control plane
    /// re-authoring an event it owns is not forwarding, it is originating — and
    /// it is never accidental.
    ///
    /// Prefer originating a fresh message over rewriting a received one.
    #[must_use]
    pub fn rewrite_dropping_unknown_fields(mut self, f: impl FnOnce(&mut M)) -> Bytes {
        f(&mut self.view);
        Bytes::from(self.view.encode_to_vec())
    }
}

impl<M> std::fmt::Debug for Forwarded<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarded")
            .field("verbatim", &self.verbatim)
            .finish_non_exhaustive()
    }
}
