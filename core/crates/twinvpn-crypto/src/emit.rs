//! Emitting deterministic CBOR, for the statements a device **authors**.
//!
//! **Authority:** RFC 8949 §4.2.1, RFC 9052 §4.4 (`Sig_structure`),
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl` encoding rules 1 and 2,
//! ADR-0018 CB-5 (the signature itself is a vtable call).
//!
//! # Why this exists and why it is a separate type system
//!
//! A device authors five of the seventeen statement types — its
//! `DeviceIdentityRecord`, its `TunnelKeyBinding`, its half of a
//! `PairingAttestation`, its `RouteAdvertisement`, its `ExitNodeOffer` — so an
//! encoder is unavoidable. The danger an encoder introduces is the one
//! `signed_statements.cddl` names: re-serializing something that arrived and
//! verifying *that*.
//!
//! The mechanism against it is that **[`Item`] and [`crate::dcbor::Value`] are
//! unrelated types with no conversion in either direction**. A received
//! statement decodes to a `Value`; the encoder consumes `Item`s; there is no
//! `From`, no `TryFrom`, and no method that bridges them. So the round trip
//! "decode what arrived → re-encode it → verify the re-encoding" is not
//! expressible, rather than merely discouraged.
//!
//! # The signature is not here
//!
//! CB-5 row 1: the identity key never reaches the core. [`StatementToSign`]
//! produces the exact `Sig_structure` octets to hand to
//! `IdentityCustody::identity_sign`, and [`assemble_cose_sign1`] puts the
//! returned signature back into an envelope. No signing key is named anywhere in
//! this module, and there is nowhere to put one.

use crate::{CryptoError, Result};

/// A value the emitter can write.
///
/// Deliberately **not** convertible from [`crate::dcbor::Value`]. See the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Major type 0.
    Uint(u64),
    /// Major type 1, written as `-1 - n` for the `n` given.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Item>),
    /// Major type 5. Keys are sorted by their encodings on emission, so a caller
    /// cannot produce a non-canonical map by listing entries out of order.
    Map(Vec<(Item, Item)>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
}

/// Encodes `item` as RFC 8949 §4.2.1 core deterministic CBOR.
///
/// Map entries are sorted by their encoded keys and a duplicate key is a
/// refusal, not a last-writer-wins.
///
/// # Errors
///
/// [`CryptoError::DerivationFailed`] if a map carries duplicate keys — a caller
/// defect, since every statement's key set is a `const` in this crate.
pub fn encode(item: &Item) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_item(item, &mut out)?;
    Ok(out)
}

fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg < 24 {
        // `arg < 24` fits a `u8` by inspection.
        out.push(m | u8::try_from(arg).unwrap_or(0));
    } else if u8::try_from(arg).is_ok() {
        out.push(m | 24);
        out.push(u8::try_from(arg).unwrap_or(0));
    } else if u16::try_from(arg).is_ok() {
        out.push(m | 25);
        out.extend_from_slice(&u16::try_from(arg).unwrap_or(0).to_be_bytes());
    } else if u32::try_from(arg).is_ok() {
        out.push(m | 26);
        out.extend_from_slice(&u32::try_from(arg).unwrap_or(0).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn write_item(item: &Item, out: &mut Vec<u8>) -> Result<()> {
    match item {
        Item::Uint(v) => write_head(0, *v, out),
        Item::Nint(v) => write_head(1, *v, out),
        Item::Bytes(b) => {
            write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Item::Text(t) => {
            write_head(3, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        Item::Array(a) => {
            write_head(4, a.len() as u64, out);
            for e in a {
                write_item(e, out)?;
            }
        }
        Item::Map(entries) => {
            write_head(5, entries.len() as u64, out);
            // §4.2.1 (c): sort by the encoded key, not by the logical key. For
            // integer labels the two orders coincide only because CBOR's
            // encoding is length-then-value for the ranges the CDDL uses; doing
            // it on the encodings is correct for every label shape.
            let mut encoded: Vec<(Vec<u8>, &Item)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kb = Vec::new();
                write_item(k, &mut kb)?;
                encoded.push((kb, v));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            for w in encoded.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(CryptoError::DerivationFailed {
                        invariant: "a deterministic CBOR map has no duplicate keys",
                    });
                }
            }
            for (kb, v) in encoded {
                out.extend_from_slice(&kb);
                write_item(v, out)?;
            }
        }
        Item::Bool(false) => out.push(0xf4),
        Item::Bool(true) => out.push(0xf5),
        Item::Null => out.push(0xf6),
    }
    Ok(())
}

/// A statement payload, its protected header, and the exact octets to sign.
///
/// The three are produced together so a caller cannot sign one protected header
/// and ship another — which would be a signature over bytes nobody will verify.
#[derive(Debug, Clone)]
pub struct StatementToSign {
    protected: Vec<u8>,
    payload: Vec<u8>,
    to_be_signed: Vec<u8>,
}

impl StatementToSign {
    /// Builds the payload, the protected header and the `Sig_structure`.
    ///
    /// `alg` is a COSE algorithm value (`-7` for ES256); `kid` is the optional
    /// key identifier. Both go in the **protected** header, because an
    /// unprotected `alg` is not covered by the signature.
    ///
    /// # Errors
    ///
    /// As [`encode`].
    pub fn new(payload: &Item, alg: i64, kid: Option<&[u8]>) -> Result<Self> {
        let payload = encode(payload)?;
        let mut hdr: Vec<(Item, Item)> = vec![(Item::Uint(1), int_item(alg))];
        if let Some(k) = kid {
            hdr.push((Item::Uint(4), Item::Bytes(k.to_vec())));
        }
        let protected = encode(&Item::Map(hdr))?;
        // RFC 9052 §4.4:
        //   Sig_structure = [ "Signature1", body_protected, external_aad, payload ]
        let to_be_signed = encode(&Item::Array(vec![
            Item::Text("Signature1".to_owned()),
            Item::Bytes(protected.clone()),
            Item::Bytes(Vec::new()),
            Item::Bytes(payload.clone()),
        ]))?;
        Ok(Self {
            protected,
            payload,
            to_be_signed,
        })
    }

    /// The octets to hand to `IdentityCustody::identity_sign`.
    #[must_use]
    pub fn to_be_signed(&self) -> &[u8] {
        &self.to_be_signed
    }

    /// The encoded payload, for a caller that needs its digest.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Assembles the COSE_Sign1 wire octets around a signature produced
    /// elsewhere.
    ///
    /// # Errors
    ///
    /// As [`encode`].
    pub fn assemble(&self, signature: &[u8]) -> Result<Vec<u8>> {
        encode(&Item::Array(vec![
            Item::Bytes(self.protected.clone()),
            Item::Map(Vec::new()),
            Item::Bytes(self.payload.clone()),
            Item::Bytes(signature.to_vec()),
        ]))
    }
}

/// Assembles a COSE_Sign1 from its four parts.
///
/// A thin alias for [`StatementToSign::assemble`], for a caller that already
/// holds a [`StatementToSign`].
///
/// # Errors
///
/// As [`encode`].
pub fn assemble_cose_sign1(unsigned: &StatementToSign, signature: &[u8]) -> Result<Vec<u8>> {
    unsigned.assemble(signature)
}

/// A signed or unsigned integer as an [`Item`].
#[must_use]
pub fn int_item(v: i64) -> Item {
    if v >= 0 {
        Item::Uint(u64::try_from(v).unwrap_or(0))
    } else {
        // -1 - n = v  =>  n = -1 - v, computed without overflowing at i64::MIN.
        Item::Nint(u64::try_from(-(v + 1)).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcbor;

    /// The emitter's output must be accepted by the strict parser. This is the
    /// property that makes the two halves one implementation of one spec rather
    /// than two implementations that happen to agree today.
    #[test]
    fn everything_this_module_emits_parses_as_canonical() {
        let item = Item::Map(vec![
            (Item::Uint(3), Item::Text("x".to_owned())),
            (Item::Uint(1), Item::Uint(2)),
            (
                Item::Uint(300),
                Item::Array(vec![Item::Bool(true), Item::Null]),
            ),
            (Item::Nint(0), Item::Bytes(vec![1, 2, 3])),
        ]);
        let bytes = encode(&item).expect("encode");
        let parsed = dcbor::parse_canonical(&bytes).expect("must be canonical");
        assert_eq!(parsed.map_get(1).and_then(dcbor::Value::as_uint), Some(2));
        assert_eq!(parsed.map_keys(), vec![1, 3, 300]);
    }

    /// The emitter sorts, so a caller cannot produce non-canonical output by
    /// listing map entries in the wrong order.
    #[test]
    fn map_entries_are_sorted_on_emission_regardless_of_the_order_given() {
        let a = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(0)),
            (Item::Uint(2), Item::Uint(0)),
        ]))
        .expect("a");
        let b = encode(&Item::Map(vec![
            (Item::Uint(2), Item::Uint(0)),
            (Item::Uint(1), Item::Uint(0)),
        ]))
        .expect("b");
        assert_eq!(a, b);
        assert!(dcbor::parse_canonical(&a).is_ok());
    }

    #[test]
    fn a_duplicate_map_key_is_refused_rather_than_last_writer_wins() {
        let err = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(0)),
            (Item::Uint(1), Item::Uint(9)),
        ]))
        .expect_err("must refuse");
        assert!(matches!(err, CryptoError::DerivationFailed { .. }));
    }

    #[test]
    fn integer_heads_use_the_shortest_form() {
        assert_eq!(encode(&Item::Uint(0)).unwrap(), vec![0x00]);
        assert_eq!(encode(&Item::Uint(23)).unwrap(), vec![0x17]);
        assert_eq!(encode(&Item::Uint(24)).unwrap(), vec![0x18, 0x18]);
        assert_eq!(encode(&Item::Uint(255)).unwrap(), vec![0x18, 0xff]);
        assert_eq!(encode(&Item::Uint(256)).unwrap(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            encode(&Item::Uint(65_536)).unwrap(),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn int_item_maps_negatives_onto_major_type_one() {
        assert_eq!(int_item(-1), Item::Nint(0));
        assert_eq!(int_item(-7), Item::Nint(6));
        assert_eq!(int_item(0), Item::Uint(0));
        assert_eq!(encode(&int_item(-1)).unwrap(), vec![0x20]);
        assert_eq!(encode(&int_item(-7)).unwrap(), vec![0x26]);
    }

    #[test]
    fn the_sig_structure_is_the_rfc_9052_four_element_array() {
        let sts = StatementToSign::new(&Item::Map(vec![(Item::Uint(1), Item::Uint(2))]), -7, None)
            .expect("build");
        let parsed = dcbor::parse_canonical(sts.to_be_signed()).expect("canonical");
        let arr = parsed.as_array().expect("array");
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0].as_text(), Some("Signature1"));
        assert_eq!(arr[2].as_bytes(), Some(&[][..]));
        assert_eq!(arr[3].as_bytes(), Some(sts.payload()));
    }

    /// The protected header carries `alg`, so a rewrite of it invalidates the
    /// signature rather than selecting a different algorithm.
    #[test]
    fn alg_and_kid_go_in_the_protected_header() {
        let sts = StatementToSign::new(&Item::Uint(1), -7, Some(b"k1")).expect("build");
        let parsed = dcbor::parse_canonical(sts.to_be_signed()).expect("canonical");
        let protected = parsed.as_array().unwrap()[1].as_bytes().unwrap();
        let hdr = dcbor::parse_canonical(protected).expect("canonical header");
        assert_eq!(hdr.map_get(1), Some(&dcbor::Value::Nint(6))); // alg = -7
        assert_eq!(
            hdr.map_get(4).and_then(dcbor::Value::as_bytes),
            Some(&b"k1"[..])
        );
    }
}
