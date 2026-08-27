//! The nesting-depth guard, run **before** `prost` sees the bytes.
//!
//! **Authority:** ADR-0003 §11 and `contracts/registry/limits.json`
//! `envelope.c1_c2_c7_max_depth` (8) and `envelope.c4_max_depth` (4).
//!
//! # Why this exists at all
//!
//! `prost` decodes nested messages by recursion, so a deeply nested input is a
//! stack-exhaustion vector, and depth is not a limit `prost` exposes. The guard
//! therefore runs first, over the raw bytes, and it is **iterative** — its own
//! stack is a `Vec` bounded by `max_depth + 1` entries — so the guard itself
//! cannot be the thing that overflows.
//!
//! It also allocates nothing proportional to a declared length: it reads
//! varints and skips, never copying a field's contents.
//!
//! # The one honest imprecision
//!
//! Protobuf's wire format gives `bytes`, `string`, and a nested message the
//! **same** wire type (2, length-delimited). Nothing in the encoding distinguishes
//! them, so no scanner can. This one recurses into a length-delimited field only
//! when its contents parse **exactly** as a sequence of well-formed records that
//! consume the length precisely — which makes it a conservative
//! *over*-approximation: a `bytes` field whose contents happen to look like a
//! message counts toward depth.
//!
//! That errs toward rejecting, which is the safe direction, and the margin is
//! wide: the deepest real message in `contracts/` nests about four levels against
//! a cap of eight, so a false reject on C1/C2/C7 needs nine levels of
//! coincidentally message-shaped bytes. The case worth naming is
//! `Auth.signed_payload`, which is deliberately opaque deterministic CBOR; CBOR's
//! major types do not encode as valid protobuf records at any useful rate, and
//! `signed_payload_of_opaque_cbor_is_not_counted_as_deep_nesting` pins it.
//!
//! Stated rather than hidden, because a validator whose imprecision is
//! undocumented is one somebody will eventually debug the hard way.

use crate::limits::Channel;
use crate::reject::Reject;

/// Rejects `bytes` if its nesting exceeds `channel`'s depth cap.
///
/// # Errors
///
/// [`Reject::DepthExceeded`] past the cap; [`Reject::Unparseable`] if the bytes
/// are not a well-formed record sequence at the top level.
pub fn check(bytes: &[u8], channel: Channel) -> Result<(), Reject> {
    let limit = channel.max_depth();
    let observed = scan(bytes, limit);
    match observed {
        Scan::Depth(d) if d <= limit => Ok(()),
        Scan::Depth(d) => Err(Reject::DepthExceeded {
            parser_id: channel.parser_id(),
            observed: d,
            limit,
        }),
        Scan::TooDeep => Err(Reject::DepthExceeded {
            parser_id: channel.parser_id(),
            observed: limit + 1,
            limit,
        }),
        Scan::NotAMessage => Err(Reject::Unparseable {
            parser_id: channel.parser_id(),
        }),
    }
}

enum Scan {
    Depth(usize),
    TooDeep,
    NotAMessage,
}

/// One nesting level being walked.
struct Frame<'a> {
    body: &'a [u8],
    pos: usize,
}

/// Walks the record structure iteratively, stopping as soon as the depth cap is
/// exceeded.
fn scan(bytes: &[u8], limit: usize) -> Scan {
    if bytes.is_empty() {
        // An empty message is depth 1 and perfectly legal — every field of a
        // proto3 message is optional.
        return Scan::Depth(1);
    }
    if !is_record_sequence(bytes) {
        return Scan::NotAMessage;
    }

    // Bounded by `limit + 1`: the walk stops the moment it would exceed the cap,
    // so this can never grow past the cap plus the frame that broke it.
    let mut stack: Vec<Frame<'_>> = Vec::with_capacity(limit + 1);
    stack.push(Frame {
        body: bytes,
        pos: 0,
    });
    let mut deepest = 1usize;

    while let Some(frame) = stack.last_mut() {
        if frame.pos >= frame.body.len() {
            stack.pop();
            continue;
        }
        let Some((_, wire_type, value, next)) = read_record(frame.body, frame.pos) else {
            // Already validated by `is_record_sequence` at every level we push,
            // so this is unreachable; popping keeps it total rather than
            // panicking on a case that should not arise.
            stack.pop();
            continue;
        };
        frame.pos = next;
        if wire_type == 2 && is_record_sequence(value) && !value.is_empty() {
            if stack.len() + 1 > limit {
                return Scan::TooDeep;
            }
            deepest = deepest.max(stack.len() + 1);
            stack.push(Frame {
                body: value,
                pos: 0,
            });
        }
    }
    Scan::Depth(deepest)
}

/// Whether `bytes` is a well-formed sequence of protobuf records that consumes
/// its length exactly.
fn is_record_sequence(bytes: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < bytes.len() {
        match read_record(bytes, pos) {
            Some((_, _, _, next)) => pos = next,
            None => return false,
        }
    }
    pos == bytes.len()
}

/// Reads one record at `pos`, returning `(field_number, wire_type, value, next)`.
///
/// `value` is the length-delimited payload for wire type 2 and an empty slice
/// otherwise. Returns `None` on any malformation, including a length that runs
/// past the end — the check that keeps a declared length from driving a read.
fn read_record(bytes: &[u8], pos: usize) -> Option<(u64, u8, &[u8], usize)> {
    let (tag, mut pos) = read_varint(bytes, pos)?;
    let wire_type = u8::try_from(tag & 0x07).ok()?;
    let field_number = tag >> 3;
    if field_number == 0 {
        return None;
    }
    match wire_type {
        0 => {
            let (_, next) = read_varint(bytes, pos)?;
            Some((field_number, 0, &[], next))
        }
        1 => {
            pos = pos.checked_add(8)?;
            (pos <= bytes.len()).then_some((field_number, 1, &[], pos))
        }
        5 => {
            pos = pos.checked_add(4)?;
            (pos <= bytes.len()).then_some((field_number, 5, &[], pos))
        }
        2 => {
            let (len, after_len) = read_varint(bytes, pos)?;
            let len = usize::try_from(len).ok()?;
            let end = after_len.checked_add(len)?;
            // The declared length is checked against what is actually present
            // BEFORE the slice is taken. This is the read equivalent of
            // ownership.md §6 rule 9.
            if end > bytes.len() {
                return None;
            }
            Some((field_number, 2, &bytes[after_len..end], end))
        }
        // 3 and 4 are the removed group wire types; 6 and 7 are undefined.
        _ => None,
    }
}

/// Reads a base-128 varint, rejecting one longer than ten bytes.
fn read_varint(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let b = *bytes.get(pos)?;
        pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}
