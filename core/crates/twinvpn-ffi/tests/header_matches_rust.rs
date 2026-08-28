//! **The drift test.** `core/ffi/include/twinvpn.h` is the ABI of record; this
//! file is what stops the Rust and the header disagreeing.
//!
//! **Authority:** ADR-0018 §11.4 (adopts H — *"hand-written `twinvpn.h` as the
//! ABI of record"*), §11.12 (*"`/core/ffi/include/twinvpn.h` hand-written; the
//! ABI of record"*), F-1 (*"every exported function is a compatibility
//! obligation forever"*).
//!
//! # Why a test and not a comment
//!
//! A comment saying "keep in sync" is not a mechanism. Nothing generates the
//! header and nothing generates the Rust, which is exactly what H buys — a
//! reviewable, stable, hand-authored contract — and exactly what makes drift
//! possible. This file closes that by parsing the header text and asserting,
//! against the Rust source:
//!
//! 1. **Every declared function exists as a `#[no_mangle] extern "C"` symbol**,
//!    and every exported symbol is declared. Either direction alone would let
//!    the surface grow silently.
//! 2. **The surface stays at F-1's size.** A hard count, so adding a thirteenth
//!    function is a deliberate act with a test to update.
//! 3. **The version constants agree** — `TW_ABI_MAJOR`/`TW_ABI_MINOR` in the
//!    header, `twinvpn_core::ABI_{MAJOR,MINOR}` in Rust, and what
//!    `tw_abi_major()` actually returns at run time.
//! 4. **The vtable's entries match, in order.** F-9's `size` field makes the
//!    field ORDER load-bearing: a shell reads its own struct and the core reads
//!    the prefix the size covers, so a reordering is an ABI break that compiles
//!    cleanly on both sides.
//! 5. **The result and selector constants agree.**
//! 6. **Every `unsafe` block carries a `// SAFETY:` comment** (DP-4), and the
//!    count is pinned so a net increase is a deliberate change a security
//!    reviewer sees.

const HEADER: &str = include_str!("../../../ffi/include/twinvpn.h");
const LIB_RS: &str = include_str!("../src/lib.rs");
const VTABLE_RS: &str = include_str!("../src/vtable.rs");
const ABI_RS: &str = include_str!("../src/abi.rs");
const ENV_RS: &str = include_str!("../src/env.rs");

/// The header, with `/* … */` comments and preprocessor lines removed.
///
/// Parsing C properly is not the job; what is needed is the declarations, and a
/// comment stripper plus a `#` filter is enough to get them without a false
/// positive from a symbol NAMED in prose.
fn header_code() -> String {
    let mut out = String::with_capacity(HEADER.len());
    let bytes: Vec<char> = HEADER.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '/' && i + 1 < bytes.len() && bytes[i + 1] == '*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every function name the header declares.
///
/// Declarations are joined into `;`-terminated statements first, because three
/// of them wrap across lines and a line-oriented parse would miss exactly the
/// three most interesting entry points.
fn header_functions() -> Vec<String> {
    let code = header_code().replace(['\n', '\r'], " ");
    let mut names = Vec::new();
    for statement in code.split(';') {
        let statement = statement.trim();
        // Skip the typedefs and the vtable's own function-pointer members.
        if statement.starts_with("typedef") || statement.contains("(*") {
            continue;
        }
        let Some(open) = statement.find('(') else {
            continue;
        };
        let head = &statement[..open];
        let Some(name) = head.split_whitespace().last() else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if name.starts_with("tw_") {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Every `#[no_mangle] extern "C"` symbol the Rust exports.
fn rust_exports() -> Vec<String> {
    let mut names = Vec::new();
    let lines: Vec<&str> = LIB_RS.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.trim().starts_with("#[no_mangle]") {
            continue;
        }
        // The signature is on the next non-attribute line.
        for candidate in lines.iter().skip(i + 1).take(4) {
            let t = candidate.trim();
            if t.starts_with("#[") {
                continue;
            }
            if let Some(rest) = t.split("fn ").nth(1) {
                if let Some(name) = rest.split('(').next() {
                    names.push(name.trim().to_owned());
                }
            }
            break;
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// The vtable entry names the header declares, in order.
fn header_vtable_fields() -> Vec<String> {
    let code = header_code();
    let start = code
        .find("typedef struct tw_host_vtable {")
        .expect("the header declares tw_host_vtable");
    let end = code[start..]
        .find("} tw_host_vtable;")
        .expect("the vtable struct is closed")
        + start;
    // Join first: several entries wrap across lines.
    let joined = code[start..end].replace(['\n', '\r'], " ");
    let body = joined
        .split_once('{')
        .map_or_else(|| joined.clone(), |(_, rest)| rest.to_owned());
    let mut fields = Vec::new();
    for statement in body.split(';') {
        let t = statement.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(open) = t.find("(*") {
            let after = &t[open + 2..];
            if let Some(name) = after.split(')').next() {
                fields.push(name.trim().to_owned());
            }
        } else if let Some(last) = t.split_whitespace().last() {
            let last = last.trim_start_matches('*');
            if !last.is_empty() && !last.contains('(') && !last.contains(')') {
                fields.push(last.to_owned());
            }
        }
    }
    fields
}

/// The vtable field names the Rust struct declares, in order.
fn rust_vtable_fields() -> Vec<String> {
    let start = VTABLE_RS
        .find("pub struct TwHostVtable {")
        .expect("the Rust declares TwHostVtable");
    let end = VTABLE_RS[start..]
        .find("\n}")
        .expect("the struct is closed")
        + start;
    let body = &VTABLE_RS[start..end];
    let mut fields = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if !t.starts_with("pub ") {
            continue;
        }
        let Some(rest) = t.strip_prefix("pub ") else {
            continue;
        };
        let Some(name) = rest.split(':').next() else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() && !name.contains(' ') {
            fields.push(name.to_owned());
        }
    }
    fields
}

fn header_define(name: &str) -> String {
    for line in HEADER.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("#define ") {
            let mut parts = rest.split_whitespace();
            if parts.next() == Some(name) {
                return parts
                    .next()
                    .unwrap_or_default()
                    .trim_end_matches('u')
                    .to_owned();
            }
        }
    }
    panic!("the header does not #define {name}");
}

// ---------------------------------------------------------------------------

#[test]
fn every_declared_function_is_exported_and_every_export_is_declared() {
    let declared = header_functions();
    let exported = rust_exports();
    assert_eq!(
        declared, exported,
        "twinvpn.h and twinvpn-ffi disagree about the exported surface.\n\
         header: {declared:?}\nrust:   {exported:?}"
    );
}

#[test]
fn the_surface_is_f1_sized() {
    // F-1: "roughly a dozen functions … every exported function is a
    // compatibility obligation FOREVER". Twelve, counted, so a thirteenth is a
    // deliberate act with a test to change and a reviewer to convince.
    assert_eq!(
        header_functions().len(),
        12,
        "the ABI surface changed size: {:?}",
        header_functions()
    );
}

#[test]
fn the_abi_version_agrees_in_three_places() {
    assert_eq!(
        header_define("TW_ABI_MAJOR"),
        twinvpn_core::ABI_MAJOR.to_string(),
        "twinvpn.h and twinvpn_core::ABI_MAJOR disagree"
    );
    assert_eq!(
        header_define("TW_ABI_MINOR"),
        twinvpn_core::ABI_MINOR.to_string()
    );
    // And what the symbol actually returns, which is the value a shell reads.
    assert_eq!(twinvpn_ffi::tw_abi_major(), twinvpn_core::ABI_MAJOR);
    assert_eq!(twinvpn_ffi::tw_abi_minor(), twinvpn_core::ABI_MINOR);
}

#[test]
fn the_vtable_fields_match_in_order() {
    // F-9's `size` field makes ORDER load-bearing: the core reads the prefix the
    // declared size covers, so a reordering is an ABI break that compiles
    // cleanly on both sides and corrupts at run time.
    let header = header_vtable_fields();
    let rust = rust_vtable_fields();
    assert_eq!(
        header, rust,
        "tw_host_vtable drifted.\nheader: {header:?}\nrust:   {rust:?}"
    );
}

#[test]
fn the_result_and_selector_constants_agree() {
    assert_eq!(header_define("TW_RULESET_BLOCKED"), "0");
    assert_eq!(header_define("TW_RULESET_PROTECTED"), "1");
    assert_eq!(header_define("TW_LINK_DOWN"), "0");
    assert_eq!(header_define("TW_LINK_UP"), "1");
    assert_eq!(header_define("TW_OK"), "0");
    assert_eq!(header_define("TW_ERR"), "1");
    assert_eq!(header_define("TW_TIMEOUT"), "2");

    assert_eq!(twinvpn_ffi::vtable::TW_OK, 0);
    assert_eq!(twinvpn_ffi::vtable::TW_ERR, 1);
    assert_eq!(twinvpn_ffi::vtable::TW_TIMEOUT, 2);
    assert_eq!(twinvpn_ffi::vtable::TW_RULESET_BLOCKED, 0);
    assert_eq!(twinvpn_ffi::vtable::TW_RULESET_PROTECTED, 1);
    assert_eq!(twinvpn_ffi::vtable::TW_LINK_DOWN, 0);
    assert_eq!(twinvpn_ffi::vtable::TW_LINK_UP, 1);
}

#[test]
fn the_header_declares_no_per_packet_entry_point() {
    // PB-1: zero FFI crossings per packet, with the one exception §11.13 names —
    // `NEPacketTunnelFlow`, which is a Swift API and not this ABI. A `tw_send`
    // or `tw_recv` appearing here would be that budget quietly spent.
    let code = header_code().to_lowercase();
    for forbidden in ["tw_send", "tw_recv", "tw_packet", "tw_read", "tw_write"] {
        assert!(
            !code.contains(forbidden),
            "PB-1: `{forbidden}` would put the datapath through the ABI"
        );
    }
}

#[test]
fn the_header_declares_no_rendered_text_field() {
    // F-4 and MI-15: `resolved` is metadata, never rendered text. Adding a
    // `summary`, `message` or `title` to the ABI would place a second text
    // authority outside the registry.
    let code = header_code();
    for forbidden in ["tw_summary", "tw_message", "tw_title"] {
        assert!(!code.contains(forbidden), "CB-4/MI-15: `{forbidden}`");
    }
}

// ---------------------------------------------------------------------------
// DP-4
// ---------------------------------------------------------------------------

/// Every `unsafe {` block in this crate's **production** code.
///
/// Test code is excluded deliberately. DP-4's count exists so that a net
/// increase in the shipped `unsafe` surface reaches a security reviewer; a test
/// double that pokes a raw pointer is not part of that surface, and folding the
/// two together would make the number move for reasons nobody needs to review.
/// Every block in a test still carries its own `// SAFETY:` comment, which
/// [`all_unsafe_blocks`] checks.
fn unsafe_blocks() -> Vec<(&'static str, usize, String)> {
    all_unsafe_blocks()
        .into_iter()
        .filter(|(_, _, _)| true)
        .collect::<Vec<_>>()
        .into_iter()
        .filter(|(file, line, _)| production_line(file, *line))
        .collect()
}

/// Whether a line number falls in the file's production half.
fn production_line(file: &str, line: usize) -> bool {
    let src = source_of(file);
    let cut = src
        .split("\n#[cfg(test)]")
        .next()
        .unwrap_or(src)
        .lines()
        .count();
    line <= cut
}

fn source_of(file: &str) -> &'static str {
    match file {
        "lib.rs" => LIB_RS,
        "vtable.rs" => VTABLE_RS,
        "abi.rs" => ABI_RS,
        "env.rs" => ENV_RS,
        other => panic!("unknown source {other}"),
    }
}

/// Every `unsafe {` block anywhere in this crate, tests included.
fn all_unsafe_blocks() -> Vec<(&'static str, usize, String)> {
    let mut out = Vec::new();
    for (name, src) in [
        ("lib.rs", LIB_RS),
        ("vtable.rs", VTABLE_RS),
        ("abi.rs", ABI_RS),
        ("env.rs", ENV_RS),
    ] {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("unsafe {") {
                continue;
            }
            let preceding = lines[..i]
                .iter()
                .rev()
                .take(6)
                .map(|l| (*l).to_owned())
                .collect::<Vec<_>>()
                .join("\n");
            out.push((name, i + 1, preceding));
        }
    }
    out
}

#[test]
fn every_unsafe_block_carries_a_safety_comment() {
    // DP-4: "Every `unsafe` block carries a `// SAFETY:` comment naming its
    // invariant."
    for (file, line, preceding) in all_unsafe_blocks() {
        assert!(
            preceding.contains("SAFETY:"),
            "{file}:{line} has an `unsafe` block with no `// SAFETY:` comment"
        );
    }
}

#[test]
fn the_unsafe_block_count_is_pinned() {
    // CI counts blocks and a NET INCREASE needs a security reviewer. Pinning the
    // number here makes the increase a test failure rather than a diff nobody
    // measured. If this fails, the right response is to justify the new block in
    // review and update the number — not to raise it quietly.
    // Raised 23 -> 24 for R-3. Honouring `tw_host_vtable.size` BEFORE
    // dereferencing the struct needs two raw reads with a check between them:
    // `addr_of!((*ptr).size).read()`, the `size` comparison, then a
    // `copy_nonoverlapping` of only the declared bytes. The block it replaced
    // (`let v = unsafe { *ptr }`) read all 24 fn-pointer fields unconditionally,
    // so this is one more block covering strictly less memory.
    let count = unsafe_blocks().len();
    assert_eq!(
        count, 24,
        "the `unsafe` block count in twinvpn-ffi changed to {count}. A net increase \
         requires a security reviewer (DP-4)."
    );
}

#[test]
fn unsafe_appears_in_no_other_composition_crate() {
    // `#![forbid(unsafe_code)]` everywhere except this crate. Asserted from
    // here, over the sources this domain owns, so the property is checked by a
    // test as well as by the compiler.
    for src in [
        include_str!("../../twinvpn-core/src/lib.rs"),
        include_str!("../../twinvpn-diag/src/lib.rs"),
        include_str!("../../twinvpn-mgmt/src/lib.rs"),
    ] {
        assert!(
            src.contains("#![forbid(unsafe_code)]"),
            "a composition crate outside twinvpn-ffi is missing #![forbid(unsafe_code)]"
        );
    }
}
