//! **The drift test.** `include/twinvpn_bridge.h` is the ABI of record for this
//! boundary; this file is what stops the Rust and the header disagreeing.
//!
//! **Authority:** ADR-0018 §11.4 (a hand-written header is the ABI of record),
//! F-1 ("every exported function is a compatibility obligation forever"). Its
//! approach is `core/crates/twinvpn-ffi/tests/header_matches_rust.rs`'s, applied
//! to the smaller surface here.
//!
//! # Why a test and not a comment
//!
//! Nothing generates the header and nothing generates the Rust — which is what a
//! hand-authored contract buys, and exactly what makes drift possible. A comment
//! saying "keep in sync" is not a mechanism. This file closes it by parsing the
//! header text and asserting, against the Rust source:
//!
//! 1. every declared function exists as a `#[no_mangle] extern "C"` symbol, and
//!    every exported symbol is declared — **either direction alone** would let
//!    the surface grow silently;
//! 2. the surface stays at its declared size, as a hard count, so adding a
//!    fifteenth function is a deliberate act with a test to update;
//! 3. the version constants agree — the header's `#define`s, the Rust
//!    constants, and what `tvb_abi_major()` actually returns at run time;
//! 4. the result and family constants agree.
//!
//! Clause 3's third leg matters more than it looks: `CoreBridge.assertABI()`
//! compares the header's `TVB_ABI_MAJOR` against the **run-time** answer, so a
//! constant that agreed with the Rust source but not with the function would
//! pass a source review and fail on a Mac.

const HEADER: &str = include_str!("../include/twinvpn_bridge.h");
const LIB_RS: &str = include_str!("../src/lib.rs");

/// The header, with `/* … */` comments and preprocessor lines removed.
///
/// Parsing C properly is not the job; what is needed is the declarations, and a
/// comment stripper plus a `#` filter is enough to get them without a false
/// positive from a symbol *named in prose*.
fn header_code() -> String {
    let chars: Vec<char> = HEADER.chars().collect();
    let mut out = String::with_capacity(HEADER.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else {
            out.push(chars[i]);
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
/// Declarations are joined into `;`-terminated statements first, because several
/// of them wrap across lines and a line-oriented parse would miss exactly the
/// most interesting entry points.
fn header_functions() -> Vec<String> {
    let code = header_code().replace(['\n', '\r'], " ");
    let mut names = Vec::new();
    for statement in code.split(';') {
        let statement = statement.trim();
        // Skip the typedefs and any function-pointer member.
        if statement.starts_with("typedef") || statement.contains("(*") {
            continue;
        }
        let Some(open) = statement.find('(') else {
            continue;
        };
        let Some(name) = statement[..open].split_whitespace().last() else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if name.starts_with("tvb_") {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Every `#[no_mangle] extern "C"` symbol the Rust exports.
fn rust_exports() -> Vec<String> {
    let lines: Vec<&str> = LIB_RS.lines().collect();
    let mut names = Vec::new();
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

/// The value of a `#define`, as text.
fn header_define(name: &str) -> String {
    for line in HEADER.lines() {
        let Some(rest) = line.trim().strip_prefix("#define ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        if parts.next() == Some(name) {
            return parts
                .next()
                .unwrap_or_default()
                .trim_end_matches('u')
                .to_owned();
        }
    }
    panic!("the header does not define {name}");
}

fn header_number(name: &str) -> i64 {
    header_define(name)
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not a number"))
}

#[test]
fn every_declared_function_is_exported_and_every_export_is_declared() {
    // Either direction alone would let the surface grow silently: a declaration
    // with no symbol is a link error nobody sees until a Mac build, and a symbol
    // with no declaration is a function Swift cannot call and nobody removed.
    let declared = header_functions();
    let exported = rust_exports();
    assert_eq!(
        declared, exported,
        "the header and the Rust disagree\n  header: {declared:?}\n  rust:   {exported:?}"
    );
}

#[test]
fn the_surface_stays_the_size_f1_makes_permanent() {
    // F-1: "every exported function is a compatibility obligation forever." A
    // hard count, so a fifteenth entry point is a deliberate act with a test to
    // update rather than a diff nobody counted.
    let exported = rust_exports();
    assert_eq!(
        exported.len(),
        17,
        "the exported surface changed: {exported:?}"
    );
    for expected in [
        "tvb_abi_major",
        "tvb_abi_minor",
        "tvb_buf_bytes",
        "tvb_buf_free",
        "tvb_ext_app_message",
        "tvb_ext_free",
        "tvb_ext_inject_inbound",
        "tvb_ext_network_changed",
        "tvb_ext_next_outbound",
        "tvb_ext_next_settings",
        "tvb_ext_sleep",
        "tvb_ext_start",
        "tvb_ext_stop",
        "tvb_ext_wake",
        // Added by X-7: PS-22 moved the management interface into the system
        // extension, and ADR-0017 11.2's macOS row serves it over XPC with an
        // `audit_token_t`. Three entries, because a session has a lifetime:
        // open with a principal, exchange messages, close.
        "tvb_mgmt_close",
        "tvb_mgmt_exchange",
        "tvb_mgmt_open",
    ] {
        assert!(
            exported.iter().any(|e| e == expected),
            "{expected} is no longer exported"
        );
    }
}

#[test]
fn the_version_constants_agree_in_the_header_the_source_and_at_run_time() {
    // The third leg is the one a source review cannot do: `CoreBridge.assertABI`
    // compares the header's `#define` against the RUN-TIME answer, so a
    // constant that agreed with the source but not the function would pass
    // review and fail on a Mac.
    assert_eq!(header_number("TVB_ABI_MAJOR"), 1);
    assert_eq!(header_number("TVB_ABI_MINOR"), 0);
    assert_eq!(
        header_number("TVB_ABI_MAJOR"),
        i64::from(twinvpn_bridge::TVB_ABI_MAJOR)
    );
    assert_eq!(
        header_number("TVB_ABI_MINOR"),
        i64::from(twinvpn_bridge::TVB_ABI_MINOR)
    );
    assert_eq!(
        header_number("TVB_ABI_MAJOR"),
        i64::from(twinvpn_bridge::tvb_abi_major())
    );
    assert_eq!(
        header_number("TVB_ABI_MINOR"),
        i64::from(twinvpn_bridge::tvb_abi_minor())
    );
}

#[test]
fn the_result_and_family_constants_agree() {
    assert_eq!(header_number("TVB_OK"), i64::from(twinvpn_bridge::TVB_OK));
    assert_eq!(header_number("TVB_ERR"), i64::from(twinvpn_bridge::TVB_ERR));
    assert_eq!(
        header_number("TVB_TIMEOUT"),
        i64::from(twinvpn_bridge::TVB_TIMEOUT)
    );
    assert_eq!(
        header_number("TVB_FAMILY_V4"),
        i64::from(twinvpn_bridge::ext::FAMILY_V4)
    );
    assert_eq!(
        header_number("TVB_FAMILY_V6"),
        i64::from(twinvpn_bridge::ext::FAMILY_V6)
    );
}

#[test]
fn the_family_constants_are_not_the_platforms_address_families() {
    // 4 and 6, deliberately. `AF_INET6` is 30 on Darwin and 10 on Linux, so a
    // constant taken from either would be wrong in exactly the tests meant to
    // check the other.
    assert_ne!(
        header_number("TVB_FAMILY_V6"),
        30,
        "that is Darwin's AF_INET6"
    );
    assert_ne!(
        header_number("TVB_FAMILY_V6"),
        10,
        "that is Linux's AF_INET6"
    );
    assert_ne!(header_number("TVB_FAMILY_V4"), 2, "that is AF_INET");
}

#[test]
fn the_header_documents_the_null_slice_shape_the_swift_side_produces() {
    // The one shape a naive `from_raw_parts` gets wrong, and the one the Swift
    // side produces on every empty argument. If this sentence is ever deleted,
    // the reason the Rust checks for it goes with it.
    assert!(
        HEADER.contains("MAY BE NULL WHEN `len` IS ZERO"),
        "the header no longer documents the empty-slice contract"
    );
    assert!(HEADER.contains("MAY BE NULL WHEN `len` IS ZERO"));
}

#[test]
fn the_header_declares_no_callback_into_swift() {
    // F-9's reasoning, applied here: handing the OS a pointer into Rust would
    // let a notification arrive on an arbitrary thread while a mutating call is
    // in flight. The two blocking readers are how Swift learns about work.
    let code = header_code();
    assert!(
        !code.contains("(*"),
        "the header declares a function pointer, which this ABI does not have"
    );
}
