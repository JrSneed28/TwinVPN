//! **M-18, asserted over this crate's own source.**
//!
//! There is no JVM on the host and this crate is a `cdylib` that is never
//! linked off-device, so the property cannot be exercised by calling an entry
//! point. It is asserted the way `twinvpn-platform-android`'s
//! `no_bridge_entry_point_throws_into_the_jvm` asserts its neighbour — over the
//! text of the surface itself, which is what makes a *future* marshalling read
//! fail here rather than in someone's VPN app.

/// `lib.rs` with its comments and this module's declaration removed.
///
/// Comments are stripped because the file documents the rule at length, and a
/// scan that could not tell the rule from a violation would forbid stating it.
fn code() -> String {
    include_str!("lib.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// **Every JNI read that can fail goes through a helper that clears.**
///
/// Why it must hold: `jni` 0.21.1 checks `ExceptionCheck` only *after* issuing
/// a call, and `Error::JavaException` does not clear. A discarded `Result`
/// therefore left the exception pending and the next JNI call in the frame was
/// issued illegally — undefined behaviour under the JNI specification, which
/// permits only fifteen functions with an exception pending (jni-rs #731).
///
/// The three fallible marshalling calls are each allowed to appear exactly
/// **once**: inside the helper that pairs them with `clear_pending`. A second
/// occurrence is a call site that bypassed the helper.
#[test]
fn every_fallible_jni_read_is_wrapped_in_a_clearing_helper() {
    let code = code();

    for (call, helper) in [
        ("convert_byte_array(", "bytes_or_clear"),
        ("get_string(", "utf8_or_clear"),
        ("byte_array_from_slice(", "take_buf"),
    ] {
        let uses = code.matches(call).count();
        assert_eq!(
            uses, 1,
            "`{call}` appears {uses} times in `lib.rs`; it may appear only \
             inside `{helper}`, which clears the pending exception the failed \
             call leaves behind (M-18)"
        );
    }

    // Each helper must actually clear, not merely wrap.
    assert_eq!(
        code.matches("clear_pending(").count(),
        4,
        "expected `clear_pending` to be defined once and called from \
         `take_buf`, `bytes_or_clear` and `utf8_or_clear`"
    );
}

/// **No JNI `Result` is discarded by a combinator.**
///
/// These are the exact forms M-18 found: `unwrap_or_default()` fabricated an
/// empty payload and `map_or_else` fabricated an empty string, and both left
/// the exception pending for the next call to trip over. The empty value on
/// failure is still the behaviour — it is produced inside the helpers now, next
/// to the clear that makes the following call legal.
#[test]
fn no_jni_result_is_discarded_by_a_bare_combinator() {
    let code = code();

    for forbidden in ["unwrap_or_default", "map_or_else", "map_or("] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears in `lib.rs`: a JNI `Result` discarded this \
             way leaves the exception PENDING, and the next JNI call in the \
             frame is then issued illegally (M-18, jni-rs #731)"
        );
    }
}
