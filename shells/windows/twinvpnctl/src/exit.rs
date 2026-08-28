//! ADR-0017 §11.12's exit-code table.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.12; [ADR-0023](../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! **EM-37**; ADR-0018 CB-2.
//!
//! # Six values, a reserved band, and a prohibition
//!
//! | | |
//! |---|---|
//! | **0** | the operation succeeded |
//! | **1** | failed for a reason the agent named |
//! | **2** | usage — **nothing was sent to the agent** |
//! | **3** | the management channel is unavailable |
//! | **4** | authorization refused |
//! | **5** | version incompatible |
//! | 6–63 | reserved for future MI conditions |
//! | **64+** | **MUST NOT be used** |
//!
//! > 64+ MUST NOT be used, to avoid collision with `sysexits.h` and shell
//! > conventions (124/125/126/127, 128+n).
//!
//! # A mapping, not a judgement
//!
//! [`for_reason_code`] translates the agent's answer into the number a script
//! switches on. It does **not** decide what went wrong — CB-2 puts that on the
//! other side of the seam — which is why nothing in this module looks at a
//! `class`, a `severity` or a `terminal` flag. EM-37 makes retryability the
//! `class`'s job:
//!
//! > automation switches on `class`, not on the exit code. Scripts MUST NOT
//! > infer retryability from the exit code alone.

/// The operation succeeded.
pub const OK: u8 = 0;
/// Failed for a reason the agent named.
pub const FAILED: u8 = 1;
/// Usage error. **Nothing was sent to the agent.**
pub const USAGE: u8 = 2;
/// The management channel is unavailable — distinct from [`FAILED`].
pub const UNAVAILABLE: u8 = 3;
/// Authorization refused — distinct so a script can tell "re-run elevated" from
/// "this will never work".
pub const UNAUTHORIZED: u8 = 4;
/// Version incompatible.
pub const VERSION: u8 = 5;
/// The highest value this CLI may ever use.
pub const MAX_PERMITTED: u8 = 63;

/// Every code this CLI can emit.
///
/// An enumeration rather than a range, so a seventh value added without a rule
/// fails an assertion rather than shipping.
pub const ALL: [u8; 6] = [OK, FAILED, USAGE, UNAVAILABLE, UNAUTHORIZED, VERSION];

/// §11.12's table, as a mapping of the code's **domain**.
///
/// # The unregistered spellings, and why both are mapped
///
/// ADR-0017 §11.12's authorization family names
/// `PLATFORM.PRIV.CLIENT_UNAUTHORIZED`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` and
/// `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`, and
/// `contracts/registry/reason_codes.json` registers **none** of the three; the
/// agent emits `POLICY.POLICY_DENIED` in their place, and
/// [`twinvpn_mgmt::SUBSTITUTIONS`] is where the cost of each substitution is
/// recorded. `MGMT.VERSION_TOO_OLD` and `MGMT.VERSION_TOO_NEW` are unregistered
/// for the same reason, and `PROTO.VERSION_UNSUPPORTED` carries the condition.
///
/// This table maps **both** spellings, so it keeps working unchanged the day
/// `ownership.md` §8 W-18's amendment registers them. `contracts/` is frozen and
/// is not this domain's to edit.
#[must_use]
pub fn for_reason_code(reason_code: &str) -> u8 {
    match reason_code {
        "MGMT.UNAVAILABLE" => UNAVAILABLE,
        "MGMT.VERSION_TOO_OLD" | "MGMT.VERSION_TOO_NEW" | "PROTO.VERSION_UNSUPPORTED" => VERSION,
        "PLATFORM.PRIV.CLIENT_UNAUTHORIZED"
        | "PLATFORM.PRIV.ADMIN_AUTH_FAILED"
        | "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED"
        | "POLICY.POLICY_DENIED"
        | "MGMT.DISARM_REQUIRES_LOCAL_AUTH"
        | "MGMT.PRINCIPAL_UNVERIFIABLE" => UNAUTHORIZED,
        _ => FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_exit_code_is_below_the_prohibited_range() {
        // §11.12: "64+ MUST NOT be used, to avoid collision with sysexits.h and
        // shell conventions (124/125/126/127, 128+n)."
        for code in ALL {
            assert!(code <= MAX_PERMITTED, "{code} is in the reserved range");
        }
        assert_eq!(MAX_PERMITTED, 63);
    }

    /// **§11.12's reserved band, asserted rather than assumed.**
    ///
    /// 6–63 are "reserved for future MI conditions" and 64+ is prohibited. A
    /// mapping that produced either would be a CLI inventing a contract, so the
    /// test drives [`for_reason_code`] over a spread of registered and
    /// unregistered codes and asserts the result is always one of §11.12's six.
    #[test]
    fn no_reason_code_can_map_into_the_reserved_band_or_beyond_it() {
        let probes = [
            "MGMT.UNAVAILABLE",
            "PROTO.VERSION_UNSUPPORTED",
            "POLICY.POLICY_DENIED",
            "MGMT.PRINCIPAL_UNVERIFIABLE",
            "MGMT.DISARM_REQUIRES_LOCAL_AUTH",
            "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
            "PLATFORM.PRIV.ADMIN_AUTH_FAILED",
            "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED",
            "MGMT.VERSION_TOO_OLD",
            "MGMT.VERSION_TOO_NEW",
            "DNS.STUB.BIND_FAILED",
            "POLICY.KILLSWITCH.ENGAGED",
            "INTERNAL.INVARIANT_VIOLATED",
            "SOMETHING.NOBODY.SHIPPED",
            "",
            "not a code at all",
        ];
        for probe in probes {
            let code = for_reason_code(probe);
            assert!(
                ALL.contains(&code),
                "{probe} mapped to {code}, which is not one of §11.12's six"
            );
            assert!(
                !(6..=63).contains(&code),
                "{probe} landed in the reserved band"
            );
            assert!(code < 64, "{probe} landed in the prohibited range");
        }
    }

    #[test]
    fn an_unavailable_channel_is_a_different_exit_from_a_refusal() {
        // "distinct from 1", and "distinct so a script can tell re-run elevated
        // from this will never work".
        assert_eq!(for_reason_code("MGMT.UNAVAILABLE"), UNAVAILABLE);
        assert_eq!(for_reason_code("POLICY.POLICY_DENIED"), UNAUTHORIZED);
        assert_eq!(for_reason_code("PROTO.VERSION_UNSUPPORTED"), VERSION);
        assert_eq!(for_reason_code("DNS.STUB.BIND_FAILED"), FAILED);
        assert_ne!(
            for_reason_code("MGMT.UNAVAILABLE"),
            for_reason_code("POLICY.POLICY_DENIED")
        );
    }

    #[test]
    fn the_authorization_family_maps_both_the_specified_and_the_substituted_spelling() {
        // So the mapping keeps working the day W-18's amendment registers
        // `PLATFORM.PRIV.CLIENT_UNAUTHORIZED`.
        for specified in [
            "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
            "PLATFORM.PRIV.ADMIN_AUTH_FAILED",
            "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED",
        ] {
            assert_eq!(
                for_reason_code(specified),
                for_reason_code("POLICY.POLICY_DENIED")
            );
        }
        for specified in ["MGMT.VERSION_TOO_OLD", "MGMT.VERSION_TOO_NEW"] {
            assert_eq!(
                for_reason_code(specified),
                for_reason_code("PROTO.VERSION_UNSUPPORTED")
            );
        }
    }

    #[test]
    fn nothing_in_this_module_looks_at_a_class_or_a_severity() {
        // EM-37: "automation switches on `class`, not on the exit code". The
        // mechanism is that `for_reason_code` takes ONE argument, so there is no
        // class for it to consult. Two codes in one class map differently, and
        // that is the property.
        assert_ne!(
            for_reason_code("POLICY.POLICY_DENIED"),
            for_reason_code("POLICY.KILLSWITCH.ENGAGED"),
            "both are POLICY class; the exit code is not the class"
        );
    }
}
