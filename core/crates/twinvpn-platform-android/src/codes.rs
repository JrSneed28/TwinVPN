//! The reason codes this adapter emits — and the **seventeen** the Android rows
//! of the Phase 1 corpus name that the frozen registry does not carry.
//!
//! **Authority:** `contracts/registry/reason_codes.json` (frozen), ADR-0015
//! §11.2, `docs/implementation/ownership.md` §3, §4.2, §6 rule 12, and §8
//! **W-18** — which established the pattern this module follows:
//!
//! > Every domain documents its substitution in a `SUBSTITUTIONS`/`UNREGISTERED`
//! > table with a tripwire test asserting the spelling is still absent, so
//! > registering a code fails the build and points at the line to delete.
//!
//! # The finding, for the Android surface
//!
//! W-18 measured `PLATFORM` as the worst-affected domain — **73 codes named
//! normatively across the corpus and absent from the registry**. Wave 3 is where
//! that lands hardest, because `PLATFORM.LIFECYCLE.*` is the namespace ADR-0022
//! contributes and the mobile lifecycle is what ADR-0022 is *about*. Not one
//! `PLATFORM.LIFECYCLE.*` code is registered.
//!
//! Three of the seventeen hurt in particular:
//!
//! - **`PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS`** is ADR-0022 §11.3's answer
//!   for the single most common Android field failure — a force-stopped app whose
//!   manifest receivers are disabled until the next manual launch, and an OEM
//!   battery manager producing the same outcome. It is `user_actionable` in the
//!   ADR and there is nothing registered that carries that meaning.
//! - **`NET.CONCURRENT_VPN`** is `docs/networking.md` §5.5 rule 4's whole
//!   mechanism and ADR-0022's response to `onRevoke()`: *"report the competing
//!   app"*. Substituting `ROUTE.IFACE_CONFLICT` keeps the shape and loses the
//!   `NET` prefix a receiver would degrade on.
//! - **`STORE.KEYSTORE_LOCKED`** is ADR-0020's named outcome for
//!   always-on-VPN-at-boot before first unlock, which on Android is not an edge
//!   case: it is what happens on every reboot of every device with a screen lock.
//!
//! Every substitution below is the nearest registered code by *meaning*, chosen
//! so that a receiver that degrades on the `DOMAIN` prefix (ADR-0015 §11.2 rule
//! 4) still reaches a defensible diagnosis. Where the nearest registered code
//! changes the domain, that is called out — because prefix degradation is
//! exactly what W-11 records as the cost.
//!
//! `contracts/` is frozen and is not this domain's to change (§3), so this is
//! **reported, not patched**.

use twinvpn_types::{codes as reg, Component, Diagnostic, EvidenceValue, ReasonCode};

/// One code the Phase 1 corpus names that the frozen registry does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling the owning document uses.
    pub specified: &'static str,
    /// The document that names it.
    pub owner: &'static str,
    /// The registered code this build emits instead.
    pub emitted: ReasonCode,
}

/// The seventeen.
///
/// A test asserts each `specified` spelling is genuinely absent, so registering
/// one fails the build and points at the line to delete.
pub const UNREGISTERED: &[Substitution] = &[
    // ---- ADR-0022 §11.11's PLATFORM.LIFECYCLE.* contributions -------------
    Substitution {
        specified: "PLATFORM.LIFECYCLE.REHYDRATED",
        owner: "ADR-0022 LC-2",
        emitted: reg::PLATFORM_PROCESS_RESTARTED,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.REHYDRATE_INCOMPLETE",
        owner: "ADR-0022 LC-6",
        // LC-6 routes this to BLOCKED via T29 and keeps RULESET_BLOCKED live.
        // `POLICY.KILLSWITCH.ENGAGED` is the registered code for "protected
        // traffic is blocked because no authorised secure path exists", which is
        // the state LC-6 lands in even though it loses the cause.
        emitted: reg::POLICY_KILLSWITCH_ENGAGED,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT",
        owner: "ADR-0022 LC-5",
        emitted: reg::INTERNAL_UNEXPECTED_STATE,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS",
        owner: "ADR-0022 §11.3 Android row",
        // The domain survives; the condition does not. A receiver degrading on
        // `PLATFORM` still learns this is a platform-capability failure, and
        // loses "the user force-stopped us and only the user can undo it" --
        // which is the whole of the remediation.
        emitted: reg::PLATFORM_ADAPTER_UNAVAILABLE,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.OS_TERMINATED",
        owner: "ADR-0022 §11.4 Android low-memory row",
        emitted: reg::PLATFORM_PROCESS_RESTARTED,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.KEY_UNAVAILABLE_PRE_UNLOCK",
        owner: "ADR-0022 LC-15",
        emitted: reg::AUTH_KEY_UNAVAILABLE,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.LOW_POWER_PROFILE",
        owner: "ADR-0022 LC-31",
        emitted: reg::PLATFORM_SUSPENDED,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.THERMAL_THROTTLED",
        owner: "ADR-0022 LC-31",
        emitted: reg::PLATFORM_SUSPENDED,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.MEMORY_BUDGET_EXCEEDED",
        owner: "ADR-0022 LC-31",
        emitted: reg::PLATFORM_ADAPTER_UNAVAILABLE,
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.TRUSTED_NET_UNPROVABLE",
        owner: "ADR-0022 TN-4",
        emitted: reg::PLATFORM_ADAPTER_UNAVAILABLE,
    },
    // ---- the Doze row ----------------------------------------------------
    Substitution {
        specified: "PLATFORM.BACKGROUND_SUSPENDED",
        owner: "ADR-0022 §11.4 Android Doze row",
        // The closest of the seventeen: `PLATFORM.SUSPENDED` is registered,
        // TRANSIENT/INFO, and means the same thing. The spelling differs only
        // by the `BACKGROUND_` prefix.
        emitted: reg::PLATFORM_SUSPENDED,
    },
    // ---- coexistence -----------------------------------------------------
    Substitution {
        specified: "NET.CONCURRENT_VPN",
        owner: "docs/networking.md §5.5.4, ADR-0022 §11.4 onRevoke row",
        // DOMAIN CHANGE: NET -> ROUTE. A receiver degrading on the prefix reads
        // this as a routing conflict rather than a connectivity condition. That
        // is the W-11 cost, and it is the least wrong of the registered set:
        // `ROUTE.IFACE_CONFLICT` at least names an interface conflict, which is
        // what a second VPN claiming the slot is.
        emitted: reg::ROUTE_IFACE_CONFLICT,
    },
    // ---- ADR-0012 §11.9 --------------------------------------------------
    Substitution {
        specified: "POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE",
        owner: "ADR-0012 §11.6 Android limitation row",
        emitted: reg::PLATFORM_ADAPTER_UNAVAILABLE,
    },
    Substitution {
        specified: "POLICY.LEAK.EGRESS_OBSERVED",
        owner: "ADR-0012 §11.9",
        // The leak canary's own verdict. `POLICY.LEAK.DETECTED` is registered,
        // FATAL/CRITICAL, and declares a `family` evidence field -- which is
        // what `ownership.md` §4.2 requires address family to be carried as.
        emitted: reg::POLICY_LEAK_DETECTED,
    },
    // ---- ADR-0020 §11's Android rows -------------------------------------
    Substitution {
        specified: "STORE.KEYSTORE_LOCKED",
        owner: "ADR-0020 §11 Android row",
        // TRANSIENT/WARN, which is the correct class: the device will be
        // unlocked, and LC-15 completes rehydration then.
        emitted: reg::AUTH_KEY_STORE_UNAVAILABLE,
    },
    Substitution {
        specified: "STORE.KEY_INVALIDATED",
        owner: "ADR-0020 §11's recovery ladder",
        // The screen lock was removed and the Keystore key is gone for good.
        // `STORE.VAULT_CORRUPT` is the registered code for an unopenable vault;
        // it loses the cause, which is the difference between "re-enrol" and
        // "restore".
        emitted: reg::STORE_VAULT_CORRUPT,
    },
    // ---- ADR-0011 --------------------------------------------------------
    Substitution {
        specified: "DNS.PLATFORM.PRIVATE_DNS_ACTIVE",
        owner: "ADR-0011, ADR-0019 §11's catalogue",
        // Same domain and subdomain; the condition differs. A receiver
        // degrading on `DNS.PLATFORM` reaches the right neighbourhood.
        emitted: reg::DNS_PLATFORM_SCOPED_API_UNAVAILABLE,
    },
];

/// `PLATFORM.VPN_PERMISSION_DENIED` — `VpnService.prepare()` has not been
/// consented to, or another app holds the platform's single VPN slot.
/// **Registered**, and `user_actionable` with ADR-0019's Android next-action
/// variant (`Settings.ACTION_VPN_SETTINGS`).
#[must_use]
pub const fn vpn_permission_denied() -> ReasonCode {
    reg::PLATFORM_VPN_PERMISSION_DENIED
}

/// `NET.CONCURRENT_VPN` — another app has taken the VPN slot (`onRevoke`).
/// **Substituted**; see [`UNREGISTERED`].
///
/// ADR-0022's response is normative and is *not* affected by the substitution:
/// tear our tunnel down cleanly, **do not fight for the slot**, report the
/// competing app.
#[must_use]
pub const fn concurrent_vpn() -> ReasonCode {
    reg::ROUTE_IFACE_CONFLICT
}

/// `PLATFORM.BACKGROUND_SUSPENDED` — Doze or App Standby. **Substituted.**
#[must_use]
pub const fn background_suspended() -> ReasonCode {
    reg::PLATFORM_SUSPENDED
}

/// `STORE.KEYSTORE_LOCKED` — credential-encrypted storage before first unlock.
/// **Substituted.**
#[must_use]
pub const fn keystore_locked() -> ReasonCode {
    reg::AUTH_KEY_STORE_UNAVAILABLE
}

/// `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` — force-stopped, or an OEM
/// battery manager. **Substituted.**
#[must_use]
pub const fn autostart_blocked() -> ReasonCode {
    reg::PLATFORM_ADAPTER_UNAVAILABLE
}

/// `POLICY.LEAK.EGRESS_OBSERVED` — protected traffic seen off the overlay.
/// **Substituted.**
#[must_use]
pub const fn egress_observed() -> ReasonCode {
    reg::POLICY_LEAK_DETECTED
}

/// `POLICY.LEAK.IPV6_UNPROTECTED` — the claim or the grant is v4-only.
/// **Registered.**
#[must_use]
pub const fn ipv6_unprotected() -> ReasonCode {
    reg::POLICY_LEAK_IPV6_UNPROTECTED
}

/// `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` — Android Private DNS takes precedence
/// over this tunnel's resolvers. **Substituted.**
#[must_use]
pub const fn private_dns_active() -> ReasonCode {
    reg::DNS_PLATFORM_SCOPED_API_UNAVAILABLE
}

/// A diagnostic from this adapter, with the family named as **evidence**.
///
/// `ownership.md` §4.2: address family is an *evidence field*, never a
/// namespace, because a per-family namespace makes "we have a v4 story and a v6
/// story" sayable — the exact asymmetry ADR-0010 R1 exists to forbid.
///
/// `correlation_id` is **not** set here and is not this function's to invent:
/// §6 rule 6 requires it preserved across every boundary, and the boundary that
/// has one is the command the core is executing. The adapter attaches it via
/// [`twinvpn_types::DiagnosticBuilder::correlated_to`] where it has the
/// `MessageId`, and omits it rather than fabricating one where it does not.
#[must_use]
pub fn diagnostic(code: ReasonCode, family: Option<twinvpn_types::AddressFamily>) -> Diagnostic {
    let mut b = Diagnostic::builder(code, Component::PlatformAdapter);
    if let Some(f) = family {
        b = b.evidence("family", EvidenceValue::Family(f));
    }
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The W-18 tripwire. If any of these is registered, this test fails and
    /// names the line to delete.
    #[test]
    fn every_unregistered_android_code_is_still_absent_from_the_frozen_registry() {
        for s in UNREGISTERED {
            assert!(
                ReasonCode::lookup(s.specified).is_none(),
                "{} ({}) is now registered — remove its substitution in \
                 twinvpn-platform-android::codes",
                s.specified,
                s.owner
            );
        }
        assert_eq!(
            UNREGISTERED.len(),
            17,
            "the Android surface of the corpus names 17 codes the registry does not carry"
        );
    }

    #[test]
    fn every_substitute_is_itself_registered() {
        for s in UNREGISTERED {
            assert!(
                ReasonCode::lookup(s.emitted.as_str()).is_some(),
                "{} substitutes an unregistered code, which would be a second defect",
                s.specified
            );
        }
    }

    #[test]
    fn every_substitution_names_the_document_that_specified_it() {
        for s in UNREGISTERED {
            assert!(!s.owner.is_empty());
            assert!(
                s.owner.starts_with("ADR-") || s.owner.starts_with("docs/"),
                "{} must cite a Phase 1 document, not a guess",
                s.specified
            );
        }
    }

    #[test]
    fn no_substitution_maps_a_code_onto_itself() {
        for s in UNREGISTERED {
            assert_ne!(s.specified, s.emitted.as_str());
        }
    }

    #[test]
    fn the_codes_this_adapter_emits_are_all_registered() {
        for code in [
            vpn_permission_denied(),
            concurrent_vpn(),
            background_suspended(),
            keystore_locked(),
            autostart_blocked(),
            egress_observed(),
            ipv6_unprotected(),
            private_dns_active(),
        ] {
            assert!(ReasonCode::lookup(code.as_str()).is_some());
        }
    }

    /// The leak verdict must be able to name the family it saw, or ADR-0010 R1's
    /// symmetry is unreportable.
    #[test]
    fn the_leak_verdict_carries_the_family_as_evidence() {
        for family in [
            twinvpn_types::AddressFamily::V4,
            twinvpn_types::AddressFamily::V6,
        ] {
            let d = diagnostic(egress_observed(), Some(family));
            assert_eq!(d.code().as_str(), "POLICY.LEAK.DETECTED");
            assert!(
                d.evidence().get("family").is_some(),
                "POLICY.LEAK.DETECTED declares `family`; it must arrive"
            );
        }
    }

    #[test]
    fn every_diagnostic_is_attributed_to_the_platform_adapter() {
        let d = diagnostic(vpn_permission_denied(), None);
        assert_eq!(d.component(), Component::PlatformAdapter);
        assert!(d.correlation_id().is_none(), "never fabricated");
    }
}
