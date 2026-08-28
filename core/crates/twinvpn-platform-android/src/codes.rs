//! The reason codes this adapter emits.
//!
//! **Authority:** `contracts/registry/reason_codes.json`, ADR-0015 §11.2,
//! `docs/implementation/ownership.md` §3, §4.2, §6 rule 12, §8 **W-18** and
//! §10.8 **M-4**.
//!
//! # The finding this module was written around, and its close
//!
//! W-18 measured `PLATFORM` as the worst-affected domain — **73 codes named
//! normatively across the corpus and absent from the registry**. Wave 3 landed
//! hardest there, because `PLATFORM.LIFECYCLE.*` is the namespace ADR-0022
//! contributes and the mobile lifecycle is what ADR-0022 is *about*. At
//! `registry_version` 1 **not one `PLATFORM.LIFECYCLE.*` code was registered**,
//! so this module carried seventeen substitutions and a tripwire over each.
//!
//! **`registry_version` 2 registered all seventeen** (`ownership.md` §9.6
//! **X-1**, 201 → 454 codes). Both mobile domains had reported the same gap
//! independently and **neither invented a code**; each substituted a registered
//! near-neighbour and left a tripwire, and every tripwire fired on the pass
//! that integrated this crate. **M-4** is that close, and this is it:
//!
//! - [`UNREGISTERED`] is **empty**, and the type and the tripwire are kept
//!   rather than deleted — a future ADR code that outruns the registry must
//!   land here visibly, which is exactly what happened last time.
//! - Every helper below emits the code its owning document spells. Three that
//!   mattered most, now under their own names:
//!   `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` (ADR-0022 §11.3's answer to
//!   the single most common Android field failure, and `user_actionable`);
//!   `NET.CONCURRENT_VPN` (`networking.md` §5.5 rule 4, where substituting
//!   `ROUTE.IFACE_CONFLICT` kept the shape and lost the `NET` prefix a receiver
//!   degrades on); and `STORE.KEYSTORE_LOCKED`, which on Android is not an edge
//!   case at all — it is what happens on every reboot of every device with a
//!   screen lock.
//!
//! The cost the substitutions carried is therefore paid by nobody, and
//! `contracts/` was changed by the §3 ceremony rather than by this domain.

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

/// Every code this build substitutes.
///
/// **Empty as of `registry_version` 2.** All seventeen the Android surface of
/// the corpus names are registered, so this adapter emits each by its own name.
/// The type and the tripwire are kept, not deleted: a future ADR code that
/// outruns the registry must land here visibly.
pub const UNREGISTERED: &[Substitution] = &[];

/// `PLATFORM.VPN_PERMISSION_DENIED` — `VpnService.prepare()` has not been
/// consented to, or another app holds the platform's single VPN slot.
/// **Registered**, and `user_actionable` with ADR-0019's Android next-action
/// variant (`Settings.ACTION_VPN_SETTINGS`).
#[must_use]
pub const fn vpn_permission_denied() -> ReasonCode {
    reg::PLATFORM_VPN_PERMISSION_DENIED
}

/// `NET.CONCURRENT_VPN` — another app has taken the VPN slot (`onRevoke`).
///
/// ADR-0022's response is normative: tear our tunnel down cleanly, **do not
/// fight for the slot**, report the competing app.
///
/// **No longer substituted.** It emitted `ROUTE.IFACE_CONFLICT`, which kept the
/// shape and lost the `NET` prefix a receiver degrades on — "the interface is
/// contended" rather than "another VPN app owns the slot", which are different
/// next actions.
#[must_use]
pub const fn concurrent_vpn() -> ReasonCode {
    reg::NET_CONCURRENT_VPN
}

/// `PLATFORM.BACKGROUND_SUSPENDED` — Doze or App Standby.
#[must_use]
pub const fn background_suspended() -> ReasonCode {
    reg::PLATFORM_BACKGROUND_SUSPENDED
}

/// `STORE.KEYSTORE_LOCKED` — credential-encrypted storage before first unlock.
///
/// **No longer substituted**, and this is the one that mattered most in
/// practice: it is not an edge case on Android but what happens on every reboot
/// of every device with a screen lock, and `AUTH.KEY_STORE_UNAVAILABLE` said
/// "the key store is broken" where the truth is "wait for the user to unlock".
#[must_use]
pub const fn keystore_locked() -> ReasonCode {
    reg::STORE_KEYSTORE_LOCKED
}

/// `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` — force-stopped, or an OEM
/// battery manager.
///
/// **No longer substituted.** ADR-0022 §11.3 makes it `user_actionable`, and
/// `PLATFORM.ADAPTER_UNAVAILABLE` is not: it told a user their adapter was
/// broken when the fix is to launch the app once by hand.
#[must_use]
pub const fn autostart_blocked() -> ReasonCode {
    reg::PLATFORM_LIFECYCLE_AUTOSTART_BLOCKED_BY_OS
}

/// The leak verdict: protected traffic seen off the overlay.
///
/// # The one substitution that survived Amendment 1, and why it is the right way round
///
/// `registry_version` 2 registered `POLICY.LEAK.EGRESS_OBSERVED`, so the
/// tripwire fired for it with the other sixteen — and repointing at it would
/// have made the diagnosis **worse**.
///
/// The two entries describe the same condition in the same words: *"the canary
/// observed protected traffic on a non-overlay interface"*. They differ in one
/// thing. `POLICY.LEAK.DETECTED` declares `family`; `POLICY.LEAK.EGRESS_OBSERVED`
/// declares **no evidence at all** — so `family` would be attached by
/// [`diagnostic`] and then dropped by the builder, which is the W-6 failure
/// mode, and a leak verdict that cannot say *which family leaked* is exactly
/// the "we have a v4 story and a v6 story" asymmetry `ownership.md` §4.2 and
/// ADR-0010 R1 exist to forbid.
///
/// So this build keeps `POLICY.LEAK.DETECTED`, which is not a downgrade: it is
/// the registered code that carries the fact. **The registry now holding two
/// identifiers for one condition is reported as a finding** —
/// `reliability.md` §3.3 forbids a second identifier for a condition another
/// entry already registers, which is the same rule that had
/// `MGMT.SCOPE_DENIED` withdrawn before registration.
#[must_use]
pub const fn egress_observed() -> ReasonCode {
    reg::POLICY_LEAK_DETECTED
}

/// `POLICY.LEAK.IPV6_UNPROTECTED` — the claim or the grant is v4-only.
#[must_use]
pub const fn ipv6_unprotected() -> ReasonCode {
    reg::POLICY_LEAK_IPV6_UNPROTECTED
}

/// `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` — Android Private DNS takes precedence
/// over this tunnel's resolvers.
#[must_use]
pub const fn private_dns_active() -> ReasonCode {
    reg::DNS_PLATFORM_PRIVATE_DNS_ACTIVE
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

    /// The W-18 tripwire, **inverted rather than deleted**.
    ///
    /// It asserted every `specified` spelling was still ABSENT and named the
    /// line to delete when one landed. `registry_version` 2 registered all
    /// seventeen and it fired exactly as designed — which is M-4, and which is
    /// why the type and this test survive an empty table: a future ADR code
    /// that outruns the registry must land here visibly.
    // `const_is_empty` fires because the table IS a const empty slice today.
    // That is exactly what this asserts and exactly what must not change
    // silently: the point is to fail when a row comes back.
    #[allow(clippy::const_is_empty)]
    #[test]
    fn no_android_code_is_substituted_any_more() {
        assert!(
            UNREGISTERED.is_empty(),
            "an Android spelling is being substituted again: {:?}",
            UNREGISTERED.iter().map(|s| s.specified).collect::<Vec<_>>()
        );
    }

    /// The leak verdict keeps `POLICY.LEAK.DETECTED`, and it must stay the one
    /// that carries `family`.
    ///
    /// If `POLICY.LEAK.EGRESS_OBSERVED` ever gains the evidence field, the two
    /// become interchangeable and the substitution should be reconsidered —
    /// this is the tripwire for that, in the same inverted form as the rest.
    #[test]
    fn the_leak_verdict_uses_the_code_that_can_carry_the_family() {
        assert!(
            egress_observed().declares_evidence("family"),
            "a leak verdict that cannot name the family is the asymmetry R1 forbids"
        );
        let weaker =
            ReasonCode::lookup("POLICY.LEAK.EGRESS_OBSERVED").expect("registered by Amendment 1");
        assert!(
            !weaker.declares_evidence("family"),
            "POLICY.LEAK.EGRESS_OBSERVED now carries `family`; the two entries \
             are interchangeable and the duplicate should be resolved"
        );
    }

    /// Every code this adapter emits is registered **and is the one its owning
    /// document spells**.
    ///
    /// The stronger half of the close. An empty `UNREGISTERED` proves nothing
    /// on its own — a helper could still return a near-neighbour with the table
    /// emptied around it, which is precisely the residual found in
    /// `twinvpn-mgmt::codes` on this same pass.
    #[test]
    fn every_helper_emits_the_code_its_document_names() {
        for (spelling, emitted) in [
            ("NET.CONCURRENT_VPN", concurrent_vpn()),
            ("PLATFORM.BACKGROUND_SUSPENDED", background_suspended()),
            ("STORE.KEYSTORE_LOCKED", keystore_locked()),
            (
                "PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS",
                autostart_blocked(),
            ),
            ("POLICY.LEAK.IPV6_UNPROTECTED", ipv6_unprotected()),
            ("DNS.PLATFORM.PRIVATE_DNS_ACTIVE", private_dns_active()),
        ] {
            assert!(
                ReasonCode::lookup(spelling).is_some(),
                "{spelling} is named by the corpus and is not registered"
            );
            assert_eq!(
                emitted.as_str(),
                spelling,
                "{spelling} must be emitted under its own name"
            );
        }
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
