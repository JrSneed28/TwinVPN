package net.twinvpn.android.core

/**
 * One diagnostic, **already resolved by the core**.
 *
 * Authority: ADR-0018 **CB-4** (the core resolves; the shell presents), **F-4**
 * (`resolved` carries the registry attributes, and *"no field is a sentence"*
 * — the sentences come from **F-10**'s `tw_render_diagnostic`), **F-10**;
 * ADR-0019 §11's presentation contract, LT-3.
 *
 * # Why this type has no `ConnectionState`
 *
 * CB-2 forbids a shell holding "a branch whose condition is a TwinVPN domain
 * fact — a `ConnectionState`, a `reason_code` class, a policy verdict, a
 * candidate priority, a timer expiry, a version comparison". CB-4 nevertheless
 * grants the shell *"typography, layout, truncation, platform idiom,
 * accessibility, iconography, and where the result appears"* — and a status
 * screen that looked the same in `BLOCKED` as in `WAN_DIRECT` would fail
 * ADR-0015 §11.6's presentation obligation and ADR-0022 LC-33's requirement that
 * the notification be *"visually distinct for `DEGRADED` and `BLOCKED`"*.
 *
 * The two are reconciled by what this type carries. The UI branches on
 * [severity] and [userActionable] — **registry attributes the core resolved**,
 * F-4's `resolved` block — and never on a state it classified itself. The
 * difference is not cosmetic: `severity` is looked up once, in the core, from
 * `contracts/registry/reason_codes.json`, so six shells cannot diverge on it
 * (R-31). A `when (state)` here would be a seventh classifier.
 *
 * Consequently there is **no** `ConnectionState` field on this type, and the UI
 * has nothing to switch on that the core did not already decide.
 */
internal data class Rendered(
    /**
     * The registered `reason_code`, e.g. `PLATFORM.VPN_PERMISSION_DENIED`.
     *
     * Carried for the diagnostic bundle and for `adb logcat`, **never rendered
     * to the user**: CB-4 makes the sentence the core's, and a code shown in
     * place of one is R-15's defect (the CLI that printed catalogue keys).
     */
    val reasonCode: String,

    /** The resolved summary sentence, in the requested locale. */
    val summary: String,

    /**
     * The resolved next action, when the registry says the code is
     * `user_actionable`. ADR-0019 LT-3 selects the variant by
     * `(platform, os_version)` **in the core**, so the Android 13+
     * `POST_NOTIFICATIONS` wording and the pre-13 wording are one decision made
     * once rather than a `Build.VERSION` branch here.
     */
    val nextAction: String?,

    /**
     * `INFO`, `WARN`, `ERROR`, `CRITICAL` — the registry's own value.
     *
     * This is what the UI branches on. See the type documentation.
     */
    val severity: Severity,

    /** Whether an Owner can act. Implies [nextAction] is present. */
    val userActionable: Boolean,

    /**
     * Whether protection is currently asserted.
     *
     * A single boolean the core computes from the `ProtectionAssertion`
     * (ADR-0015 §11.6 rule 1: *"a pure function of the most recent assertion,
     * never of the agent's belief"*). [ProtectionIndicator.UNKNOWN] is a real
     * value and O-18's fail-safe direction: **never green** where the assertion
     * could not be produced.
     */
    val protection: ProtectionIndicator,

    /**
     * The three-valued always-on posture, as a stable tag —
     * `LOCKDOWN_CONFIRMED`, `LOCKDOWN_ABSENT`, `LOCKDOWN_UNVERIFIED`.
     *
     * Rendered, not interpreted: ADR-0022 LC-40 requires `UNVERIFIED` to present
     * as *not protected by lockdown*, and the core has already folded that into
     * [protection].
     */
    val lockdownTag: String,
) {
    /** The registry's severity ladder. */
    enum class Severity { INFO, WARN, ERROR, CRITICAL }

    /** ADR-0015 O-18's three-valued indicator. */
    enum class ProtectionIndicator {
        /** The assertion says protected. */
        PROTECTED,

        /** The assertion says not protected. */
        UNPROTECTED,

        /**
         * No assertion could be produced.
         *
         * **Never rendered as green.** On Android this is what a dead tun
         * descriptor produces, and a dead descriptor means traffic is egressing
         * untunneled — so `UNKNOWN` here is closer to `UNPROTECTED` than to
         * `PROTECTED`, and the UI treats it that way.
         */
        UNKNOWN,
    }
}
