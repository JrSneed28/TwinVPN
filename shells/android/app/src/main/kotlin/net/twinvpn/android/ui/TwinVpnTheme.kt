package net.twinvpn.android.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import net.twinvpn.android.core.Rendered

/**
 * The Compose theme, and the **only** place a severity becomes a colour.
 *
 * Authority: ADR-0018 **CB-4** (*"Presentation | Shell | typography, layout,
 * truncation, platform idiom, accessibility, iconography, and where the result
 * appears"*), CB-2; ADR-0019 §11 (Jetpack Compose is Android's supported
 * direction), §11.9, and its accessibility contract.
 *
 * # Why a severity → colour map is not a CB-2 violation
 *
 * CB-2 forbids "a branch whose condition is a TwinVPN domain fact — a
 * `ConnectionState`, a `reason_code` class, a policy verdict". [Rendered.severity]
 * is none of those *as the shell sees it*: it is a **registry attribute the core
 * already resolved** and handed across in F-4's `resolved` block. The
 * classification — which condition is `WARN` and which is `CRITICAL` — happened
 * once, in the core, from `contracts/registry/reason_codes.json`.
 *
 * What is left here is the mapping from an already-decided severity to a hue,
 * which is exactly what CB-4 assigns to the shell. Keeping it in **one file**
 * matters for the same reason: ADR-0019's presentation contract requires
 * `DEGRADED` and `BLOCKED` to be visually distinct, and a colour chosen at four
 * call sites is four chances to make two of them the same.
 *
 * # Colour is never the only signal
 *
 * ADR-0019's accessibility contract, and ordinary sense: every surface that uses
 * [statusColor] also carries an icon and the core's own sentence. A user with a
 * colour-vision deficiency, or one reading the notification in a monochrome
 * shade, loses nothing.
 */
@Composable
internal fun TwinVpnTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val scheme = when {
        // Material You where the platform offers it. Purely presentation.
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

/** The protected / degraded / blocked / unknown palette. */
internal object StatusPalette {
    /** Protection is asserted. */
    val ok = Color(0xFF1B7F4B)

    /** A quality objective is violated but traffic is carried. */
    val degraded = Color(0xFFB26A00)

    /** Protected traffic is blocked, or a terminal condition holds. */
    val blocked = Color(0xFFB3261E)

    /**
     * No assertion could be produced.
     *
     * ADR-0015 **O-18**: the indicator goes `UNKNOWN`, **never green**. A
     * distinct neutral rather than a dimmed green, because a dimmed green reads
     * as "mostly fine" at a glance and this state is not.
     */
    val unknown = Color(0xFF5F6368)
}

/**
 * The colour for one resolved diagnostic.
 *
 * Reads [Rendered.protection] **first**: the `ProtectionAssertion` is the
 * authority on whether the device is protected (ADR-0015 §11.6 rule 1, *"a pure
 * function of the most recent assertion, never of the agent's belief"*), and a
 * severity is about the condition rather than about the posture. A `WARN`
 * alongside an asserted protection is amber-on-green, not amber.
 */
internal fun statusColor(rendered: Rendered?): Color = when {
    rendered == null -> StatusPalette.unknown
    rendered.protection == Rendered.ProtectionIndicator.UNKNOWN -> StatusPalette.unknown
    rendered.protection == Rendered.ProtectionIndicator.PROTECTED -> StatusPalette.ok
    rendered.severity >= Rendered.Severity.ERROR -> StatusPalette.blocked
    rendered.severity == Rendered.Severity.WARN -> StatusPalette.degraded
    else -> StatusPalette.unknown
}
