package net.twinvpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.twinvpn.android.R
import net.twinvpn.android.core.Rendered

/**
 * Diagnostics.
 *
 * Authority: ADR-0015 §11.2 (the registry is the authority), §11.4 (field
 * classification and redaction), ADR-0018 **CB-4**, **F-4**;
 * `docs/implementation/ownership.md` §6 rules 11 and 12;
 * ADR-0019 §11 (export targets: Android uses SAF).
 *
 * # The code is shown, and it is not the message
 *
 * R-15 is the defect this screen is written against: `twinvpnctl` rendered
 * catalogue *keys* to the user, and the tell was that **an unknown code rendered
 * better than a known one**, because the unknown-code fallback emitted a real
 * sentence.
 *
 * So both are shown, and each in its place: the **sentence** the core resolved is
 * the body, and the **code** is a small monospaced line beneath it for a support
 * case to quote. Neither substitutes for the other.
 *
 * # What is never rendered here
 *
 * §6 rule 11: no private key, no session key, no tunnel payload, no pairing
 * secret, no token. The screen has no access to any of them — a `Rendered`
 * carries only registry attributes and resolved text, and redaction happened
 * core-side before the envelope was built (ADR-0015 §11.4, and F-4's *"already
 * redacted"*).
 *
 * # The bundle
 *
 * `docs/threat-model.md` §9 requires a **user act** before a diagnostic bundle
 * is assembled, and ADR-0022 LC-17's table puts assembly, redaction and
 * rendering in the app process. Both hold here: the export button below is that
 * act, and it hands off to SAF (`ACTION_CREATE_DOCUMENT`) so the user chooses
 * where the file goes. It is **not wired in this wave** — the bundle comes from
 * the core over ADR-0017, which is the binding W-38 blocks.
 */
@Composable
internal fun DiagnosticsScreen(rendered: Rendered?) {
    Column(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.diagnostics_title),
            style = MaterialTheme.typography.titleMedium,
        )

        if (rendered == null) {
            Text(
                text = stringResource(R.string.diagnostics_empty),
                style = MaterialTheme.typography.bodyMedium,
            )
            return@Column
        }

        // The sentence: the core's, resolved from the registry in the caller's
        // locale, with evidence already substituted (F-10).
        Text(text = rendered.summary, style = MaterialTheme.typography.bodyLarge)
        rendered.nextAction?.let {
            Text(text = it, style = MaterialTheme.typography.bodyMedium)
        }

        // The code: for a support case, never as the message. R-15.
        Text(
            text = rendered.reasonCode,
            style = MaterialTheme.typography.labelSmall,
        )

        // The always-on posture as a stable tag, for the same reason: a bundle
        // that says `LOCKDOWN_UNVERIFIED` is answerable; one that says
        // "not protected" is not.
        Text(
            text = rendered.lockdownTag,
            style = MaterialTheme.typography.labelSmall,
        )
    }
}
