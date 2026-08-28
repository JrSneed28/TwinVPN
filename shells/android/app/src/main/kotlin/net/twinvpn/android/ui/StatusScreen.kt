package net.twinvpn.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.twinvpn.android.R
import net.twinvpn.android.core.Rendered

/**
 * The status surface.
 *
 * Authority: ADR-0019 §11 (the presentation contract, the permission table,
 * §11.9's anti-silence requirement), ADR-0015 **O-18**, ADR-0018 **CB-4**,
 * ADR-0022 **LC-40**.
 *
 * # The rule this screen is built to
 *
 * **Every sentence a user reads here came from the core.** There is no string in
 * this file describing a connection state, a failure, or a remediation — the
 * only literals are chrome (button labels, section headings), and even those are
 * resources rather than inline text.
 *
 * That is CB-4's split at its sharpest: the core resolves `reason_code` +
 * evidence + locale + platform context into a summary and a next action
 * (`tw_render_diagnostic`, F-10, **pure**), and this screen decides where they
 * go and how large they are.
 *
 * The alternative — `when (state) { BLOCKED -> "Blocked" ... }` — is what R-31
 * names as a defect class and what CB-2 forbids, and it would give the GUI and
 * the CLI on the same host two different sentences for one condition.
 */
@Composable
internal fun StatusScreen(
    rendered: Rendered?,
    consentGranted: Boolean,
    notificationsAllowed: Boolean,
    onRequestConsent: () -> Unit,
    onOpenVpnSettings: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Column(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        ProtectionBanner(rendered)

        if (rendered == null) {
            // No assertion has been produced. O-18's direction: this is stated,
            // not filled in with an optimistic guess.
            Text(
                text = stringResource(R.string.status_starting),
                style = MaterialTheme.typography.bodyLarge,
            )
        } else {
            Text(
                text = rendered.summary,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.semantics {
                    // The status is announced when it changes, which is what
                    // makes this an anti-silence surface for a screen-reader
                    // user as well as a sighted one.
                    liveRegion = LiveRegionMode.Polite
                },
            )
            rendered.nextAction?.let { action ->
                Text(text = action, style = MaterialTheme.typography.bodyMedium)
            }
        }

        // ADR-0019 §11's Android VPN-consent row. Without the grant no tunnel is
        // possible, and "pairing, device list, settings, and diagnostics remain
        // usable" — which is why this is a card rather than a blocking dialog.
        if (!consentGranted) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.consent_title))
                    Button(onClick = onRequestConsent) {
                        Text(stringResource(R.string.consent_action))
                    }
                }
            }
        }

        // ADR-0019 §11's Android 13+ row, stated in the ADR's own terms: the
        // anti-silence surface is GONE, and the user is told so rather than
        // discovering it the first time protection stops while backgrounded.
        if (!notificationsAllowed) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.notifications_lost_title))
                    Text(
                        text = stringResource(R.string.notifications_lost_body),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = onOpenVpnSettings) {
                        Text(stringResource(R.string.action_open_settings))
                    }
                }
            }
        }

        LockdownCard(rendered, onOpenVpnSettings)

        Spacer(Modifier.height(8.dp))
        Button(onClick = onConnect, enabled = consentGranted, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_connect))
        }
        OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_disconnect))
        }
    }
}

/**
 * The protection indicator.
 *
 * Colour **and** an announced description, never colour alone. The colour comes
 * from [statusColor], which reads the assertion first and the resolved severity
 * second — see [TwinVpnTheme]'s documentation for why that is CB-4 rather than
 * CB-2.
 */
@Composable
private fun ProtectionBanner(rendered: Rendered?) {
    val description = when (rendered?.protection) {
        Rendered.ProtectionIndicator.PROTECTED -> R.string.protection_protected
        Rendered.ProtectionIndicator.UNPROTECTED -> R.string.protection_unprotected
        // O-18: no assertion is `UNKNOWN`, and `UNKNOWN` is not green.
        else -> R.string.protection_unknown
    }
    Column(
        Modifier
            .fillMaxWidth()
            .background(statusColor(rendered), RoundedCornerShape(12.dp))
            .padding(16.dp)
            .semantics { contentDescription = "" },
    ) {
        Text(
            text = stringResource(description),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

/**
 * The always-on posture, presented three-valued.
 *
 * ADR-0022 **LC-40** and `docs/networking.md` §5.4: `LOCKDOWN_UNVERIFIED` MUST
 * be presented as *not protected by lockdown*, with the guided flow to
 * `Settings.ACTION_VPN_SETTINGS`. ADR-0012 §11.6's Android row adds that the
 * posture must be *"an unmissable, persistent state, not a settings hint"* —
 * hence a card that is always present rather than a line in a settings list.
 *
 * The `when` here is over a **stable tag string the core supplied**, not over a
 * posture this shell computed. There is no probe in this module, and there must
 * not be one: under lockdown our own sockets are the permitted ones, so a
 * reachability test proves nothing.
 */
@Composable
private fun LockdownCard(rendered: Rendered?, onOpenVpnSettings: () -> Unit) {
    val body = when (rendered?.lockdownTag) {
        "LOCKDOWN_CONFIRMED" -> R.string.lockdown_confirmed
        "LOCKDOWN_ABSENT" -> R.string.lockdown_absent
        else -> R.string.lockdown_unverified
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.lockdown_title))
            Text(stringResource(body), style = MaterialTheme.typography.bodySmall)
            if (rendered?.lockdownTag != "LOCKDOWN_CONFIRMED") {
                OutlinedButton(onClick = onOpenVpnSettings) {
                    Text(stringResource(R.string.action_open_settings))
                }
            }
        }
    }
}
