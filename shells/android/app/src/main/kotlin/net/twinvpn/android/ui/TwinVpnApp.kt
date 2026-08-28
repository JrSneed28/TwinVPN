package net.twinvpn.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import net.twinvpn.android.R
import net.twinvpn.android.core.Rendered

/** The four top-level destinations ADR-0019 §11's Android row implies. */
internal enum class Destination { STATUS, PEERS, PAIRING, DIAGNOSTICS }

/**
 * The app shell: a scaffold, a nav bar, and four screens.
 *
 * Authority: ADR-0019 §11 (Jetpack Compose, *"the FGS notification is where a
 * backgrounded user learns protection stopped"*), §11.9; ADR-0018 CB-4.
 *
 * # Where the state comes from, and where it does not
 *
 * `rendered` is whatever the core last resolved and published on its **one
 * ordered event stream** (ADR-0018 F-5). It is `null` before the first event,
 * which is a real state and is rendered as such — never as "connected" and never
 * as "disconnected", because neither has been established.
 *
 * In this wave it stays `null`: `CoreClient` cannot subscribe, because
 * `contracts/` defines no command or event message for `tw_core_submit` to carry
 * (W-38). That is a reported gap rather than a stub with a fake, and the UI is
 * written so the fix is one binding rather than a rewrite — nothing below
 * synthesises a status.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TwinVpnApp(
    consentGranted: Boolean,
    notificationsAllowed: Boolean,
    onRequestConsent: () -> Unit,
    onOpenVpnSettings: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    var destination by remember { mutableStateOf(Destination.STATUS) }

    // The core has published nothing yet. See the function documentation: this
    // is honest rather than convenient.
    val rendered: Rendered? = null

    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
        bottomBar = {
            NavigationBar {
                for (item in Destination.entries) {
                    NavigationBarItem(
                        selected = destination == item,
                        onClick = { destination = item },
                        icon = {},
                        label = { Text(stringResource(labelFor(item))) },
                    )
                }
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (destination) {
                Destination.STATUS -> StatusScreen(
                    rendered = rendered,
                    consentGranted = consentGranted,
                    notificationsAllowed = notificationsAllowed,
                    onRequestConsent = onRequestConsent,
                    onOpenVpnSettings = onOpenVpnSettings,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                )
                Destination.PEERS -> PeersScreen()
                Destination.PAIRING -> PairingScreen()
                Destination.DIAGNOSTICS -> DiagnosticsScreen(rendered)
            }
        }
    }
}

/**
 * The label for a destination.
 *
 * A `when` over a **UI enum this file defines**, not over a domain fact. CB-2
 * bans the latter; navigation is presentation and is squarely CB-4's.
 */
private fun labelFor(destination: Destination): Int = when (destination) {
    Destination.STATUS -> R.string.nav_status
    Destination.PEERS -> R.string.nav_peers
    Destination.PAIRING -> R.string.nav_pairing
    Destination.DIAGNOSTICS -> R.string.nav_diagnostics
}
