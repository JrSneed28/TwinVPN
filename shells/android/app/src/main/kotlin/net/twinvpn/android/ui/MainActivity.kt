package net.twinvpn.android.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import net.twinvpn.android.vpn.TwinVpnService

/**
 * The single Activity. **It does not load the core.**
 *
 * Authority: ADR-0018 §11.5 (*"Android UI activity | **no** | ADR-0017 over
 * binder | it is a UI"*), CB-2, CB-4; ADR-0019 §11's Android rows (the VPN
 * consent row and the Android 13+ notification row), §11.10(b) (`FLAG_SECURE`);
 * ADR-0016 H2.
 *
 * # What an Activity is permitted to be
 *
 * A renderer and a consent broker. It holds no `tw_core*`, makes no path
 * decision, and can be destroyed at any moment without the tunnel noticing —
 * which is ADR-0022 §11.4's "the app is killed while the extension lives" row in
 * its Android form, and is the property that makes the service the authority.
 *
 * # The two permission flows, and what each costs when refused
 *
 * | Permission | Trigger | Refused | Code |
 * |---|---|---|---|
 * | VPN consent | `VpnService.prepare()` | no tunnel is possible; pairing, the device list, settings and diagnostics stay usable | `PLATFORM.VPN_PERMISSION_DENIED` |
 * | `POST_NOTIFICATIONS` (13+) | first launch | the ongoing notification cannot be posted, **so the anti-silence surface is gone** | reduced-visibility posture, stated in-app |
 *
 * Both are ADR-0019 §11's rows verbatim. Neither refusal is fatal and neither is
 * absorbed: the second in particular is *stated plainly*, because a user who
 * cannot be told that protection stopped needs to know that in advance.
 *
 * # `FLAG_SECURE`
 *
 * ADR-0019 §11.10(b) and S-3: the pairing QR encodes `pairing_secret`, which is
 * **optical-confidential** (ADR-0007 §7.4), so a screenshot, a screen recording
 * or a screen-sharing session defeats it. `FLAG_SECURE` is set for the whole
 * window rather than for the pairing screen alone, because a flag toggled per
 * screen is a flag that is off during the transition into the screen that needs
 * it.
 */
class MainActivity : ComponentActivity() {

    private var consentGranted by mutableStateOf(false)
    private var notificationsAllowed by mutableStateOf(true)

    private val consent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        // `RESULT_OK` means the user approved. Anything else is a refusal, and
        // it is recorded as a fact — the SENTENCE the user reads comes from the
        // core's `PLATFORM.VPN_PERMISSION_DENIED` (CB-4), not from here.
        consentGranted = result.resultCode == Activity.RESULT_OK
        if (consentGranted) startService(TwinVpnService.Intents.start(this))
    }

    private val notifications = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> notificationsAllowed = granted }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // ADR-0019 §11.10(b) / S-3. Set before any content is drawn.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        consentGranted = VpnService.prepare(this) == null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            TwinVpnTheme {
                TwinVpnApp(
                    consentGranted = consentGranted,
                    notificationsAllowed = notificationsAllowed,
                    onRequestConsent = ::requestConsent,
                    onOpenVpnSettings = ::openVpnSettings,
                    onConnect = { startService(TwinVpnService.Intents.start(this)) },
                    onDisconnect = { startService(TwinVpnService.Intents.stop(this)) },
                )
            }
        }
    }

    /**
     * Launches the system's VPN consent dialog.
     *
     * `prepare()` returns `null` when consent already exists, which is not an
     * error and not a reason to show anything.
     */
    private fun requestConsent() {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            consentGranted = true
            startService(TwinVpnService.Intents.start(this))
        } else {
            consent.launch(intent)
        }
    }

    /**
     * ADR-0019 §11's Android next-action target: `Settings.ACTION_VPN_SETTINGS`.
     *
     * This is where always-on and "Block connections without VPN" live, and it
     * is the *only* place they can be turned on — ADR-0012 §11.6's Android
     * limitation row: *"lockdown cannot be enabled programmatically by a non-DPC
     * app"*. So the product guides; it does not enable.
     */
    private fun openVpnSettings() {
        startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
    }
}
