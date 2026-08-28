package net.twinvpn.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log

/**
 * `BOOT_COMPLETED` — the one OS-owned start trigger a non-DPC Android app has
 * besides always-on VPN itself.
 *
 * Authority: ADR-0022 **LC-9** (*"every supported platform MUST have at least
 * one **OS-owned** start trigger — one the operating system fires without any
 * TwinVPN process already running. A product whose only start path is 'the user
 * opens the app' cannot satisfy R-08 or R-13"*), §11.3's Android row.
 *
 * # What this receiver cannot do, stated rather than attempted
 *
 * ADR-0022 §11.3's Android row names the failure exactly:
 *
 * > If always-on is not configured and the receiver does not fire — most
 * > commonly because the user **force-stopped** the app, which puts it in the
 * > stopped state and disables manifest receivers until the next manual launch —
 * > **there is no protection at all and the app cannot fix it.**
 * > `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS`, user-actionable, plus the
 * > always-on guidance flow. OEM battery managers produce the same outcome.
 *
 * There is no workaround here and there must not be one. The condition is
 * surfaced by the UI on next launch, and the guided flow points at
 * `Settings.ACTION_VPN_SETTINGS` where always-on can be turned on — which is the
 * mechanism that *does* survive a force-stop, because the system starts the
 * service itself.
 *
 * # Why `prepare()` is checked and not called
 *
 * `VpnService.prepare(context)` returns an `Intent` when consent has not been
 * given, and that intent can only be launched from an Activity with a user
 * present. At boot there is none. So a missing consent is not an error here: it
 * is the ordinary state of a device that has never been through first-run, and
 * the receiver simply does not start the service. ADR-0019's Android row already
 * owns the consent flow.
 */
class BootReceiver : BroadcastReceiver() {

    private companion object {
        const val TAG = "TwinVPN.Boot"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }

        // Consent is a user grant that predates this boot or does not exist.
        // Without it there is nothing to start, and nothing to report from a
        // context with no user in front of it.
        if (VpnService.prepare(context) != null) {
            Log.i(TAG, "no VPN consent at boot; the first-run flow owns this")
            return
        }

        // ADR-0022 §11.3: `BOOT_COMPLETED` is one of the exemptions to the
        // Android 12+ restriction on starting a foreground service from the
        // background, so this is permitted where an arbitrary background start
        // would not be.
        val start = TwinVpnService.Intents.start(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(start)
        } else {
            context.startService(start)
        }
    }
}
