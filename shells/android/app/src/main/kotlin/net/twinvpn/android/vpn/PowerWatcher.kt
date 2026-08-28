package net.twinvpn.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.PowerManager
import net.twinvpn.android.NativeBridge

/**
 * `PowerManager` idle and battery-saver callbacks → the bridge.
 *
 * Authority: `docs/networking.md` §5.2's Android row (*"`PowerManager` idle
 * callbacks"*), §5.4's Doze row; ADR-0022 §11.4's Doze row, **LC-31**,
 * **LC-32**; `docs/implementation/ownership.md` §10.2.
 *
 * # Two booleans, and no response
 *
 * LC-31 lists what the product does about `low_power` and `metered` — adopt the
 * background timer profile, suppress the warm relay standby, move the
 * direct-upgrade prober to event-driven, defer update checks and telemetry — and
 * every one of those is a **core** decision. LC-32 then closes the list of what
 * no power pressure may ever buy: it may not disarm the kill switch, skip a
 * rekey, lengthen liveness detection while traffic is offered, suppress a
 * `reason_code`, stop renewing the `ProtectionAssertion`, or silently reduce
 * scope.
 *
 * So this class observes and reports. It has no threshold, no timer, and no
 * behaviour that changes with what it observes.
 *
 * # What is deliberately not here
 *
 * No wake lock — `ownership.md` §10.2(1) forbids one outright, and there is no
 * `PowerManager.newWakeLock` call anywhere in this shell. Staying scheduled is
 * the foreground service's job (LC-33), which is the *sanctioned* mechanism.
 */
internal class PowerWatcher(
    private val context: Context,
    private val handle: () -> Long,
) {
    private val power = context.getSystemService(PowerManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) = publish()
    }

    /** Starts watching, and reports the posture once so the core starts from a
     *  fact rather than from a default. */
    fun start() {
        val filter = IntentFilter().apply {
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }
        context.registerReceiver(receiver, filter)
        publish()
    }

    /** Stops watching. Safe to call when `start` was never reached. */
    fun stop() {
        runCatching { context.unregisterReceiver(receiver) }
    }

    /**
     * Reads both booleans and hands them across.
     *
     * `isDeviceIdleMode` **or** `isPowerSaveMode` is what the seam's
     * `LinkFacts.low_power` carries; the Rust side keeps the two separable for
     * the diagnostic bundle, because "the device is dozing" and "the user turned
     * battery saver on" have different remediations.
     */
    fun publish() {
        val held = handle()
        if (held == 0L) return
        val lowPower = (power?.isDeviceIdleMode ?: false) || (power?.isPowerSaveMode ?: false)
        val metered = connectivity?.isActiveNetworkMetered ?: false
        NativeBridge.nativeOnPower(held, metered, lowPower)
    }
}
