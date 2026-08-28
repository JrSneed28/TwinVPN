package net.twinvpn.android

import android.net.VpnService
import android.util.Log

/**
 * Holds the `SocketKeepalive` objects the platform hands back.
 *
 * Authority: `docs/networking.md` §5.4's Android Doze row, ADR-0022 LC-31/LC-32,
 * `docs/implementation/ownership.md` §10.2(2).
 *
 * # Why this exists at all
 *
 * `ConnectivityManager.createSocketKeepalive` returns an object that must be
 * kept alive; letting it be collected stops the keepalive. That is bookkeeping,
 * not a decision, and it is the whole content of this file.
 *
 * # What is deliberately absent
 *
 * There is no `AlarmManager`, no `setExactAndAllowWhileIdle`, no `WorkManager`
 * periodic request, and no wake lock. §10.2 forbids the first three as
 * "undocumented background-execution tricks … an app-side alarm cadence chosen
 * to defeat Doze", and the fourth outright. A reviewer can confirm that by
 * grepping this whole module for `AlarmManager` and `WakeLock` and finding
 * nothing, which is the point of concentrating the mechanism here.
 *
 * # The residual, stated
 *
 * `SocketKeepalive` on a **UDP** socket requires the socket to be connected and
 * the platform to support it on the current transport; several OEM builds do
 * not offer it on Wi-Fi. Where it is unavailable the Rust side has already told
 * the core (`KeepalivePlan::Unavailable` carrying `PLATFORM.OS_UNSUPPORTED`),
 * and the core decides — shorten the idle horizon, prefer a relay, or accept the
 * NAT binding loss. **This class never substitutes a mechanism of its own.**
 */
internal object SocketKeepaliveHolder {

    private const val TAG = "TwinVPN.Keepalive"

    /**
     * Requests a keepalive and retains the handle.
     *
     * Implemented as a no-op stub in this wave and marked as such: the
     * `SocketKeepalive` API needs a connected `UdpSocket` object rather than a
     * bare descriptor, and the socket lives on the Rust side (§10.4 puts the NAT
     * ladder there). Bridging a descriptor back into a `java.net.DatagramSocket`
     * so the platform will accept it is a device-verified step this wave cannot
     * take, so it is **written and reported as unverified** rather than written
     * and claimed.
     *
     * The honest consequence: on a real device this currently logs and returns,
     * so the NAT binding is maintained by the core's own keepalive traffic
     * rather than by the kernel timer. That is *slower and more wakeful*, not
     * incorrect, and it is the direction that does not require an undocumented
     * trick. It is recorded in `shells/android/README.md` §6 and in the
     * completion report as a device-farm debt.
     */
    fun request(service: VpnService, fd: Int, intervalSeconds: Int) {
        Log.i(
            TAG,
            "socket keepalive requested (interval=${intervalSeconds}s) — " +
                "not yet bound to the platform API; see README §6",
        )
        // Deliberately no fallback. `ownership.md` §10.2(2).
    }
}
