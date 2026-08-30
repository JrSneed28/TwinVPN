package net.twinvpn.android.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import net.twinvpn.android.NativeBridge

/**
 * `ConnectivityManager.NetworkCallback` → the bridge. **Event-driven, never
 * polled.**
 *
 * Authority: `docs/networking.md` §5.1 (*"subscribe_network_change(cb) —
 * event-driven, never polled"*), §5.2's Android row, §5.4's roaming row;
 * ADR-0018 CB-2, F-9's inversion.
 *
 * # There is no timer in this file, and that is the requirement
 *
 * §5.1's rule is not about efficiency: *"a poll interval is a window in which
 * the host has moved networks and the core still believes it has not"*, and
 * every roaming deadline in `docs/reliability.md` §5 is measured from the moment
 * the change is **known**. A poll interval would be added directly to
 * `T_FAILOVER_TARGET`.
 *
 * # Why the callback is registered for *all* networks
 *
 * `registerDefaultNetworkCallback` reports only the network the system has
 * chosen as default. A Wi-Fi↔cellular handoff is then a single
 * `onAvailable(cellular)` with no `onLost(wifi)`, and the core loses the fact
 * that the Wi-Fi underlay went away — which is exactly what
 * `docs/networking.md` §5.4's roaming row turns into `MIGRATING`.
 * `registerNetworkCallback` is a **listen**: it reports every network that
 * matches the request as it appears and stops matching, so both halves of the
 * handoff arrive. The request's capability set is not empty and has nothing to
 * do with this — see [start].
 *
 * # Nothing here classifies
 *
 * Each callback encodes what the platform said and hands it across. The diff
 * that turns Android's whole-current-state callbacks into the seam's deltas, and
 * the classification of those deltas, are both Rust's — and
 * `twinvpn-platform-android`'s tests exercise every case of it on a Linux host.
 */
internal class ConnectivityWatcher(
    context: Context,
    private val handle: () -> Long,
) {
    private val manager =
        context.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager is unavailable")

    /**
     * The last capabilities and link properties seen per network.
     *
     * Android delivers `onCapabilitiesChanged` and `onLinkPropertiesChanged`
     * independently, and each carries only its own half. Encoding one half with
     * the other missing would tell the core that a network lost its addresses,
     * so both halves are held and every callback sends the **whole** current
     * picture — which is the shape the Rust diff expects.
     */
    private val capabilities = HashMap<Long, NetworkCapabilities>()
    private val links = HashMap<Long, LinkProperties>()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = publish(network, up = true)

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            synchronized(this@ConnectivityWatcher) {
                capabilities[network.networkHandle] = caps
            }
            publish(network, up = true)
        }

        override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) {
            synchronized(this@ConnectivityWatcher) {
                links[network.networkHandle] = link
            }
            publish(network, up = true)
        }

        override fun onLost(network: Network) {
            synchronized(this@ConnectivityWatcher) {
                capabilities.remove(network.networkHandle)
                links.remove(network.networkHandle)
            }
            val held = handle()
            if (held != 0L) NativeBridge.nativeOnNetworkLost(held, network.networkHandle)
        }

        /**
         * The system is about to lose this network.
         *
         * Reported as an ordinary observation with `isUp = false` rather than as
         * a loss: it has not gone yet, and reporting it as gone would make the
         * core tear down a path that is still carrying traffic. `onLost` follows
         * and *is* the loss.
         */
        override fun onLosing(network: Network, maxMsToLive: Int) = publish(network, up = false)
    }

    /** Starts watching. Idempotent at the manager's level. */
    fun start() {
        // `NetworkRequest.Builder()` does NOT start empty: its default
        // capability set is NOT_RESTRICTED | TRUSTED | NOT_VPN, and removing
        // NOT_VPN leaves the other two in place. What it buys is exactly one
        // thing — VPN networks match, so a competing VPN (and our own tunnel,
        // once `Builder.establish()` runs) arrives as an ordinary observation
        // for Rust to classify `Tunnel`. `bridge::AndroidBridge::on_revoked`
        // documents why that is deliberate.
        //
        // Getting BOTH halves of a handoff is not this call's doing: it comes
        // from `registerNetworkCallback` reporting every matching network,
        // rather than `registerDefaultNetworkCallback` reporting only the
        // chosen default. See the class documentation.
        val request = NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        manager.registerNetworkCallback(request, callback)
    }

    /** Stops watching. Safe to call when `start` was never reached. */
    fun stop() {
        runCatching { manager.unregisterNetworkCallback(callback) }
    }

    private fun publish(network: Network, up: Boolean) {
        val held = handle()
        if (held == 0L) return
        val (caps, link) = synchronized(this) {
            capabilities[network.networkHandle] to links[network.networkHandle]
        }
        NativeBridge.nativeOnNetwork(
            held,
            NetworkCodec.encode(network, caps, link, isUp = up),
        )
    }
}
