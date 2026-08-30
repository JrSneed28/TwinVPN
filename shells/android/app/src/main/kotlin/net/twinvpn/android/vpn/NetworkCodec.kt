package net.twinvpn.android.vpn

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface
import java.nio.ByteBuffer

/**
 * Encodes one `Network` for [net.twinvpn.android.NativeBridge.nativeOnNetwork].
 *
 * Authority: `docs/implementation/ownership.md` §10.4 (the bridge is internal
 * linkage, versionless, one artifact from one commit), §6 rules 9 and 10;
 * ADR-0018 CB-2.
 *
 * # This is a writer, not a protocol
 *
 * The layout is defined once, in Rust, at
 * `twinvpn_platform_android::bridge::wire`, together with **every bound it
 * validates** — payload size, name length, address and resolver counts, prefix
 * canonicality, the link-local zone rule. This class writes that layout and
 * validates nothing, because validating here would be a second implementation
 * of the same rule and the two would drift.
 *
 * The Rust decoder treats what arrives as **untrusted input** whatever wrote it,
 * refuses on any violation, and is round-tripped against its own encoder by
 * `bridge::wire::tests::a_network_round_trips_through_the_wire` — which is what
 * keeps this writer honest without a test that cannot run.
 *
 * # No decision is taken here
 *
 * Every value written is read straight off `NetworkCapabilities` or
 * `LinkProperties`. There is no threshold, no preference, no classification: the
 * transports go across as a bitset rather than as "this is Wi-Fi", and Rust's
 * `link_class` decides what that means — including the rule that a
 * `TRANSPORT_VPN` network is a *tunnel* even when it also carries Wi-Fi.
 */
internal object NetworkCodec {

    /** Must equal `twinvpn_platform_android::bridge::wire::WIRE_VERSION`. */
    private const val WIRE_VERSION: Byte = 1

    private const val FLAG_UP = 1
    private const val FLAG_METERED = 1 shl 1
    private const val FLAG_PRIVATE_DNS = 1 shl 2
    private const val FLAG_DEFAULT_V4 = 1 shl 3
    private const val FLAG_DEFAULT_V6 = 1 shl 4

    private const val FAMILY_V4: Byte = 4
    private const val FAMILY_V6: Byte = 6

    /**
     * The transport bit positions `NetworkCapabilities` uses. They are the
     * platform's own constants and are mirrored in
     * `twinvpn_platform_android::netchange::TransportSet`.
     */
    private val TRANSPORTS = intArrayOf(
        NetworkCapabilities.TRANSPORT_CELLULAR,
        NetworkCapabilities.TRANSPORT_WIFI,
        NetworkCapabilities.TRANSPORT_BLUETOOTH,
        NetworkCapabilities.TRANSPORT_ETHERNET,
        NetworkCapabilities.TRANSPORT_VPN,
        NetworkCapabilities.TRANSPORT_WIFI_AWARE,
        NetworkCapabilities.TRANSPORT_LOWPAN,
    )

    /**
     * Encodes one observation.
     *
     * `isUp` is `true` while `onLost` has not fired for this `Network`.
     */
    fun encode(
        network: Network,
        capabilities: NetworkCapabilities?,
        link: LinkProperties?,
        isUp: Boolean,
    ): ByteArray {
        val out = ByteArrayOutputStream(192)
        out.write(WIRE_VERSION.toInt())
        out.writeLongBe(network.networkHandle)

        val name = link?.interfaceName ?: "unknown"
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        out.writeShortBe(nameBytes.size)
        out.write(nameBytes)

        out.writeIntBe(transportBits(capabilities))

        var flags = 0
        if (isUp) flags = flags or FLAG_UP
        if (capabilities != null &&
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        ) {
            flags = flags or FLAG_METERED
        }
        if (link != null && link.isPrivateDnsActive) flags = flags or FLAG_PRIVATE_DNS
        if (hasDefaultRoute(link, v6 = false)) flags = flags or FLAG_DEFAULT_V4
        if (hasDefaultRoute(link, v6 = true)) flags = flags or FLAG_DEFAULT_V6
        out.write(flags)

        out.writeIntBe(link?.mtu ?: 0)

        // The RFC 4007 zone Rust needs for `fe80::/10`, resolved ONCE from the
        // interface NAME rather than read off each address.
        //
        // `Inet6Address.getScopeId()` is always `0` here and cannot be anything
        // else: `LinkAddress.writeToParcel` writes only `address.getAddress()`
        // and `createFromParcel` rebuilds through
        // `InetAddress.getByAddress(byte[])`, which has nowhere to put a scope.
        // So every address out of `LinkProperties` — link-locals included —
        // arrives here unscoped, and the Rust decoder refuses a link-local with
        // no interface index. That refusal was `PLATFORM.ADAPTER_UNAVAILABLE` on
        // every ordinary Wi-Fi network, because every one of them has an
        // `fe80::/64`.
        //
        // `NetworkInterface.getIndex()` is `if_nametoindex(name)` — libcore fills
        // it from `getifaddrs()`, a netlink call, not `/proc/net` — which is
        // exactly the kernel index `sock::addr::v6_from_kernel` documents as its
        // input, so `ZoneIndex` means the same thing on both sides. The API-30
        // restriction on this class (a non-system app sees only interfaces
        // associated with an `InetAddress`) cannot bite: the interface being
        // encoded has addresses by definition.
        //
        // Residual, stated rather than papered over: a `LinkProperties` with no
        // interface name leaves this `0`, and its link-local addresses are still
        // refused. The system does deliver that shape — a `CALLBACK_AVAILABLE`
        // for our own tunnel carries an empty `LinkProperties` — and it is
        // harmless there, because a `LinkProperties` with no interface name
        // carries no addresses either.
        val zone = link?.interfaceName
            ?.let { runCatching { NetworkInterface.getByName(it)?.index }.getOrNull() }
            ?: 0

        val addresses = link?.linkAddresses.orEmpty()
        out.write(addresses.size)
        for (address in addresses) {
            // The prefix is written as the platform reports it; Rust refuses a
            // non-canonical one rather than masking it, because masking loses
            // the host address the core actually needs.
            out.write(familyTag(address.address).toInt())
            out.write(address.prefixLength)
            out.writeAddress(address.address, zone)
        }

        val resolvers = link?.dnsServers.orEmpty()
        out.write(resolvers.size)
        for (resolver in resolvers) {
            out.write(familyTag(resolver).toInt())
            // The same parcelling loses the resolvers' scope ids too, and both
            // loops share `read_address` on the Rust side.
            out.writeAddress(resolver, zone)
        }

        val nat64 = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) link?.nat64Prefix else null
        if (nat64 == null) {
            out.write(0)
        } else {
            out.write(1)
            out.write(nat64.address.address)
            out.write(nat64.prefixLength)
        }
        return out.toByteArray()
    }

    private fun transportBits(capabilities: NetworkCapabilities?): Int {
        if (capabilities == null) return 0
        var bits = 0
        for ((index, transport) in TRANSPORTS.withIndex()) {
            if (capabilities.hasTransport(transport)) bits = bits or (1 shl index)
        }
        return bits
    }

    /**
     * Whether `link` carries a default route for the named family.
     *
     * Asked **per family**, because ADR-0010 R6's case — IPv6 appearing after
     * the tunnel is up — is a v6 default arriving while the v4 one is unchanged,
     * and one combined answer would make that indistinguishable from nothing
     * having happened.
     */
    private fun hasDefaultRoute(link: LinkProperties?, v6: Boolean): Boolean =
        link?.routes.orEmpty().any { route ->
            route.isDefaultRoute && (route.destination.address is Inet6Address) == v6
        }

    private fun familyTag(address: java.net.InetAddress): Byte =
        if (address is Inet4Address) FAMILY_V4 else FAMILY_V6

    /**
     * Writes the octets, and for IPv6 the interface's zone.
     *
     * The zone matters for one case and one only: a link-local address is
     * unusable on a multi-homed host without it, and Rust refuses one that
     * arrives with `0`. On any other address it is metadata and Rust drops it,
     * per RFC 4007.
     *
     * `zone` is the **interface's** index, not `Inet6Address.scopeId` — the
     * scope id does not survive `LinkProperties`' parcelling. See [encode].
     */
    private fun ByteArrayOutputStream.writeAddress(address: java.net.InetAddress, zone: Int) {
        write(address.address)
        if (address is Inet6Address) writeIntBe(zone)
    }

    private fun ByteArrayOutputStream.writeShortBe(value: Int) {
        write((value ushr 8) and 0xff)
        write(value and 0xff)
    }

    private fun ByteArrayOutputStream.writeIntBe(value: Int) {
        write(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value).array())
    }

    private fun ByteArrayOutputStream.writeLongBe(value: Long) {
        write(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array())
    }
}
