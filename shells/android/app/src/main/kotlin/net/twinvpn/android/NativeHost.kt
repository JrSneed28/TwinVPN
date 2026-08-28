package net.twinvpn.android

import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.net.InetAddress
import net.twinvpn.android.keystore.TwinKeystore

/**
 * Everything the Rust adapter calls back into.
 *
 * Authority: `docs/implementation/ownership.md` §10.4, ADR-0018 CB-2, CB-5,
 * CB-7, PB-1; ADR-0012 **KS-9(1)**; ADR-0020 §11's Android rows.
 *
 * # Every method here is one statement, and that is the design
 *
 * §10.4: *"Swift and Kotlin marshal; they do not decide."* The strongest form
 * of that available is a class in which **no method contains a branch**. Read
 * them: each is a single call on a `VpnService.Builder`, a `VpnService`, or
 * [TwinKeystore]. There is no `when`, no `if` on any value that came from the
 * core, and nothing that could be a second implementation of a decision.
 *
 * The loop that *is* a decision — which `Builder` operations, in which order,
 * with `0.0.0.0/0` **and** `::/0` claimed together — is in Rust
 * (`twinvpn_platform_android::builder`), is exercised by `make test` on a Linux
 * host, and is type-checked for `aarch64-linux-android` by `make cross-check`.
 * Putting the walk here instead would have moved it into §9.2's *written, not
 * compiled* row for no benefit.
 *
 * # Threading
 *
 * Rust attaches the calling thread to the JVM and calls these from whichever
 * thread it is on — a binder thread, its own datapath thread, or the thread that
 * called `nativeCreate`. The builder is therefore guarded: `builderReset`
 * through `builderEstablish` are one sequence and must not interleave.
 */
internal class NativeHost(
    private val service: VpnService,
    private val keystore: TwinKeystore,
    private val sessionLabel: String,
) {
    private val lock = Any()

    /** The builder under construction, between `builderReset` and `builderEstablish`. */
    private var builder: VpnService.Builder? = null

    /** The descriptor `establish()` most recently produced, for `closeTun`. */
    private var descriptor: ParcelFileDescriptor? = null

    /** The networks Rust last named as the underlay. Kept so a re-`establish`
     *  does not lose them. */
    @Volatile
    private var underlying: Array<Network>? = null

    // -----------------------------------------------------------------------
    // VpnService.Builder — one statement each
    // -----------------------------------------------------------------------

    /**
     * Starts a fresh `Builder`, discarding any partial configuration.
     *
     * `docs/networking.md` §2.3: partial application is the leak window. A
     * failed programme leaves a builder that is thrown away, never one that is
     * established.
     */
    fun builderReset() = synchronized(lock) {
        builder = service.Builder().setSession(sessionLabel)
    }

    /** `Builder.setMtu`. */
    fun builderSetMtu(mtu: Int) = synchronized(lock) {
        requireBuilder().setMtu(mtu)
        Unit
    }

    /**
     * `Builder.addAddress`.
     *
     * Octets, not text. `twinvpn-types`' address types have no `Display` because
     * ADR-0015 §11.4 classes an address `SENSITIVE`, so an address never becomes
     * a string on its way here.
     */
    fun builderAddAddress(octets: ByteArray, prefixLength: Int) = synchronized(lock) {
        requireBuilder().addAddress(InetAddress.getByAddress(octets), prefixLength)
        Unit
    }

    /**
     * `Builder.addRoute`.
     *
     * A full tunnel calls this with `0.0.0.0/0` **and** `::/0` — ADR-0012
     * §11.6's Android row, and ADR-0010 R1. Which routes arrive is Rust's; this
     * method adds whichever it is given.
     */
    fun builderAddRoute(octets: ByteArray, prefixLength: Int) = synchronized(lock) {
        requireBuilder().addRoute(InetAddress.getByAddress(octets), prefixLength)
        Unit
    }

    /** `Builder.addDnsServer`. */
    fun builderAddDnsServer(octets: ByteArray) = synchronized(lock) {
        requireBuilder().addDnsServer(InetAddress.getByAddress(octets))
        Unit
    }

    /** `Builder.addSearchDomain`. */
    fun builderAddSearchDomain(domain: String) = synchronized(lock) {
        requireBuilder().addSearchDomain(domain)
        Unit
    }

    /**
     * `Builder.addDisallowedApplication`.
     *
     * A **deny** list, never `addAllowedApplication`: the allow-list form makes
     * the tunnel's coverage the complement of a list a newly installed app is
     * not on, which is fail-open as the app set changes.
     */
    fun builderAddDisallowedApplication(packageName: String) = synchronized(lock) {
        requireBuilder().addDisallowedApplication(packageName)
        Unit
    }

    /** `Builder.setBlocking`. */
    fun builderSetBlocking(blocking: Boolean) = synchronized(lock) {
        requireBuilder().setBlocking(blocking)
        Unit
    }

    /**
     * `Builder.establish()`, detaching the descriptor.
     *
     * Returns `-1` when the system declines — consent absent, or another app
     * holds the platform's single VPN slot. Rust maps that to
     * `PLATFORM.VPN_PERMISSION_DENIED`, which ADR-0019's Android row routes to
     * `Settings.ACTION_VPN_SETTINGS`.
     *
     * **PB-1**: the descriptor is detached here and read directly by Rust
     * thereafter — zero JNI crossings per packet.
     */
    fun builderEstablish(): Int = synchronized(lock) {
        val established = requireBuilder().establish() ?: return -1
        descriptor?.close()
        descriptor = established
        underlying?.let { service.setUnderlyingNetworks(it) }
        established.detachFd()
    }

    /** Closes the descriptor `establish()` produced. Idempotent. */
    fun closeTun(@Suppress("UNUSED_PARAMETER") fd: Int) = synchronized(lock) {
        descriptor?.close()
        descriptor = null
    }

    // -----------------------------------------------------------------------
    // VpnService
    // -----------------------------------------------------------------------

    /**
     * `VpnService.setUnderlyingNetworks`.
     *
     * `docs/networking.md` §5.4's roaming row requires this to be kept current
     * across Wi-Fi/cellular handoff so the system accounts and routes correctly.
     * An empty array means the system default, which is what `null` expresses.
     */
    fun setUnderlyingNetworks(handles: LongArray) {
        val networks = handles.map { Network.fromNetworkHandle(it) }.toTypedArray()
        underlying = networks.takeIf { it.isNotEmpty() }
        service.setUnderlyingNetworks(underlying)
    }

    /**
     * `VpnService.protect(int)`.
     *
     * **ADR-0012 KS-9(1) understates this for Android.** The clause reads
     * "iOS/Android — implicit, the provider's own sockets are excluded from its
     * own tunnel by construction", which is true on iOS and false here: a
     * `VpnService` claiming `0.0.0.0/0` captures its own process's traffic like
     * any other app's, and the exclusion is this explicit call per descriptor.
     * Rust calls it for every socket it opens, before the socket is used, and
     * refuses to hand an unprotected one to the core.
     */
    fun protectSocket(fd: Int): Boolean = service.protect(fd)

    /**
     * A kernel-side `SocketKeepalive` on `fd`.
     *
     * `docs/networking.md` §5.4's Doze row: *"keepalives scheduled via the
     * tunnel socket's own kernel-side timer where possible, **not app-side
     * alarms**"*. There is no `AlarmManager` anywhere in this shell, and
     * `ownership.md` §10.2 forbids one.
     *
     * The interval is chosen by the core; this method neither picks nor clamps
     * it. Rust has already refused an interval outside the platform's documented
     * `[10, 3600]` window and told the core so, so a value reaching here is one
     * the platform accepts.
     */
    fun requestKeepalive(fd: Int, intervalSeconds: Int) {
        SocketKeepaliveHolder.request(service, fd, intervalSeconds)
    }

    // -----------------------------------------------------------------------
    // Android Keystore (CB-5 and CB-7)
    // -----------------------------------------------------------------------

    /** `0` StrongBox, `1` TEE, `2` software keymaster, anything else absent. */
    fun securityLevel(): Int = keystore.securityLevel()

    /** `device_id ‖ identity_id ‖ generation ‖ spki`. */
    fun identityPublic(): ByteArray? = keystore.identityPublic()

    /** Signs inside the element. ES256, never exported (§11.16 (c)). */
    fun identitySign(keyTag: Int, generation: Int, message: ByteArray): ByteArray? =
        keystore.sign(keyTag, generation, message)

    /** The Android Key Attestation chain, or `null` (`HARDWARE_UNATTESTED`). */
    fun attestation(): ByteArray? = keystore.attestation()

    /** Reads a Tier-1 item. `null` is **absent**, which is a normal first run. */
    fun itemRead(key: String): ByteArray? = keystore.read(key)

    /**
     * Writes a Tier-1 item, atomically.
     *
     * CB-6a: Keystore AES-256-GCM with `setRandomizedEncryptionRequired(true)`
     * performs the AEAD, which makes Android one of the **two of ten** targets
     * where the SEK is never materialised in core memory.
     */
    fun itemWrite(key: String, value: ByteArray) = keystore.write(key, value)

    /** Deletes a Tier-1 item. Idempotent. */
    fun itemDelete(key: String) = keystore.delete(key)

    private fun requireBuilder(): VpnService.Builder =
        builder ?: throw IllegalStateException("builderReset was not called")
}
