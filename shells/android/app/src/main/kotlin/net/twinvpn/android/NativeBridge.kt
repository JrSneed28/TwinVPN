package net.twinvpn.android

/**
 * The **whole** JNI surface between this app and the Rust adapter.
 *
 * Authority: `docs/implementation/ownership.md` §10.4 ("Swift and Kotlin
 * marshal; they do not decide"), ADR-0018 CB-2, §11.5's Android rows.
 *
 * # Five entries in, and every one of them an Android fact
 *
 * §10.4 forbids this bridge growing "a TwinVPN domain fact — an entry that
 * takes or returns a `ConnectionState`, a `reason_code` class, a policy verdict
 * or a candidate priority". Read the declarations below: every parameter is
 * something `ConnectivityManager`, `PowerManager` or `VpnService` said. There is
 * no `setState`, no `reportError(code)`, no `onConnected`.
 *
 * The Rust side asserts this over its own source
 * (`bridge::tests::the_bridge_speaks_android_and_never_twinvpn`), so the
 * prohibition is a test rather than a convention.
 *
 * # Which direction each call goes
 *
 * | Direction | Mechanism |
 * |---|---|
 * | Kotlin → Rust | the `native…` methods here |
 * | Rust → Kotlin | [NativeHost]'s methods, called over JNI from `bridge::jvm` |
 *
 * Nothing else crosses. The tunnel descriptor is detached once at `establish()`
 * and read directly by Rust thereafter — ADR-0018 **PB-1**: *"one JNI call at
 * setup, then direct reads"*, **zero** crossings per packet.
 */
internal object NativeBridge {

    /**
     * The CDYLIB. `System.loadLibrary` throws `UnsatisfiedLinkError` if the ABI
     * is missing, which is a packaging defect (ADR-0018 VR-4) and is allowed to
     * be fatal: an app that ran without its core would report a posture it
     * cannot possibly know.
     */
    init {
        System.loadLibrary("twinvpn_platform_android")
    }

    /**
     * Creates the adapter and returns an opaque handle, or `0` on failure.
     *
     * @param host the object Rust calls back into. Held as a JNI global
     *   reference for the life of the handle.
     * @param storeRoot the **credential-encrypted** vault directory, created by
     *   the caller with its attributes already applied. CB-7 and CD-2: the path
     *   is injected, never discovered by the adapter.
     */
    external fun nativeCreate(host: NativeHost, storeRoot: String): Long

    /** Releases the adapter. Idempotent on `0`. */
    external fun nativeDestroy(handle: Long)

    /**
     * One `Network` as `ConnectivityManager` currently describes it, encoded by
     * [net.twinvpn.android.vpn.NetworkCodec].
     *
     * Called from `onAvailable`, `onCapabilitiesChanged` and
     * `onLinkPropertiesChanged` — Android delivers whole current states, and the
     * *diff* that turns them into deltas is Rust's.
     *
     * @throws IllegalStateException carrying a registered `reason_code` if the
     *   payload violates a bound. The message is a **code**, never a sentence.
     */
    external fun nativeOnNetwork(handle: Long, payload: ByteArray)

    /** `onLost(Network)`. `network` is `Network.getNetworkHandle()`. */
    external fun nativeOnNetworkLost(handle: Long, network: Long)

    /**
     * `PowerManager.isDeviceIdleMode()` / `isPowerSaveMode()`, and whether the
     * current default link is metered.
     *
     * Two booleans. What they mean — ADR-0022 LC-31's timer profile, standby
     * suppression, probe cadence — is decided in the core.
     */
    external fun nativeOnPower(handle: Long, metered: Boolean, lowPower: Boolean)

    /** `VpnService.onRevoke()`. */
    external fun nativeOnRevoked(handle: Long)

    /**
     * What a DPC or managed configuration reported about always-on lockdown.
     *
     * **Three-valued** (`-1` unknown, `0` absent, `1` confirmed), because
     * ADR-0022 **LC-40** requires exactly three and a `Boolean` would make
     * "nobody told us" indistinguishable from "we were told it is off".
     *
     * There is deliberately no probe: under lockdown *our own* sockets are the
     * permitted ones, so a reachability test from this process proves nothing.
     */
    external fun nativeOnLockdownReport(handle: Long, reported: Int)

    /** The three-valued encoding [nativeOnLockdownReport] takes. */
    const val LOCKDOWN_UNVERIFIED: Int = -1

    /** See [LOCKDOWN_UNVERIFIED]. */
    const val LOCKDOWN_ABSENT: Int = 0

    /** See [LOCKDOWN_UNVERIFIED]. */
    const val LOCKDOWN_CONFIRMED: Int = 1
}
