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
        // The core's JNI carriage. A SECOND library, because CD-I5 forbids
        // `twinvpn-platform-android` to name `twinvpn-core` — a platform
        // implementation that could reach the composition root would let a
        // decision migrate downward into it. Merging the two `.so`s to save a
        // load would invert exactly that arrow.
        System.loadLibrary("twinvpn_android_jni")
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

    // -----------------------------------------------------------------------
    // The CORE, across `twinvpn.h`.
    // -----------------------------------------------------------------------
    //
    // Every entry below is a marshalling call and none is an Android fact, so
    // §10.4's prohibition — no `ConnectionState`, no `reason_code` class, no
    // policy verdict, no candidate priority — holds here for a different
    // reason than it does above: these carry OPAQUE BYTES, and a `ByteArray`
    // has no domain meaning to leak.
    //
    // F-8: "only handles, slices and scalars cross; structured data crosses as
    // encoded bytes." That is why none of these takes a typed parameter.

    /**
     * `tw_core_create`. Returns an opaque handle, or `0` on refusal.
     *
     * The `config` slice is empty on this platform: the adapter is linked
     * in-process as a Rust crate, so the core reaches the platform directly
     * rather than back out through F-9 — `ownership.md` §10.4's ruling.
     */
    external fun nativeCoreCreate(config: ByteArray): Long

    /**
     * `tw_core_destroy`. Idempotent on `0`.
     *
     * **Does not tear down enforcement.** CB-6 puts the installed claim in the
     * OS's custody so that the core going away cannot drop protection.
     */
    external fun nativeCoreDestroy(handle: Long)

    /**
     * `tw_core_submit`. Non-blocking (F-5).
     *
     * `command` is one management-interface frame — a 4-byte big-endian length
     * prefix and UTF-8 JSON — whose body is a `request`. Returns `null` on
     * success and the **F-4 envelope** on refusal: codes and typed evidence,
     * never a sentence (MI-15).
     */
    external fun nativeCoreSubmit(handle: Long, command: ByteArray): ByteArray?

    /**
     * `tw_core_next_event`. **The only blocking call in the ABI.**
     *
     * Returns one MI frame, or `null` on a timeout, a wake, or a refusal. The
     * three are deliberately not distinguished: the core's own documentation
     * says a caller tells them apart "by asking again", which is what a drain
     * loop does anyway.
     */
    external fun nativeCoreNextEvent(handle: Long, timeoutMs: Int): ByteArray?

    /**
     * `tw_core_wake`. Cancels an in-flight [nativeCoreNextEvent].
     *
     * Callable from **any** thread, which is what lets shutdown stop the drain
     * loop rather than wait out its timeout — and is why the drain thread is
     * never killed.
     */
    external fun nativeCoreWake(handle: Long)

    /**
     * `tw_render_diagnostic` — **F-10**, the one deliberate exception to F-1's
     * small surface.
     *
     * The core owns every rendered string. A shell that composed one would be
     * making the judgement CB-4 removes from it, and six shells composing them
     * independently is R-31.
     */
    external fun nativeRenderDiagnostic(
        reasonCode: String,
        evidence: ByteArray,
        locale: String,
        platformCtx: ByteArray,
    ): ByteArray?

    /** The three-valued encoding [nativeOnLockdownReport] takes. */
    const val LOCKDOWN_UNVERIFIED: Int = -1

    /** See [LOCKDOWN_UNVERIFIED]. */
    const val LOCKDOWN_ABSENT: Int = 0

    /** See [LOCKDOWN_UNVERIFIED]. */
    const val LOCKDOWN_CONFIRMED: Int = 1
}
