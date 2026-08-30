package net.twinvpn.android

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import net.twinvpn.android.core.CoreClient
import net.twinvpn.android.core.Rendered
import net.twinvpn.android.vpn.TwinVpnService
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * **The link-and-run proof for Android**, and the one file in
 * `app/src/androidTest/` that is meant to go green on an ordinary emulator.
 *
 * Authority: ADR-0018 §11.9 row 3 (`cdylib` in the AAB, four ABIs, ≤ 6 MB per
 * ABI, `LOAD` alignment ≥ 0x4000), §11.5's Android rows (*"`VpnService` — loads
 * the core"*), F-1…F-8, F-10, CB-2, CD-I5, PB-1, VR-4; ADR-0022 §11.3, §11.4,
 * LC-33; `docs/implementation/ownership.md` §10.4, §10.5.
 *
 * # How this differs from the three files beside it
 *
 * `LifecycleMatrixTest`, `DozeAndRevocationTest` and `LeakMeasurementTest` are
 * **device-farm** suites: every helper in them is `TODO("device farm")`, they
 * fail on the first run by design, and `shells/android/README.md` §3.4 says so.
 * They describe what a farm must measure.
 *
 * This file measures what an *emulator* can, and every assertion in it is meant
 * to hold on `ubuntu-24.04` + an `x86_64` system image with no device, no root,
 * no packet capture and no second VPN app:
 *
 * | Boundary | Crossed here |
 * |---|---|
 * | the two `.so`s load | `NativeBridge`'s `init` — `System.loadLibrary` for the adapter **and** the core's JNI carriage |
 * | the core is created | `nativeCoreCreate` → `tw_core_create` (VR-4 checks `abi_major` first) |
 * | core code is invoked | `nativeCoreSubmit` → `tw_core_submit` → `Core::submit` |
 * | a result comes back | the F-4 refusal envelope, and an event frame off `tw_core_next_event` |
 * | the core renders | `nativeRenderDiagnostic` → `tw_render_diagnostic` (F-10) |
 * | the production consumer | [`CoreClient`], on its own drain thread (F-6/S-47) |
 * | the application lifecycle | [`TwinVpnService`] really started and really destroyed by the system |
 * | ABI packaging | the installed APK's own `lib/<abi>/` entries |
 *
 * `build/ci/ci-android.sh` reads the lifecycle transitions out of logcat rather
 * than hard-coding them — see [transition].
 *
 * # What is NOT here, and exactly why (M-19)
 *
 * No `VpnService.establish()`, and consent is only half the reason.
 *
 * Consent is grantable without a dialog — `appops set <package> ACTIVATE_VPN
 * allow` is what the system records when the dialog is accepted, and
 * `ci-android.sh` could run it over `adb shell`. What is missing is the thing to
 * establish *with*. `VpnService.Builder` is an inner class of a **running
 * `VpnService` instance**, and the only one this package declares is
 * [`TwinVpnService`], which establishes when the core applies a
 * `NetworkContract` — i.e. after pairing, which an emulator has no peer for. A
 * test-owned `VpnService` cannot substitute: `src/androidTest/` is packaged as
 * `net.twinvpn.android.test`, a **separate package with its own uid**, and the
 * platform redacts what it hands a caller about a VPN it does not own — so
 * observing that tunnel would answer a different question.
 *
 * So the re-entrancy is proved in two halves. The **adapter** half runs on a
 * Linux host: `bridge::tests::reentrancy` drives the whole `establish()`
 * fan-out through the real decoder, the real snapshot and the real
 * `setUnderlyingNetworks` call. The **platform** half is
 * [`the_watchers_own_request_is_accepted_and_onAvailable_arrives_first`] below —
 * what an emulator can measure without a tunnel: that the request
 * `ConnectivityWatcher` registers is accepted, and that the first callback of a
 * fan-out really does arrive before the network has been described, which is the
 * window in which an observation cannot be classified.
 *
 * Closing the remaining half needs a `<service>` in **`src/main/`**'s manifest
 * plus the `appops` grant in CI, or a device farm. Neither is this file's.
 */
@RunWith(AndroidJUnit4::class)
class NativeLinkRunTest {

    private companion object {
        const val TAG = "TwinVPN.CI"

        /** `twinvpn_mgmt::envelope::LENGTH_PREFIX_BYTES`. */
        const val PREFIX_BYTES = 4

        /**
         * The ABIs ADR-0018 §11.9 row 3 requires, in the NDK's spelling.
         *
         * The ADR names Rust triples — `aarch64-linux-android`,
         * `armv7-linux-androideabi`, `x86_64-linux-android`,
         * `i686-linux-android` — and `app/build.gradle.kts`'s `abiFilters`
         * names the same four as Android spells them. Both are the source; this
         * list is the assertion.
         */
        val REQUIRED_ABIS = setOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

        /** How long one `tw_core_next_event` call blocks. Not a deadline. */
        const val DRAIN_TIMEOUT_MS = 250

        /** How many `next_event` calls a bounded wait makes before failing. */
        const val DRAIN_ATTEMPTS = 40
    }

    /**
     * One lifecycle marker, in the strict format `build/ci/ci-android.sh`
     * greps out of logcat.
     *
     * Called **after** the transition is observed, never in advance. A script
     * that hard-coded the list would report the same transitions whether or not
     * the test drove any, which is the compile-only job dressed as a lifecycle
     * job that `build/acceptance/platform-evidence.schema.json` rejects.
     *
     * The names are `androidx.lifecycle.Lifecycle.State`'s and the platform's
     * own service callbacks — `INITIALIZED`, `CREATED`, `STARTED`, `DESTROYED`
     * — because that is Android's application-lifecycle vocabulary (ADR-0022
     * §11.3's Android row) rather than one invented here.
     */
    private fun transition(from: String, to: String) {
        val line = "TWINVPN_LIFECYCLE_TRANSITION $from->$to"
        Log.i(TAG, line)
        println(line)
    }

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    // -----------------------------------------------------------------------
    // 1. the production JNI boundary
    // -----------------------------------------------------------------------

    /**
     * The two libraries load, the core is created, core code is invoked, and a
     * result comes back — all through the entries `TwinVpnService` itself uses.
     *
     * **Two `.so`s, not one.** CD-I5 forbids `twinvpn-platform-android` to name
     * `twinvpn-core`, so the core's JNI entries live in
     * `libtwinvpn_android_jni.so` and the adapter in
     * `libtwinvpn_platform_android.so`. `NativeBridge`'s `init` loads both, and
     * an `UnsatisfiedLinkError` here is ADR-0018 VR-4's packaging defect.
     */
    @Test
    fun the_two_libraries_load_and_the_core_answers_across_the_production_jni_boundary() {
        // Touching the object runs its `init`, which is the `System.loadLibrary`
        // pair. A failure is an `UnsatisfiedLinkError` and is allowed to be
        // fatal: an app running without its core would report a posture it
        // cannot know.
        val handle = NativeBridge.nativeCoreCreate(ByteArray(0))
        assertNotEquals(
            "tw_core_create returned 0: the core refused, which is either an " +
                "abi_major mismatch (a packaging defect, VR-4) or an unavailable adapter",
            0L,
            handle,
        )
        Log.i(TAG, "tw_core_create: handle acquired")

        try {
            // ---- a result comes back, deterministically --------------------
            //
            // An unknown operation is refused SYNCHRONOUSLY with the F-4
            // envelope — codes and typed evidence, never a sentence (MI-15) —
            // so this needs no timing at all. `tw_core_submit` accepts the bare
            // operation name as well as a framed request, which is what lets
            // this test name an operation without re-implementing
            // `twinvpn_mgmt`'s framing.
            val refusal = NativeBridge.nativeCoreSubmit(
                handle,
                "twinvpn.ci.no.such.operation".toByteArray(Charsets.UTF_8),
            )
            assertNotNull(
                "an unknown operation must come back as an F-4 envelope, not as silence",
                refusal,
            )
            assertTrue("the envelope carries bytes", refusal!!.isNotEmpty())

            // F-10: the core owns every rendered string. A shell that composed
            // one would be making the judgement CB-4 removes from it.
            val rendered = NativeBridge.nativeRenderDiagnostic(
                "MGMT.OP_UNKNOWN",
                refusal,
                "en-US",
                ByteArray(0),
            )
            assertNotNull("tw_render_diagnostic never returns null", rendered)
            Log.i(TAG, "tw_render_diagnostic: ${rendered!!.size} bytes back across JNI")

            // ---- an accepted operation, and its event ----------------------
            val accepted = NativeBridge.nativeCoreSubmit(
                handle,
                "status.get".toByteArray(Charsets.UTF_8),
            )
            assertNull("status.get is in the catalogue and must be accepted", accepted)

            // F-5: "all state changes, including the completion of a submitted
            // command, arrive as events on exactly one totally ordered stream".
            // Bounded, because a stream that never carries it must fail rather
            // than hang.
            var body: JSONObject? = null
            for (attempt in 0 until DRAIN_ATTEMPTS) {
                val frame = NativeBridge.nativeCoreNextEvent(handle, DRAIN_TIMEOUT_MS)
                    ?: continue // a timeout, a wake, or a refusal: ask again.
                body = decodeBody(frame)
                if (body != null) break
            }
            assertNotNull(
                "the core published the outcome of status.get and nothing delivered it",
                body,
            )
            assertEquals(
                "the frame the core pushed is an event, not a response",
                "event",
                body!!.optString("kind"),
            )
            Log.i(TAG, "tw_core_next_event: topic=${body.optString("topic")}")
        } finally {
            // `tw_core_wake` first, so nothing is inside a blocking call, then
            // destroy. CB-6: destroying the core does NOT tear down enforcement.
            NativeBridge.nativeCoreWake(handle)
            NativeBridge.nativeCoreDestroy(handle)
        }
    }

    /**
     * The **production consumer**: `CoreClient`'s drain thread over a real core.
     *
     * `CoreClient` used to be a stub (`start()` slept, `requestConnect()`
     * logged) and `TwinVpnService.onStartCommand` called it, so the app ran an
     * adapter with no core behind it. This drives the real one: one thread, one
     * `tw_core_next_event` loop, `tw_core_wake` to stop it, and a join rather
     * than an interrupt — a thread killed inside a JNI call leaves the core
     * holding a lock nobody will release.
     */
    @Test
    fun the_core_client_drains_the_one_ordered_stream_and_stops_without_leaking_its_thread() {
        val handle = NativeBridge.nativeCoreCreate(ByteArray(0))
        assertNotEquals(0L, handle)

        val seen = mutableListOf<Rendered>()
        val client = CoreClient(handle)
        client.subscribe { rendered -> synchronized(seen) { seen += rendered } }
        client.start()
        try {
            // The same submission `TwinVpnService.onStartCommand` makes. A shell
            // that enumerated peers here would be holding a decision CB-2
            // removes from it.
            client.requestNetUp()
            client.requestNetDown()
        } finally {
            client.stop()
            NativeBridge.nativeCoreDestroy(handle)
        }
        // The assertion is that the drain ran and stopped, not that a particular
        // diagnostic appeared: `CoreClient` publishes only the three
        // diagnostic-bearing topics, and a clean `net.up` legitimately produces
        // none. `stop()` returning is the fact under test — it wakes an
        // in-flight `next_event` and joins.
        Log.i(TAG, "CoreClient: drain started and stopped, ${seen.size} rendered diagnostic(s)")
    }

    // -----------------------------------------------------------------------
    // 2. the application lifecycle
    // -----------------------------------------------------------------------

    /**
     * The real [`TwinVpnService`] is created by the system, reaches
     * `onStartCommand`, and is destroyed — with the real core and the real
     * adapter inside it.
     *
     * This is the transition set `ci-android.sh` records. Each marker is printed
     * only after the state has been **observed** through
     * `ActivityManager.getRunningServices`, which on API 26+ returns the
     * caller's own services and nothing else — so it is an OS answer rather than
     * a flag this test set.
     *
     * `startForegroundService`, not `startService`: ADR-0022 LC-33 makes a
     * user-started tunnel a foreground service, `onStartCommand` posts the
     * ongoing notification, and Android 8+ refuses a background `startService`.
     */
    @Test
    fun the_vpn_service_is_created_started_and_destroyed_by_the_system() {
        val ctx = context
        assertTrue(
            "a previous test left the service running; the emulator is not clean",
            !serviceRunning(ctx),
        )

        ctx.startForegroundService(TwinVpnService.Intents.start(ctx))
        assertTrue(
            "TwinVpnService did not reach onCreate: check logcat for 'the platform " +
                "adapter could not be created' or 'the core could not be created', " +
                "both of which stopSelf()",
            await { serviceRunning(ctx) },
        )
        transition("INITIALIZED", "CREATED")
        // onStartCommand has run by the time the service is listed as running
        // with a foreground notification; the start intent carried ACTION_START,
        // so `net.up` was submitted to the core inside it.
        transition("CREATED", "STARTED")

        ctx.startService(TwinVpnService.Intents.stop(ctx))
        assertTrue(
            "ACTION_STOP must stopSelf(); ADR-0022 LC-2 row 4 makes it durable",
            await { !serviceRunning(ctx) },
        )
        transition("STARTED", "DESTROYED")
    }

    // -----------------------------------------------------------------------
    // 3. ABI packaging
    // -----------------------------------------------------------------------

    /**
     * The installed package carries **every** Phase-1 ABI, not just the one this
     * emulator runs.
     *
     * ADR-0018 §11.9 row 3 lists four Rust triples and
     * `app/build.gradle.kts`'s `abiFilters` lists the same four as Android
     * spells them. A build that quietly shipped one ABI would pass every other
     * test in this file — the emulator's own — and fail on a user's phone with
     * `UnsatisfiedLinkError`, which VR-4 classes as a packaging defect.
     *
     * The APK under test is the one the emulator installed, read through
     * `ApplicationInfo.sourceDir`. `ci-android.sh` makes the same assertion
     * against the **release** artifact, which this on-device test cannot see.
     */
    @Test
    fun the_installed_package_carries_every_phase_one_abi() {
        val apk = context.applicationInfo.sourceDir
        val abis = ZipFile(apk).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("lib/") && it.endsWith(".so") }
                .map { it.removePrefix("lib/").substringBefore('/') }
                .toSet()
        }
        Log.i(TAG, "packaged ABIs: ${abis.sorted()}")
        assertEquals(
            "ADR-0018 §11.9 row 3 and app/build.gradle.kts:30 require all four",
            REQUIRED_ABIS,
            abis.intersect(REQUIRED_ABIS),
        )

        // And both libraries are present for each of them: one `.so` per ABI
        // would satisfy the check above while still missing the core's carriage.
        val libraries = ZipFile(apk).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("lib/") && it.endsWith(".so") }
                .map { it.substringAfterLast('/') }
                .toSet()
        }
        assertTrue(
            "libtwinvpn_platform_android.so is missing: $libraries",
            "libtwinvpn_platform_android.so" in libraries,
        )
        assertTrue(
            "libtwinvpn_android_jni.so is missing (CD-I5 makes it a SECOND library): $libraries",
            "libtwinvpn_android_jni.so" in libraries,
        )
    }

    // -----------------------------------------------------------------------
    // 4. the watcher's own request, on the real ConnectivityManager
    // -----------------------------------------------------------------------

    /**
     * **M-19's platform half.** The request `ConnectivityWatcher` registers is
     * accepted by the real `ConnectivityManager`, and the first callback of a
     * fan-out arrives **before** the network has been described.
     *
     * `ConnectivityWatcher.start()` removes `NET_CAPABILITY_NOT_VPN`, which
     * lifts the `NOT_VPN` filter `NetworkRequest.Builder` applies by default —
     * so a competing VPN, and our own tunnel once `establish()` runs, match as
     * ordinary observations. The request is rebuilt here verbatim rather than
     * reached through the watcher, because the watcher publishes into a bridge
     * handle this test does not own.
     *
     * The assertion that matters is the **order**. `onAvailable(Network)` is
     * delivered first, with neither `NetworkCapabilities` nor `LinkProperties`
     * yet cached, so `NetworkCodec.encode(network, null, null, isUp = true)`
     * writes an empty transport bitset and the name `"unknown"`. That
     * observation cannot be classified, and after `establish()` the
     * unclassifiable one is **our own tunnel** — which
     * `AndroidBridge::on_network` must not let redefine the underlay. If a
     * future Android stops delivering the bare `onAvailable` first, this fails
     * and the adapter's guard becomes dead weight rather than silently wrong.
     */
    @Test
    fun the_watchers_own_request_is_accepted_and_onAvailable_arrives_first() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager is unavailable")
        val request = NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val order = mutableListOf<String>()
        fun record(entry: String) = synchronized(order) { order += entry }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = record("available")

            override fun onCapabilitiesChanged(
                network: Network,
                caps: NetworkCapabilities,
            ) = record("capabilities:vpn=${caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)}")

            override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) =
                record("link:name=${link.interfaceName ?: "none"}")
        }

        manager.registerNetworkCallback(request, callback)
        try {
            // Two, not three: `onAvailable` and `onCapabilitiesChanged` are what
            // the assertions below read, and requiring the `LinkProperties`
            // callback as well would make this fail on timing rather than on the
            // property under test.
            assertTrue(
                "the emulator delivered no fan-out at all; either it has no " +
                    "network or the watcher's request matched nothing",
                await { synchronized(order) { order.size } >= 2 },
            )
        } finally {
            manager.unregisterNetworkCallback(callback)
        }

        val delivered = synchronized(order) { order.toList() }
        Log.i(TAG, "the watcher's request delivered: $delivered")
        assertEquals(
            "onAvailable is delivered before the network is described; the " +
                "observation it produces carries no transports and no addresses",
            "available",
            delivered.first(),
        )
        assertTrue(
            "no capabilities callback followed onAvailable: an observation that " +
                "can never be classified would never rejoin the underlay set",
            delivered.any { it.startsWith("capabilities:") },
        )
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /** Whether the system currently lists our own `VpnService` as running. */
    private fun serviceRunning(ctx: Context): Boolean {
        val manager = ctx.getSystemService(ActivityManager::class.java)
        @Suppress("DEPRECATION")
        return manager.getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == TwinVpnService::class.java.name }
    }

    /**
     * Polls `condition` until it holds, or gives up.
     *
     * A bounded wait that FAILS rather than a sleep that hopes: an assertion
     * that passes because the poll was long enough is not an assertion.
     */
    private fun await(attempts: Int = 100, condition: () -> Boolean): Boolean {
        repeat(attempts) {
            if (condition()) return true
            Thread.sleep(100)
        }
        return condition()
    }

    /**
     * The `body` object of one management-interface frame.
     *
     * A 4-byte big-endian length and UTF-8 JSON — `twinvpn_mgmt::envelope`'s
     * shape, which MI-20 makes the same on every carriage. `null` for anything
     * that does not decode, because `twinvpn.h` is explicit that an unknown
     * `body.kind` is a forward-compatible event to ignore and never a parse
     * failure.
     */
    private fun decodeBody(frame: ByteArray): JSONObject? {
        if (frame.size <= PREFIX_BYTES) return null
        val declared = ByteBuffer.wrap(frame, 0, PREFIX_BYTES).order(ByteOrder.BIG_ENDIAN).int
        if (declared <= 0 || frame.size < PREFIX_BYTES + declared) return null
        return try {
            JSONObject(String(frame, PREFIX_BYTES, declared, Charsets.UTF_8))
                .optJSONObject("body")
        } catch (_: org.json.JSONException) {
            null
        }
    }
}
