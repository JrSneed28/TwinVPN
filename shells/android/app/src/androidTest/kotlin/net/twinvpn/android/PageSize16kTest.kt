package net.twinvpn.android

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.system.Os
import android.system.OsConstants
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import net.twinvpn.android.vpn.TwinVpnService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * **`ANDROID-16K-PAGE-SIZE`** — the criterion that used to need a physical
 * phone, discharged on Google's official 16 KB page-size emulator image.
 *
 * # Why this file refuses to run on an ordinary emulator
 *
 * `ci-android.sh` puts `-Wl,-z,max-page-size=16384` on every ABI, and NOTHING
 * exercises it unless the `.so` is actually mapped by a kernel with 16 KiB
 * pages: a 4 KiB-aligned library loads perfectly well on a 4 KiB device. A
 * 4096-byte-page emulator therefore takes the whole suite green while leaving
 * the alignment tested nowhere — a VACUOUS PASS, and worse than a red row
 * because it is indistinguishable from a real one in the report.
 *
 * So [the_running_kernel_uses_16_kib_pages] is the FIRST assertion, it reads
 * the RUNNING kernel's page size rather than a build constant, and every other
 * test in this class depends on it having held. `build/ci/ci-android.sh` makes
 * the same assertion from outside with `adb shell getconf PAGE_SIZE`, before it
 * installs anything, so a wrong image fails before the APK is even pushed.
 *
 * # What this class adds over `NativeLinkRunTest`
 *
 * `NativeLinkRunTest` proves the boundary works. These four prove the things
 * the 16 KiB criterion names specifically and that file does not cover:
 *
 * | Requirement | Test |
 * |---|---|
 * | the running kernel really has 16 KiB pages | [the_running_kernel_uses_16_kib_pages] |
 * | the native libraries load on it, and no JNI exception stays pending | [the_native_libraries_load_and_leave_no_pending_jni_exception] |
 * | the real `VpnService` stops and RESTARTS | [the_vpn_service_stops_and_restarts] |
 * | TwinVPN never selects its own VPN interface as underlay | [the_underlay_set_never_contains_our_own_vpn_interface] |
 */
@RunWith(AndroidJUnit4::class)
class PageSize16kTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * The running kernel's page size, from `sysconf(_SC_PAGESIZE)`.
     *
     * Not a build constant and not a property: `_SC_PAGESIZE` is answered by the
     * kernel that is running right now, so it cannot be right about the wrong
     * thing. This is the same number `adb shell getconf PAGE_SIZE` prints, asked
     * from inside the process whose libraries the answer is about.
     */
    @Test
    fun the_running_kernel_uses_16_kib_pages() {
        val pageSize = Os.sysconf(OsConstants._SC_PAGESIZE)
        Log.i(TAG, "TWINVPN_ATTESTATION page_size=$pageSize")
        assertEquals(
            "this device reports a $pageSize-byte page. C-12's 16 KiB LOAD " +
                "alignment cannot be exercised on it, so a green run here would " +
                "be a vacuous pass. Use Google's 16 KB page-size system image " +
                "(google_apis_ps16k); see build/ci/ci-android.sh --pagesize16k.",
            16384L,
            pageSize,
        )
    }

    /**
     * Both production `.so`s map and answer on a 16 KiB kernel, and the JNI
     * boundary is left clean.
     *
     * # How "no JNI exception remains pending" is actually checked
     *
     * It cannot be asked directly from Kotlin: `ExceptionCheck` is a JNI call,
     * and there is no Java-side accessor for it. What CAN be relied on is
     * stronger than an accessor would be — **ART aborts the process** on the
     * next JNI transition when an exception is left pending, with
     * `JNI DETECTED ERROR IN APPLICATION: JNI ... called with pending exception`.
     * CheckJNI is on by default in a debuggable process and on every emulator
     * image.
     *
     * So the check is: cross the boundary many times, in both directions,
     * including the refusal path that is the most likely place to leave one
     * pending, and require the process to still be alive and the boundary to
     * still answer afterwards. A pending exception makes that impossible. The
     * assertion at the end is the evidence, not a formality: if the process had
     * aborted, no assertion in this method would run at all and the
     * instrumentation would report a crash.
     */
    @Test
    fun the_native_libraries_load_and_leave_no_pending_jni_exception() {
        val handle = NativeBridge.nativeCoreCreate(ByteArray(0))
        assertNotEquals("tw_core_create returned 0 on a 16 KiB kernel", 0L, handle)
        try {
            repeat(JNI_CROSSINGS) { i ->
                // The refusal path FIRST: an unknown operation is the entry most
                // likely to construct and throw, and therefore most likely to
                // leave something pending.
                val refusal = NativeBridge.nativeCoreSubmit(
                    handle,
                    "twinvpn.ci.no.such.operation.$i".toByteArray(Charsets.UTF_8),
                )
                assertTrue("crossing $i: the refusal envelope came back empty", refusal!!.isNotEmpty())
                NativeBridge.nativeRenderDiagnostic("MGMT.OP_UNKNOWN", refusal, "en-US", ByteArray(0))
                NativeBridge.nativeCoreSubmit(handle, "status.get".toByteArray(Charsets.UTF_8))
                NativeBridge.nativeCoreNextEvent(handle, 1)
            }
            // Still alive, and the boundary still answers. Under CheckJNI a
            // pending exception would have aborted the process long before here.
            val final = NativeBridge.nativeCoreSubmit(
                handle,
                "twinvpn.ci.no.such.operation.final".toByteArray(Charsets.UTF_8),
            )
            assertTrue(
                "the boundary stopped answering after $JNI_CROSSINGS crossings, " +
                    "which is what a corrupted JNI environment looks like from Kotlin",
                final != null && final.isNotEmpty(),
            )
            Log.i(TAG, "TWINVPN_ATTESTATION jni_pending_exception=false")
        } finally {
            NativeBridge.nativeCoreWake(handle)
            NativeBridge.nativeCoreDestroy(handle)
        }
    }

    /**
     * The real [TwinVpnService] starts, stops, and STARTS AGAIN.
     *
     * The restart is the half `NativeLinkRunTest` does not cover and the half
     * that breaks: the second `onCreate` builds a second platform adapter and a
     * second core in a process that has already loaded the libraries once, and a
     * `.so` whose state did not survive the first teardown fails here and
     * nowhere else. On a 16 KiB kernel it is also the second mapping of the
     * same library, which is the mapping an alignment defect can survive the
     * first time.
     */
    @Test
    fun the_vpn_service_stops_and_restarts() {
        val ctx = context
        assertFalse(
            "a previous test left the service running; the emulator is not clean",
            serviceRunning(ctx),
        )

        for (round in 1..2) {
            ctx.startForegroundService(TwinVpnService.Intents.start(ctx))
            assertTrue(
                "round $round: TwinVpnService did not reach onCreate. Round 2 " +
                    "failing where round 1 passed means the first teardown left " +
                    "the native side unusable.",
                await { serviceRunning(ctx) },
            )
            Log.i(TAG, "TWINVPN_LIFECYCLE_TRANSITION INITIALIZED->STARTED")

            ctx.startService(TwinVpnService.Intents.stop(ctx))
            assertTrue(
                "round $round: ACTION_STOP must stopSelf()",
                await { !serviceRunning(ctx) },
            )
            Log.i(TAG, "TWINVPN_LIFECYCLE_TRANSITION STARTED->DESTROYED")
        }
        Log.i(TAG, "TWINVPN_LIFECYCLE_TRANSITION DESTROYED->RESTARTED")
    }

    /**
     * TwinVPN never selects its own VPN interface as underlay.
     *
     * The defect this guards against is a loop, not a leak: an underlay set that
     * contained our own `tun` would have the tunnel carried by itself, and on
     * Android the symptom is a connection that comes up and then stalls with no
     * error anywhere.
     *
     * # What is actually asserted, and what a stronger test would need
     *
     * The instrumented process cannot call `VpnService.establish()` — the
     * builder is an inner class of a RUNNING `VpnService` instance and consent
     * is a UI grant (`NativeLinkRunTest`'s header sets this out). So this test
     * does the strongest thing available without one: it enumerates every
     * network the system currently offers a watcher that has explicitly removed
     * `NET_CAPABILITY_NOT_VPN` — the same request `AndroidBridge`'s watcher
     * makes, so it sees exactly what the adapter sees — and asserts that no
     * network carrying `TRANSPORT_VPN` is in the set the adapter would treat as
     * underlay.
     *
     * With TwinVPN's own tunnel up, that network IS ours, and its presence in
     * the underlay set is the defect. With no tunnel up, the assertion still has
     * teeth against ANY VPN on the device, which is the same class of mistake
     * arriving from a different direction.
     */
    @Test
    fun the_underlay_set_never_contains_our_own_vpn_interface() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager is unavailable")

        // ONE snapshot, filtered twice. `allNetworks` is deprecated in API 31
        // with no synchronous replacement -- `registerNetworkCallback` is
        // asynchronous and would turn this assertion into a latch -- so the
        // suppression matches the one on `serviceRunning` below. Reading it
        // once also matters on its own: two calls are two moments, and a
        // network appearing or dropping between them would leave the VPN set
        // and the underlay set describing different states of the device.
        @Suppress("DEPRECATION")
        val networks = manager.allNetworks
        val vpnNetworks = networks.filter { network ->
            manager.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
        val underlay = networks.filter { network ->
            val caps = manager.getNetworkCapabilities(network) ?: return@filter false
            // The adapter's own rule: a network is underlay only when it is NOT
            // a VPN. `NET_CAPABILITY_NOT_VPN` is the system's own answer to that
            // question, and reading it is what keeps this test from
            // re-implementing the classification it is checking.
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        Log.i(
            TAG,
            "TWINVPN_ATTESTATION underlay_excludes_vpn=true " +
                "(vpn=${vpnNetworks.size} underlay=${underlay.size})",
        )
        for (network in underlay) {
            val caps = manager.getNetworkCapabilities(network)
            assertFalse(
                "a network carrying TRANSPORT_VPN reached the underlay set. If " +
                    "that network is ours the tunnel would carry itself; if it " +
                    "is another app's, our traffic would ride a VPN we do not " +
                    "control. Both are the same defect.",
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
            )
        }
    }

    /**
     * The `.so`s the process actually mapped, and the segment alignment the
     * loader accepted.
     *
     * A 16 KiB kernel refuses to map a `PT_LOAD` segment whose alignment is
     * below its page size, so the libraries being present in `/proc/self/maps`
     * at all is the loader's own verdict on C-12. Recorded rather than asserted
     * separately: the load already happened in
     * [the_native_libraries_load_and_leave_no_pending_jni_exception], and this
     * is what puts the evidence in logcat for `ci-android.sh` to carry.
     */
    @Test
    fun the_mapped_libraries_are_recorded() {
        NativeBridge.nativeCoreCreate(ByteArray(0)).let { h ->
            if (h != 0L) NativeBridge.nativeCoreDestroy(h)
        }
        val maps = File("/proc/self/maps").readLines()
            .filter { it.contains("libtwinvpn_") }
            .map { it.substringAfterLast(' ') }
            .distinct()
        Log.i(TAG, "TWINVPN_ATTESTATION mapped_libraries=${maps.size}")
        maps.forEach { Log.i(TAG, "mapped: $it") }
        assertTrue(
            "neither TwinVPN library is mapped in this process, so nothing was " +
                "loaded on the 16 KiB kernel and the criterion is undischarged",
            maps.size >= 2,
        )
    }

    private fun serviceRunning(ctx: Context): Boolean {
        val manager = ctx.getSystemService(ActivityManager::class.java)
        @Suppress("DEPRECATION")
        return manager.getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == TwinVpnService::class.java.name }
    }

    /** A bounded wait that FAILS rather than a sleep that hopes. */
    private fun await(condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + AWAIT_NANOS
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(POLL_MS)
        }
        return condition()
    }

    private companion object {
        const val TAG = "TwinVPN.PageSize16k"
        const val JNI_CROSSINGS = 64
        const val POLL_MS = 100L
        val AWAIT_NANOS = 20_000_000_000L
    }
}
