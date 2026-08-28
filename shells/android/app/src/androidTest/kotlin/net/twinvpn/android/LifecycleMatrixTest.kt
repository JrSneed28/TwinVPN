package net.twinvpn.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The **device-bound** half of the wave-3 matrix.
 *
 * `docs/implementation/ownership.md` §10.5 rule 2:
 *
 * > The genuinely device-bound rows are written as real-device lifecycle tests
 * > and reported as unrun. Process termination by the OS, Doze, extension
 * > memory-limit kill … are in this set.
 *
 * ============================================================================
 * NONE OF THESE TESTS HAS BEEN RUN. NONE OF THEM HAS BEEN COMPILED.
 * ============================================================================
 *
 * There is no JDK, no Gradle, no Android SDK and no NDK on the host wave 3 runs
 * on. Every test in this directory is **written, not compiled** in §9.2's sense,
 * and the completion report says so. They are what discharges the device-farm
 * debt when a farm exists; they discharge nothing now.
 *
 * # What is deliberately NOT here
 *
 * Every row §10.5 rule 1 says *must* be a host-runnable test over the mock
 * adapter — roaming producing `MIGRATING`, a revoked peer, a restored
 * connection, the kill-switch posture, and both leak families — is in
 * `core/crates/twinvpn-platform-android/tests/matrix.rs`, where it **runs**.
 * Duplicating them here would move proven behaviour into the unrun column, which
 * is the exact mistake rule 1 exists to prevent.
 *
 * What remains is what genuinely needs a device: an OS that kills processes, a
 * Doze controller, a second VPN app, and a packet capture.
 */
@RunWith(AndroidJUnit4::class)
class LifecycleMatrixTest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    /**
     * **Matrix row: process termination.**
     *
     * ADR-0022 §11.4's Android low-memory row: no notice, and a foreground
     * service is late in the LMK order but **not exempt**. LC-7 makes the next
     * start a resume, because the journal is written *ahead* rather than at
     * exit.
     *
     * The assertion that matters is not that we survive — we do not — but that
     * the restart reads `absence_cause = CRASH` (or `UNKNOWN`, which LC-7 treats
     * as `CRASH`) and resumes into `RECONNECTING` **carrying a code**. The
     * consequence half runs on the host
     * (`matrix.rs::row_6_a_terminated_process_resumes_into_reconnecting_with_a_code`);
     * what needs a device is that the kill happens with no exit handler and the
     * journal is still readable afterwards.
     */
    @Test
    fun the_service_resumes_after_an_os_kill_with_no_exit_handler() {
        startTunnelAndWaitForProtection()

        // `am kill` is the closest reproduction of an LMK kill available to a
        // test: SIGKILL, no exit handler, no notice. `force-stop` would be a
        // DIFFERENT test — it also disables manifest receivers, which is
        // ADR-0022 §11.3's force-stop row and is asserted separately below.
        device.executeShellCommand("am kill net.twinvpn.android")
        device.waitForIdle()

        // START_STICKY, or the system's always-on restart.
        val resumed = waitForServiceRunning(timeoutMillis = 30_000)
        assertTrue("the service must be restarted after an OS kill", resumed)

        // The journal was written ahead, so the restart knows it crashed.
        assertNotEquals(
            "a resumed instance must not report a clean shutdown",
            "CLEAN_STOP",
            readAbsenceCause(),
        )
    }

    /**
     * **Matrix row: process termination — the force-stop variant.**
     *
     * ADR-0022 §11.3's Android row: a force-stop puts the app in the stopped
     * state and **disables manifest receivers until the next manual launch**, so
     * `BOOT_COMPLETED` will not fire. *"There is no protection at all and the app
     * cannot fix it."*
     *
     * This test asserts the honest outcome — that we do **not** come back — and
     * that the next manual launch surfaces the condition. A test that asserted
     * recovery would be asserting a workaround that must not exist.
     */
    @Test
    fun a_force_stop_is_not_recovered_from_and_is_surfaced_on_next_launch() {
        startTunnelAndWaitForProtection()

        device.executeShellCommand("am force-stop net.twinvpn.android")
        device.waitForIdle()

        assertTrue(
            "a force-stopped app must not restart itself",
            !waitForServiceRunning(timeoutMillis = 15_000),
        )

        launchApp()
        // `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` is unregistered and is
        // substituted onto `PLATFORM.ADAPTER_UNAVAILABLE`
        // (`twinvpn_platform_android::codes`). The test asserts the SUBSTITUTED
        // spelling, because that is what the build emits — asserting the ADR's
        // spelling would fail for the right reason at the wrong layer.
        assertTrue(
            "the user must be told autostart is blocked",
            statusMentions("PLATFORM.ADAPTER_UNAVAILABLE"),
        )
    }

    /**
     * **Matrix row: foreground / background, and lock / unlock.**
     *
     * The tunnel must survive both, and the ongoing notification must remain
     * posted — LC-33 makes it the surface on which a backgrounded user learns
     * protection stopped, so a notification that vanishes on background is the
     * failure this test exists to catch.
     */
    @Test
    fun the_tunnel_survives_background_and_screen_lock() {
        startTunnelAndWaitForProtection()

        device.pressHome()
        device.waitForIdle()
        assertTrue("backgrounding must not stop the tunnel", isProtected())
        assertTrue("the anti-silence surface must remain", notificationPosted())

        device.sleep()
        device.waitForIdle()
        assertTrue("a screen lock must not stop the tunnel", isProtected())

        device.wakeUp()
        launchApp()
        assertTrue("unlocking must not stop the tunnel", isProtected())
    }

    /**
     * **Matrix row: process termination — the pre-first-unlock case.**
     *
     * ADR-0022 **LC-15** and ADR-0020's Android row: the identity key and the
     * SEK live in credential-encrypted storage, which is unreadable before the
     * first unlock after a reboot. An always-on start at boot must come up
     * **fail-closed and named** — `STORE.KEYSTORE_LOCKED` (substituted onto
     * `AUTH.KEY_STORE_UNAVAILABLE`) — and must complete rehydration on the first
     * unlock.
     *
     * Needs a reboot, so it needs a farm. The half that does not — that a locked
     * element produces the substituted code with the right class — runs on the
     * host in `matrix.rs::row_2_…`.
     */
    @Test
    fun a_boot_before_first_unlock_comes_up_fail_closed_and_named() {
        device.executeShellCommand("reboot")
        device.waitForIdle()
        // Deliberately NOT unlocked here.
        assertTrue(
            "the pre-unlock posture must be named, not silent",
            statusMentions("AUTH.KEY_STORE_UNAVAILABLE"),
        )
        assertTrue(
            "and it must not present as protected",
            !isProtected(),
        )
    }

    // -----------------------------------------------------------------------
    // Helpers. Each is device-bound, which is why this whole file is.
    // -----------------------------------------------------------------------

    private fun startTunnelAndWaitForProtection() = TODO("device farm")

    private fun launchApp() = TODO("device farm")

    private fun waitForServiceRunning(timeoutMillis: Long): Boolean = TODO("device farm")

    private fun isProtected(): Boolean = TODO("device farm")

    private fun notificationPosted(): Boolean = TODO("device farm")

    private fun statusMentions(reasonCode: String): Boolean = TODO("device farm")

    private fun readAbsenceCause(): String = TODO("device farm")
}
