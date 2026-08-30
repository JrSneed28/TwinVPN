package net.twinvpn.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Doze, App Standby, and `onRevoke()`.
 *
 * ============================================================================
 * NONE OF THESE TESTS HAS BEEN RUN. NONE OF THEM HAS BEEN COMPILED.
 * ============================================================================
 * See [LifecycleMatrixTest]'s header. `docs/implementation/ownership.md` §10.5
 * rule 2 and §10.3's **written, not compiled** / **written, not executed** rows.
 *
 * # Why these four need a device and the rest do not
 *
 * Doze is a state only `dumpsys deviceidle` can force. `onRevoke()` requires a
 * *second* VPN app to take the platform's single slot. Neither can be faked
 * without faking the thing under test.
 */
@RunWith(AndroidJUnit4::class)
class DozeAndRevocationTest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    /**
     * **Matrix row: Doze.**
     *
     * ADR-0022 §11.4's Doze row: *"no notice; timers are deferred, the process
     * is not killed"*, and the response is to park per `docs/reliability.md`
     * §11.2 and **detect the gap on wake from the suspend-inclusive clock, never
     * from a timer that did not run.**
     *
     * That last clause is the assertion. `CLOCK_BOOTTIME` advances through Doze
     * and `CLOCK_MONOTONIC` does not, which is ADR-0022 LC-8's whole point — and
     * getting the two the wrong way round is the failure LC-8 calls *invisible
     * on Linux CI*. The host suite asserts both clocks are readable and monotone
     * (`clock::tests`), but only a dozing device proves they **diverge**.
     */
    @Test
    fun the_suspend_inclusive_clock_advances_through_doze_and_the_monotonic_one_does_not() {
        startTunnelAndWaitForProtection()
        val before = readClocks()

        device.executeShellCommand("dumpsys battery unplug")
        device.executeShellCommand("dumpsys deviceidle force-idle")
        Thread.sleep(120_000)

        device.executeShellCommand("dumpsys deviceidle unforce")
        device.executeShellCommand("dumpsys battery reset")
        val after = readClocks()

        val elapsedGap = after.elapsedMicros - before.elapsedMicros
        val monotonicGap = after.monotonicMicros - before.monotonicMicros
        assertTrue(
            "CLOCK_BOOTTIME must include the Doze window",
            elapsedGap >= 110_000_000,
        )
        assertTrue(
            "the suspend gap must be visible as a DIFFERENCE between the clocks",
            elapsedGap > monotonicGap,
        )
    }

    /**
     * **Matrix row: Doze — the keepalive prohibition.**
     *
     * `ownership.md` §10.2(2) and `docs/networking.md` §5.4: keepalives ride the
     * tunnel socket's own kernel-side timer, **never an app-side alarm cadence
     * chosen to defeat Doze**, and §10.2(1) forbids a wake lock outright.
     *
     * The structural half is already proven and does not need a device: the
     * `KeepalivePlan` type has two variants and neither is an alarm
     * (`power::tests::no_keepalive_plan_can_express_an_app_side_alarm`), and no
     * `AlarmManager` or `WakeLock` appears anywhere in this module. What a device
     * adds is the behavioural check that nothing wakes us on a cadence.
     */
    @Test
    fun nothing_wakes_the_app_on_a_cadence_during_doze() {
        startTunnelAndWaitForProtection()
        device.executeShellCommand("dumpsys batterystats --reset")
        device.executeShellCommand("dumpsys deviceidle force-idle")
        Thread.sleep(300_000)

        val wakeups = readWakeupCount()
        device.executeShellCommand("dumpsys deviceidle unforce")

        // Zero, not "few". An app-side cadence is what this asserts the absence
        // of, and one wakeup is a cadence.
        assertTrue("no app-scheduled wakeups during Doze, observed $wakeups", wakeups == 0)

        val wakeLocks = readWakeLockCount()
        assertTrue("§10.2(1) forbids a wake lock; observed $wakeLocks", wakeLocks == 0)
    }

    /**
     * **Matrix row: revoked — `onRevoke()` from another VPN app.**
     *
     * ADR-0022 §11.4's `onRevoke` row: *"Tear down our tunnel cleanly; do **not**
     * fight for the slot; report the competing app."* `NET.CONCURRENT_VPN`
     * (substituted onto `ROUTE.IFACE_CONFLICT`).
     *
     * The "do not fight" half is the interesting assertion, and it is negative:
     * after another app takes the slot we must **stay** stopped. An
     * implementation that re-established would produce a slot war that neither
     * app wins and that the user cannot exit.
     */
    @Test
    fun another_vpn_taking_the_slot_is_reported_and_never_contested() {
        startTunnelAndWaitForProtection()

        // Requires a second, cooperating VPN app on the device. That is a farm
        // fixture, not something this test can install.
        startCompetingVpn()
        device.waitForIdle()

        assertTrue("our tunnel must be torn down", !isProtected())
        assertTrue(
            "the competing app must be reported",
            statusMentions("ROUTE.IFACE_CONFLICT"),
        )

        Thread.sleep(30_000)
        assertTrue(
            "we must not fight for the slot",
            !isProtected(),
        )
    }

    /**
     * **Matrix row: `onRevoke()` from Settings.**
     *
     * The user revoking the VPN grant in Settings closes our descriptor. The
     * read-back must then say **no ruleset installed** rather than reporting the
     * posture we last intended — which is `installed_ruleset`'s honest answer and
     * is asserted on the host over a `socketpair`
     * (`matrix.rs::row_8_on_revoke_drops_the_claim_and_the_read_back_tells_the_truth`).
     * What a device adds is that Settings actually produces that callback.
     */
    @Test
    fun revoking_the_grant_in_settings_drops_the_claim_and_says_so() {
        startTunnelAndWaitForProtection()
        revokeVpnGrantInSettings()
        device.waitForIdle()

        assertTrue("protection must not be claimed after revocation", !isProtected())
        assertTrue(
            "and the indicator must be UNKNOWN or UNPROTECTED, never green",
            !statusMentions("Protected"),
        )
    }

    // -----------------------------------------------------------------------

    private data class Clocks(val monotonicMicros: Long, val elapsedMicros: Long)

    private fun readClocks(): Clocks = TODO("device farm")

    private fun readWakeupCount(): Int = TODO("device farm")

    private fun readWakeLockCount(): Int = TODO("device farm")

    private fun startTunnelAndWaitForProtection(): Unit = TODO("device farm")

    private fun startCompetingVpn(): Unit = TODO("device farm: a second VPN app fixture")

    private fun revokeVpnGrantInSettings(): Unit = TODO("device farm")

    private fun isProtected(): Boolean = TODO("device farm")

    private fun statusMentions(text: String): Boolean = TODO("device farm")
}
