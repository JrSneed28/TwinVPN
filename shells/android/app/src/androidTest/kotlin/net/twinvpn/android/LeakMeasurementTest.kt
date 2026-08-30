package net.twinvpn.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * **Real leak measurement** — IPv4, IPv6 and DNS, on a device, with a capture.
 *
 * ============================================================================
 * NONE OF THESE TESTS HAS BEEN RUN. NONE OF THEM HAS BEEN COMPILED.
 * ============================================================================
 *
 * Authority: ADR-0012 §11.6's Android rows and its **honest platform-limitation
 * table**; ADR-0010 **R1** and **R6**; `docs/networking.md` §9.1's four leak
 * channels; `docs/implementation/ownership.md` §10.5 (*"Leak coverage is **both
 * families and DNS** on every platform"*).
 *
 * # What runs on the host, and what only a device can answer
 *
 * The host suite proves the **claim** is correct: a full tunnel claims
 * `0.0.0.0/0` **and** `::/0`, a single-family default is widened rather than
 * left unclaimed, both resolver families reach the builder, a one-family claim
 * is never reported as protection, and the `BLOCKED`↔`PROTECTED` swap never
 * leaves the claim absent
 * (`core/crates/twinvpn-platform-android/tests/matrix.rs`, rows 9–12).
 *
 * What that cannot answer is whether the **platform honours** the claim. ADR-0012
 * §11.6's Android limitation row is explicit that *"some connectivity-check and
 * system traffic is exempt in lockdown"*, and a claim honoured for our own
 * traffic and not for another app's is a leak no amount of rendering proves
 * absent. These tests are the measurement, and they need a capture on the
 * device's real interfaces.
 *
 * # Both families, or the whole exercise is void
 *
 * `ownership.md` §4.2 refuses `TVPN-IPV4-*`/`TVPN-IPV6-*` as reason-code domains
 * for exactly this reason: *"a per-family namespace makes 'we have a v4 story
 * and a v6 story' sayable — the exact asymmetry ADR-0010 R1 exists to forbid"*.
 * Every test below runs against **both** families, and the DNS test asserts on
 * both resolver families rather than on "DNS".
 */
@RunWith(AndroidJUnit4::class)
class LeakMeasurementTest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    /**
     * **Matrix rows: IPv4 leaks and IPv6 leaks — the `BLOCKED` posture.**
     *
     * ADR-0012's `BLOCKED` is not "no rules": it is the same route claim over
     * everything with nothing forwarded. Nothing but the class-7 bootstrap
     * exemption may leave the device in either family.
     *
     * The counters are read **per family** and asserted **separately**, so a v6
     * leak cannot be absorbed into a v4 total.
     */
    @Test
    fun nothing_egresses_off_tunnel_in_either_family_while_blocked() {
        startTunnelAndWaitForProtection()
        forceBlockedPosture()

        val capture = captureOnPhysicalInterfaces(durationMillis = 30_000) {
            generateTraffic(family = 4)
            generateTraffic(family = 6)
        }

        assertEquals(
            "IPv4 protected traffic must not egress off-tunnel while BLOCKED",
            0,
            capture.offTunnelPacketsV4,
        )
        assertEquals(
            "IPv6 protected traffic must not egress off-tunnel while BLOCKED",
            0,
            capture.offTunnelPacketsV6,
        )
        // Class 7 (KS-9): TwinVPN's own control, rendezvous and relay traffic is
        // permitted, and its ABSENCE would be the different bug of a device that
        // can never recover from BLOCKED.
        assertTrue(
            "the bootstrap exemption must remain usable",
            capture.bootstrapPackets > 0,
        )
    }

    /**
     * **Matrix row: IPv6 leaks — R6's case.**
     *
     * ADR-0010 R6: IPv6 must not bypass tunnel policy *"including when IPv6
     * appears **after** the tunnel is up"*. On Android there is no firewall
     * behind the claim, so an unclaimed family does not fall through to a
     * blocking rule — it egresses.
     *
     * This is the single most valuable device test in the suite, because it is
     * the case a v4-first implementation passes every host test and still fails.
     */
    @Test
    fun ipv6_arriving_after_the_tunnel_is_up_does_not_bypass_it() {
        startTunnelAndWaitForProtection()
        assertTrue("start on a v4-only underlay", currentUnderlayFamilies() == setOf(4))

        enableIpv6OnTheUnderlay()
        device.waitForIdle()

        val capture = captureOnPhysicalInterfaces(durationMillis = 30_000) {
            generateTraffic(family = 6)
        }
        assertEquals(
            "IPv6 must be claimed even though it appeared after establish()",
            0,
            capture.offTunnelPacketsV6,
        )
    }

    /**
     * **Matrix row: DNS leaks.**
     *
     * `docs/networking.md` §9.1's DNS channel, both resolver families. Android
     * has no per-suffix scoping for a `VpnService` at any supported API level —
     * the adapter reports `DNS.PLATFORM.SCOPED_API_UNAVAILABLE` for exactly that
     * — so every query the tunnel carries goes to the resolvers we claimed, and
     * this test is what proves none goes anywhere else.
     */
    @Test
    fun no_dns_query_reaches_a_resolver_we_did_not_claim() {
        startTunnelAndWaitForProtection()

        val capture = captureOnPhysicalInterfaces(durationMillis = 30_000) {
            resolve("example.invalid")
            resolve("example.test")
        }

        assertEquals(
            "no IPv4 DNS query may reach an unclaimed resolver",
            0,
            capture.offTunnelDnsV4,
        )
        assertEquals(
            "no IPv6 DNS query may reach an unclaimed resolver",
            0,
            capture.offTunnelDnsV6,
        )
    }

    /**
     * **Matrix row: DNS leaks — Android Private DNS.**
     *
     * Private DNS (DoT) takes precedence over a VPN's own resolvers. ADR-0019's
     * catalogue names it as a user-actionable condition
     * (`DNS.PLATFORM.PRIVATE_DNS_ACTIVE`, unregistered and substituted onto
     * `DNS.PLATFORM.SCOPED_API_UNAVAILABLE`).
     *
     * `docs/networking.md` §5.5 rule 2 forbids disabling a host resolver
     * service, so the product **reports** this and does not work around it. The
     * assertion is therefore that the condition is surfaced — not that queries
     * stop going to the private resolver, which they will and which we may not
     * prevent.
     */
    @Test
    fun private_dns_is_reported_rather_than_worked_around() {
        enablePrivateDns("dns.example")
        startTunnelAndWaitForProtection()

        assertTrue(
            "Private DNS taking precedence must be surfaced to the user",
            statusMentions("DNS.PLATFORM.SCOPED_API_UNAVAILABLE"),
        )
    }

    /**
     * **Matrix row: kill-switch behaviour — the window ADR-0012 §11.6 measures
     * rather than assumes.**
     *
     * The Android limitation row's residual is *"everything, until the user
     * enables lockdown"*. This test measures the interval between the device
     * having a network and our claim being in force, on a device where lockdown
     * is **not** enabled — the same measurement P09 makes for iOS's
     * attach-to-arm window.
     *
     * It has no pass threshold, deliberately. The number is the deliverable:
     * ADR-0012 requires the window to be *measured* rather than assumed to be
     * zero, and inventing a bound here would be assuming it.
     */
    @Test
    fun the_boot_to_claim_window_is_measured_and_recorded() {
        device.executeShellCommand("reboot")
        unlockDevice()
        val windowMillis = measureNetworkUpToClaimInForce()
        recordMeasurement("android.boot_to_claim_ms", windowMillis)
        assertTrue("the window must be finite", windowMillis >= 0)
    }

    // -----------------------------------------------------------------------

    private data class Capture(
        val offTunnelPacketsV4: Int,
        val offTunnelPacketsV6: Int,
        val offTunnelDnsV4: Int,
        val offTunnelDnsV6: Int,
        val bootstrapPackets: Int,
    )

    private fun captureOnPhysicalInterfaces(durationMillis: Long, body: () -> Unit): Capture =
        TODO("device farm: a rooted capture, or an upstream tap")

    private fun startTunnelAndWaitForProtection(): Unit = TODO("device farm")

    private fun forceBlockedPosture(): Unit = TODO("device farm")

    private fun generateTraffic(family: Int): Unit = TODO("device farm")

    private fun resolve(name: String): Unit = TODO("device farm")

    private fun currentUnderlayFamilies(): Set<Int> = TODO("device farm")

    private fun enableIpv6OnTheUnderlay(): Unit = TODO("device farm: a dual-stack AP fixture")

    private fun enablePrivateDns(hostname: String): Unit = TODO("device farm")

    private fun unlockDevice(): Unit = TODO("device farm")

    private fun measureNetworkUpToClaimInForce(): Long = TODO("device farm")

    private fun recordMeasurement(name: String, value: Long): Unit = TODO("device farm")

    private fun statusMentions(text: String): Boolean = TODO("device farm")
}
