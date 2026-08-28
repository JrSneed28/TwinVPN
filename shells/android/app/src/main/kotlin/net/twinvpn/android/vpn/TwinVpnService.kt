package net.twinvpn.android.vpn

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.RestrictionsManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import net.twinvpn.android.NativeBridge
import net.twinvpn.android.NativeHost
import net.twinvpn.android.core.CoreClient
import net.twinvpn.android.keystore.TwinKeystore

/**
 * The `VpnService`: the datapath, the foreground-service lifecycle, and
 * `onRevoke`.
 *
 * Authority: `docs/networking.md` §5.2's Android row, §5.4, §5.5;
 * ADR-0012 §11.6's Android row; ADR-0016 H2 (*"exactly one privileged process
 * per device, per Android user"*); ADR-0022 §11.3, §11.4, **LC-33**;
 * ADR-0018 §11.5 (*"Android `VpnService` — **loads the core**"*), PB-1.
 *
 * # This process is the authority; the Activity is not
 *
 * ADR-0018 §11.5's two Android rows are explicit: the `VpnService` loads the
 * core, and the UI activity does **not** — it reaches the core over ADR-0017.
 * So everything durable, every path decision and the whole datapath live here,
 * and the Activity can be killed at any moment without the tunnel noticing
 * (ADR-0022 §11.4's "the app is killed while the extension lives" row, which is
 * the same shape on Android).
 *
 * # `START_STICKY`, and the one case it does not cover
 *
 * ADR-0022 §11.4's Android low-memory row: *"Always-on VPN has the system
 * restart the service; otherwise `START_STICKY`."* Both are used. Neither covers
 * a **force-stop**, which disables manifest receivers until the next manual
 * launch — `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` (substituted; see
 * `twinvpn_platform_android::codes`), user-actionable, and stated in the UI
 * rather than hidden.
 *
 * # `onRevoke`
 *
 * ADR-0022 §11.4's `onRevoke` row is normative: *"Tear down our tunnel cleanly;
 * do **not** fight for the slot; report the competing app."* This class does the
 * first two. **Reporting is the core's** — it emits `NET.CONCURRENT_VPN`
 * (substituted onto `ROUTE.IFACE_CONFLICT`), and the competing app arrives as an
 * ordinary `TRANSPORT_VPN` network observation through [ConnectivityWatcher].
 * There is no `if (revoked) showMessage(...)` here, and there must not be.
 */
class TwinVpnService : VpnService() {

    private companion object {
        const val TAG = "TwinVPN.Service"

        /** Started by the user, or by the boot receiver. */
        const val ACTION_START = "net.twinvpn.android.START"

        /** Stopped by the user. A restart is not consent (ADR-0022 LC-2). */
        const val ACTION_STOP = "net.twinvpn.android.STOP"

        /** The managed-configuration key a DPC sets to report lockdown. */
        const val RESTRICTION_LOCKDOWN = "always_on_lockdown"
    }

    /** The PLATFORM ADAPTER's handle (`twinvpn-platform-android`). */
    @Volatile
    private var handle: Long = 0

    /**
     * The CORE's handle (`twinvpn.h`, through `twinvpn-android-jni`).
     *
     * A second handle, because they are two libraries: CD-I5 forbids
     * `twinvpn-platform-android` to name `twinvpn-core`, so the core's JNI
     * entries live in a separate `.so` and hand back a separate opaque value.
     * Conflating them would be the first step towards merging the crates.
     */
    @Volatile
    private var coreHandle: Long = 0

    private lateinit var notification: ServiceNotification
    private var connectivity: ConnectivityWatcher? = null
    private var power: PowerWatcher? = null
    private var core: CoreClient? = null

    override fun onCreate() {
        super.onCreate()
        notification = ServiceNotification(this)

        // CB-7 and CD-2: the vault directory is CREATED HERE, with its
        // attributes, and injected. The adapter never discovers it.
        //
        // ADR-0020 §11's Android row: the DEFAULT credential-encrypted context,
        // NOT `createDeviceProtectedStorageContext()`. Device-encrypted storage
        // is readable before first unlock and may hold only the non-secret
        // bootstrap record LC-15 permits — never the SEK or the identity.
        val vault = java.io.File(filesDir, "vault").apply { mkdirs() }

        val host = NativeHost(
            service = this,
            keystore = TwinKeystore(applicationContext),
            sessionLabel = getString(net.twinvpn.android.R.string.app_name),
        )
        handle = NativeBridge.nativeCreate(host, vault.absolutePath)
        if (handle == 0L) {
            // The adapter could not be built. Starting without it would mean
            // reporting a posture we cannot know, which ADR-0015 O-18 forbids
            // more strongly than it forbids being unavailable.
            Log.e(TAG, "the platform adapter could not be created")
            stopSelf()
            return
        }

        reportLockdownPosture()

        connectivity = ConnectivityWatcher(this) { handle }.also { it.start() }
        power = PowerWatcher(this) { handle }.also { it.start() }

        // **The core.** Until this call existed, `CoreClient` was a stub: this
        // service ran a platform adapter with nothing behind it, the
        // notification appeared, and no command reached anything.
        //
        // The config slice is empty: on Android the adapter is linked
        // in-process as a Rust crate, so the core reaches the platform directly
        // rather than back out through F-9 (`ownership.md` §10.4).
        coreHandle = NativeBridge.nativeCoreCreate(ByteArray(0))
        if (coreHandle == 0L) {
            // ADR-0015 O-18 again: a service that came up without a core would
            // render a posture it cannot know. Refusing to start is the weaker
            // failure and the correct one.
            Log.e(TAG, "the core could not be created")
            stopSelf()
            return
        }

        core = CoreClient(coreHandle).also { client ->
            // The ONE ordered event stream (ADR-0018 F-5). The notification is a
            // subscriber like any other; it renders what the core resolved.
            client.subscribe { rendered -> notification.render(rendered) }
            client.start()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSelf()
                return Service.START_NOT_STICKY
            }
            else -> Unit
        }

        // LC-33: a user-started `VpnService` runs as a foreground service with
        // an ongoing notification for as long as the tunnel is up. Posted before
        // anything else, because Android 12+ kills a service that has not gone
        // foreground within the window.
        //
        // "Where the tunnel is started by the SYSTEM as an always-on VPN, no
        // TwinVPN-owned foreground notification is required and one MUST NOT be
        // forced." `isAlwaysOnStart` is how the system tells us, and it is a
        // platform fact rather than a decision.
        val alwaysOn = intent == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
        if (!alwaysOn) {
            notification.startForeground(this)
        }

        // `net.up` rather than a per-peer connect: the service is starting the
        // TUNNEL, and which peers exist is the core's to know. A shell that
        // enumerated peers here would be holding a decision CB-2 removes from
        // it.
        core?.requestNetUp()
        // ADR-0022 §11.4: on a low-memory kill the system restarts us. A null
        // intent on the restart is what `START_STICKY` delivers, and it is
        // indistinguishable from an always-on start — which is why the branch
        // above turns on it rather than on anything TwinVPN-shaped.
        return Service.START_STICKY
    }

    /**
     * Another app has become the active VPN.
     *
     * Called by the system on a binder thread while our descriptor is already
     * closed. The core learns that the claim is gone and names the condition; we
     * do not name it, and we do not try to take the slot back.
     */
    override fun onRevoke() {
        Log.i(TAG, "onRevoke: another application holds the VPN slot")
        val held = handle
        if (held != 0L) NativeBridge.nativeOnRevoked(held)
        // §5.5 rule 4 and ADR-0022: do NOT fight for the slot. Stopping is the
        // whole response; the core reports and the UI renders what it reports.
        stopSelf()
    }

    override fun onDestroy() {
        connectivity?.stop()
        power?.stop()
        // The drain thread first — `stop()` wakes an in-flight `next_event`
        // rather than waiting out its timeout — and only then the instance it
        // is reading from. Destroying a core a thread is still blocked inside
        // is how a shutdown becomes a crash.
        core?.stop()
        core = null
        val heldCore = coreHandle
        coreHandle = 0
        if (heldCore != 0L) {
            // CB-6: this does NOT tear down enforcement.
            NativeBridge.nativeCoreDestroy(heldCore)
        }
        val held = handle
        handle = 0
        if (held != 0L) {
            // CB-6: destroying the adapter does NOT tear down enforcement. On
            // Android the claim dies with the process anyway, which is exactly
            // why `EnforcementView::custody` reports `survives_core_exit: false`
            // unless lockdown is CONFIRMED. Nothing here pretends otherwise.
            NativeBridge.nativeDestroy(held)
        }
        super.onDestroy()
    }

    /**
     * Reads the managed configuration and reports the **three-valued** posture.
     *
     * ADR-0022 **LC-40** and `docs/networking.md` §5.4: a non-DPC app on
     * Android 10+ cannot read whether it is the always-on VPN or whether
     * lockdown is on, and *"the obvious in-app probe is invalid by
     * construction — under lockdown our own sockets are the permitted ones, so a
     * successful reachability test proves nothing"*.
     *
     * So there is no probe here. A managed configuration that carries the key
     * gives `CONFIRMED` or `ABSENT`; **everything else is `UNVERIFIED`**, which
     * presents as unprotected. Note carefully that a missing key is `UNVERIFIED`
     * and not `ABSENT`: "nobody told us" and "we were told it is off" are
     * different facts, and collapsing them would let an unmanaged device present
     * as positively determined.
     */
    private fun reportLockdownPosture() {
        val held = handle
        if (held == 0L) return
        val restrictions = getSystemService(RestrictionsManager::class.java)
        val bundle = restrictions?.applicationRestrictions
        val reported = when {
            bundle == null || !bundle.containsKey(RESTRICTION_LOCKDOWN) ->
                NativeBridge.LOCKDOWN_UNVERIFIED
            bundle.getBoolean(RESTRICTION_LOCKDOWN) -> NativeBridge.LOCKDOWN_CONFIRMED
            else -> NativeBridge.LOCKDOWN_ABSENT
        }
        NativeBridge.nativeOnLockdownReport(held, reported)
    }

    /** Intents the UI and the boot receiver use to reach this service. */
    object Intents {
        /** Starts the tunnel. */
        fun start(context: Context): Intent =
            Intent(context, TwinVpnService::class.java).setAction(ACTION_START)

        /** Stops it. ADR-0022 LC-2 row 4: a restart will not undo this. */
        fun stop(context: Context): Intent =
            Intent(context, TwinVpnService::class.java).setAction(ACTION_STOP)
    }
}
