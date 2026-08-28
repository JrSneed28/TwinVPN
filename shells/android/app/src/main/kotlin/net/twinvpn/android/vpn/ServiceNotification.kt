package net.twinvpn.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import net.twinvpn.android.R
import net.twinvpn.android.core.Rendered
import net.twinvpn.android.ui.MainActivity

/**
 * The ongoing notification — **the anti-silence surface**, not chrome.
 *
 * Authority: ADR-0022 **LC-33**; ADR-0019 §11's Android row (*"the FGS
 * notification is where a backgrounded user learns protection stopped"*),
 * §11.9, PC-7; ADR-0015 §11.6's presentation obligation and **O-18**;
 * ADR-0018 **CB-4**.
 *
 * # LC-33, clause by clause
 *
 * > A user-started `VpnService` runs as a foreground service with an ongoing
 * > notification for as long as the tunnel is up. The notification MUST render
 * > the derived `ConnectionState` per ADR-0019's presentation contract, MUST be
 * > visually distinct for `DEGRADED` and `BLOCKED`, and **MUST NOT be a static
 * > "VPN active"**. The system's own VPN key indicator is in addition to, not
 * > instead of, this.
 *
 * - *renders the derived state* — [render] shows [Rendered.summary], which the
 *   core resolved from the registry in the caller's locale (CB-4, F-10).
 * - *visually distinct* — see below.
 * - *not static* — there is no literal status string in this file. The only
 *   strings it can display are the ones the core sent.
 * - *in addition to the key indicator* — nothing here suppresses it, and nothing
 *   could.
 *
 * # How "visually distinct" is achieved without a CB-2 violation
 *
 * The obvious implementation is `when (state) { BLOCKED -> red; … }`, and it is
 * forbidden: CB-2 bans a shell branch whose condition is a `ConnectionState`.
 * The permitted one branches on [Rendered.Severity] — a **registry attribute the
 * core resolved**, carried in F-4's `resolved` block — so the mapping from
 * condition to severity is made once, in the core, from
 * `contracts/registry/reason_codes.json`, and six shells cannot diverge on it
 * (R-31). What stays here is colour and icon, which CB-4 lists as presentation.
 *
 * # Android 13+ with the notification permission refused
 *
 * ADR-0019 §11's row is explicit: *"the foreground-service notification cannot
 * be posted, so the **anti-silence surface is gone**. The UI states plainly that
 * TwinVPN will not be able to tell you when protection stops."* [canPost]
 * reports it; the status screen says it. The service still runs — refusing to
 * protect because we cannot narrate would be the wrong trade — but the loss is
 * **declared**, never absorbed.
 */
internal class ServiceNotification(context: Context) {

    private companion object {
        const val CHANNEL_ID = "twinvpn.status"
        const val NOTIFICATION_ID = 1
    }

    private val manager = NotificationManagerCompat.from(context)
    private val appContext = context.applicationContext

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                appContext.getString(R.string.channel_status),
                // LOW, not MIN: MIN hides the notification from the shade on
                // several OEM builds, and a surface the user cannot find is not
                // an anti-silence surface. Not DEFAULT either — it must not make
                // a sound every time a path migrates.
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = appContext.getString(R.string.channel_status_description)
                setShowBadge(false)
            }
            appContext.getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }
    }

    /**
     * Whether the ongoing notification can be posted at all.
     *
     * `false` on Android 13+ with `POST_NOTIFICATIONS` refused, and on any
     * release where the user has disabled the channel. Reported to the UI.
     */
    fun canPost(): Boolean = manager.areNotificationsEnabled()

    /** Enters the foreground with a placeholder the first event replaces. */
    fun startForeground(service: TwinVpnService) {
        val notification = build(rendered = null)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            service.startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            service.startForeground(NOTIFICATION_ID, notification)
        }
    }

    /**
     * Replaces the notification with what the core most recently resolved.
     *
     * Called from the event stream, so the surface changes when the tunnel does
     * — ADR-0019 §11.9(4)'s trigger, delivered as an event (ADR-0022 X6) rather
     * than discovered by a poll.
     */
    fun render(rendered: Rendered) {
        if (!canPost()) return
        manager.notify(NOTIFICATION_ID, build(rendered))
    }

    private fun build(rendered: Rendered?): Notification {
        val open = PendingIntent.getActivity(
            appContext,
            0,
            Intent(appContext, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val builder = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(iconFor(rendered))
            .setColor(accentFor(rendered))
            .setColorized(rendered?.severity == Rendered.Severity.CRITICAL)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            // The tunnel's state is not a lock-screen secret, but the peer
            // labels the summary may name are `SENSITIVE` under ADR-0015 §11.4.
            // PRIVATE hides the text on a locked screen and keeps the title,
            // which is exactly the split that surface needs.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(open)
            .setContentTitle(appContext.getString(R.string.app_name))

        if (rendered == null) {
            // The only string this class supplies on its own, and it says
            // "starting" rather than "protected" — O-18's direction: never green
            // before an assertion exists.
            builder.setContentText(appContext.getString(R.string.status_starting))
        } else {
            builder.setContentText(rendered.summary)
            rendered.nextAction?.let {
                builder.setStyle(NotificationCompat.BigTextStyle().bigText("${rendered.summary}\n$it"))
            }
        }

        builder.addAction(
            R.drawable.ic_stop,
            appContext.getString(R.string.action_disconnect),
            PendingIntent.getService(
                appContext,
                1,
                TwinVpnService.Intents.stop(appContext),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
        return builder.build()
    }

    /**
     * Iconography, branched on the **resolved severity** and never on a state
     * this shell classified. See the class documentation.
     */
    private fun iconFor(rendered: Rendered?): Int = when {
        rendered == null -> R.drawable.ic_status_unknown
        rendered.protection == Rendered.ProtectionIndicator.PROTECTED -> R.drawable.ic_status_ok
        rendered.severity == Rendered.Severity.CRITICAL -> R.drawable.ic_status_blocked
        rendered.severity == Rendered.Severity.ERROR -> R.drawable.ic_status_blocked
        rendered.severity == Rendered.Severity.WARN -> R.drawable.ic_status_degraded
        // O-18: UNKNOWN is never green.
        else -> R.drawable.ic_status_unknown
    }

    private fun accentFor(rendered: Rendered?): Int = when {
        rendered == null -> androidx.core.content.ContextCompat.getColor(appContext, R.color.status_unknown)
        rendered.protection == Rendered.ProtectionIndicator.PROTECTED ->
            androidx.core.content.ContextCompat.getColor(appContext, R.color.status_ok)
        rendered.severity >= Rendered.Severity.ERROR ->
            androidx.core.content.ContextCompat.getColor(appContext, R.color.status_blocked)
        rendered.severity == Rendered.Severity.WARN ->
            androidx.core.content.ContextCompat.getColor(appContext, R.color.status_degraded)
        else -> androidx.core.content.ContextCompat.getColor(appContext, R.color.status_unknown)
    }
}
