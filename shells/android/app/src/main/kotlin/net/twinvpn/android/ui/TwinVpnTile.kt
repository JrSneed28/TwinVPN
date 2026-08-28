package net.twinvpn.android.ui

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import net.twinvpn.android.vpn.TwinVpnService

/**
 * The quick-settings tile.
 *
 * Authority: ADR-0019 §11's Android row, which lists the tile beside the
 * foreground-service notification as a first-class surface; ADR-0018 CB-2, CB-4;
 * ADR-0015 **O-18**.
 *
 * # A tile is a button and an indicator, and nothing more
 *
 * `Tile.STATE_ACTIVE` / `STATE_INACTIVE` is the platform's own two-valued
 * affordance. It is **not** a `ConnectionState`, and this class must not try to
 * make it one: a tunnel that is `MIGRATING` or `DEGRADED` is neither "on" nor
 * "off", and collapsing twelve states into two here would be a classification
 * the shell performed.
 *
 * So the tile follows the `ProtectionAssertion`, which is the one genuinely
 * binary fact in the model (ADR-0015 §11.6 rule 1: *"a pure function of the most
 * recent assertion, never of the agent's belief"*), and the subtitle carries the
 * core's own sentence. Where no assertion exists the tile is
 * `STATE_UNAVAILABLE` — O-18's *never green*, in the platform's vocabulary.
 */
class TwinVpnTile : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        // No assertion is available to this process yet: the tile lives in the
        // UI process, which does not load the core (ADR-0018 §11.5), and reaches
        // it over ADR-0017 — the binding W-38 blocks. `STATE_UNAVAILABLE` is the
        // honest value until then, and it is also the fail-safe one.
        qsTile?.apply {
            state = Tile.STATE_UNAVAILABLE
            updateTile()
        }
    }

    override fun onClick() {
        super.onClick()
        // Starting is a user intent, which a shell may carry. Whether a
        // connection results is the core's.
        startService(TwinVpnService.Intents.start(this))
    }
}
