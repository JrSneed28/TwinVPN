package net.twinvpn.android

import android.app.Application

/**
 * The application object.
 *
 * Authority: ADR-0018 §11.5's two Android rows; ADR-0016 H2; ADR-0022 LC-14.
 *
 * # Deliberately almost empty
 *
 * ADR-0018 §11.5 is explicit that on Android the **`VpnService` loads the core**
 * and the **UI activity does not** — it reaches the core over ADR-0017. So this
 * class must not load the native library, must not create an adapter, and must
 * not hold any runtime authority: doing any of that here would put a second core
 * instance in the process that the Activity shares, and S-47 permits exactly one
 * mutating handle.
 *
 * The `Application` object is created in **both** the UI process and the service
 * process (they are one process here, but that is a packaging choice that could
 * change), so anything expensive placed here is paid for twice and anything
 * stateful placed here is ambiguous about which side owns it.
 *
 * # LC-14, and why it needs no code on Android today
 *
 * > **Rule LC-14 — background is an app-level fact, not a scene-level one.**
 * > `EV_BACKGROUND` MUST be derived from *all* surfaces being background, and
 * > MUST NOT be emitted while any scene, window, or external-display surface is
 * > foreground.
 *
 * Android's single-`Activity` model makes "all surfaces" trivially one surface,
 * so the aggregation is empty. It is named here rather than omitted because the
 * rule is about the *derivation*, and a future multi-window or Android-on-desktop
 * surface would make it load-bearing — at which point the aggregation belongs
 * here, not in the service, and still produces **one** event for the core.
 */
class TwinVpnApplication : Application()
