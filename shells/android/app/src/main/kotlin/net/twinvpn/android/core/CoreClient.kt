package net.twinvpn.android.core

import android.util.Log
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The drain thread for the core's **one ordered event stream**, and the
 * submission side.
 *
 * Authority: ADR-0018 **F-5** (*"submit + one ordered event stream … all state
 * changes, including the completion of a submitted command, arrive as events on
 * **exactly one** totally ordered stream per instance"*), **F-6** (a `tw_core*`
 * is `Send` but not `Sync` for mutating calls — S-47), **F-4**, **F-10**;
 * ADR-0017 (one contract, two carriages).
 *
 * # A REPORTED GAP, not a design choice
 *
 * This class is a **stub**, and the reason is a contract gap this domain found
 * rather than a corner cut. `tw_core_submit` takes *"an encoded command from the
 * SAME command set the local management interface carries"* (F-8: encoded bytes
 * generated from ADR-0003's contract artifacts) — and **`contracts/` defines no
 * such command or event message.** OQ-2 deliberately excluded a `mgmt.proto` so
 * the management interface could not acquire an independent vocabulary, which is
 * recorded as **W-38**; the consequence for a Kotlin shell is that there is
 * nothing generated to encode a command *into*.
 *
 * `shells/linux` does not hit this because it links the Rust crates directly and
 * calls typed constructors. A Kotlin shell cannot: §10.4 keeps sockets and the
 * NAT ladder in Rust, but the command/event stream is `twinvpn.h`'s, and
 * `twinvpn.h` says the payload is a contract artifact that does not exist.
 *
 * **Reported to the integration lead as a cross-boundary request** rather than
 * worked around: the alternative — inventing an encoding here — would create the
 * second vocabulary OQ-2 exists to prevent, in the one shell least able to keep
 * it in step. Every method below therefore logs and returns, and the completion
 * report lists this as the single largest thing `shells/android` cannot do.
 *
 * # What the shape would be, once there is a message to carry
 *
 * One thread calls `tw_core_next_event` in a loop with a timeout, decodes the
 * `ErrorEnvelope`/event, and fans it out to [subscribe]rs. Submission is
 * non-blocking and happens on the caller's thread, serialized by F-6's rule that
 * exactly one thread may hold the instance for mutation. `tw_core_wake` cancels
 * an in-flight `next_event` at shutdown. Nothing in that shape is decided here —
 * F-5 fixes all of it.
 */
internal class CoreClient(private val handle: Long) {

    private companion object {
        const val TAG = "TwinVPN.Core"
    }

    private val running = AtomicBoolean(false)
    private val subscribers = CopyOnWriteArrayList<(Rendered) -> Unit>()
    private var drain: Thread? = null

    /**
     * Adds an event subscriber.
     *
     * The notification, the status screen and the quick-settings tile are all
     * subscribers. ADR-0019 §11.9(4)'s unconditional invalidation on
     * foreground/resume has its trigger here rather than in a poll — ADR-0022
     * X6 supplies the transitions as events for exactly that reason.
     */
    fun subscribe(onEvent: (Rendered) -> Unit) {
        subscribers += onEvent
    }

    /** Starts the drain thread. */
    fun start() {
        if (!running.compareAndSet(false, true)) return
        drain = thread(name = "twinvpn-core-events", isDaemon = false) {
            while (running.get()) {
                // tw_core_next_event(core, timeout_ms, &event, &err) — the ONLY
                // blocking call in the ABI. Blocked on W-38; see the class
                // documentation.
                Thread.sleep(250)
            }
        }
        Log.w(TAG, "core event stream not bound: no command/event contract exists (W-38)")
    }

    /** Stops the drain thread. Idempotent. */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        // tw_core_wake(core) — callable from any thread, and what cancels an
        // in-flight `next_event` rather than waiting out its timeout.
        drain?.join(1_000)
        drain = null
    }

    /**
     * Asks the core to connect.
     *
     * Not "connects": the shell has no opinion about whether a connection is
     * possible, which peers exist, or what to do if it fails. It submits an
     * intent and renders whatever comes back on the event stream.
     */
    fun requestConnect() {
        submit("session.connect")
    }

    /** Asks the core to disconnect. ADR-0022 LC-2 row 4 makes this durable. */
    fun requestDisconnect() {
        submit("session.disconnect")
    }

    /**
     * Submits one command.
     *
     * The parameter is the operation **name** rather than an encoded message,
     * which is the shape of the gap: F-8 requires encoded bytes from a contract
     * artifact, and there is none. Recorded so a reader does not mistake this
     * for the intended interface.
     */
    private fun submit(operation: String) {
        if (handle == 0L) return
        Log.w(TAG, "submit($operation) not carried: no command contract exists (W-38)")
    }

    /** Fans one resolved diagnostic out. Called by the drain thread. */
    private fun publish(rendered: Rendered) {
        for (subscriber in subscribers) subscriber(rendered)
    }
}
