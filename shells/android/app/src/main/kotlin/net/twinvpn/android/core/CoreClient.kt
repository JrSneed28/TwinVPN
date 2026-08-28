package net.twinvpn.android.core

import android.util.Log
import net.twinvpn.android.NativeBridge
import net.twinvpn.contracts.v1.ErrorEnvelope
import net.twinvpn.contracts.v1.ErrorSeverity
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The drain thread for the core's **one ordered event stream**, and the
 * submission side.
 *
 * Authority: ADR-0018 **F-4**, **F-5** (*"submit + one ordered event stream …
 * all state changes, including the completion of a submitted command, arrive as
 * events on **exactly one** totally ordered stream per instance"*), **F-6** (a
 * `tw_core*` is `Send` but not `Sync` for mutating calls — S-47), **F-8**,
 * **F-10**; ADR-0017 §11.3, MI-19, MI-20; `ownership.md` §8 item 10.
 *
 * # W-38 was the blocker, and it is stale
 *
 * This class used to be a **stub**. `start()` slept in a loop, `requestConnect()`
 * logged and returned, and `TwinVpnService.onStartCommand` called it — so the
 * Android app ran a platform adapter with no core behind it. The recorded reason
 * was W-38: *"`contracts/` defines no command or event message"*, OQ-2 having
 * deliberately excluded a `mgmt.proto` so the management interface could not
 * acquire an independent vocabulary.
 *
 * That reasoning was right when it was written and is no longer true of the
 * code. Both directions now speak the **management-interface frame** every
 * other carriage speaks — a 4-byte big-endian length prefix and UTF-8 JSON —
 * and neither needed a new contract message, which was OQ-2's whole objection:
 *
 * * **out**: `tw_core_submit` accepts a frame whose body is a `request`,
 *   carrying the operation name and its encoded parameters;
 * * **in**: `tw_core_next_event` returns a frame whose body is an `event` or a
 *   `compacted` marker.
 *
 * MI-20 — *"one contract, two carriages, never two contracts"* — is what makes
 * that correct rather than convenient. This file therefore **invents no
 * encoding**: it frames JSON the core defined and decodes protobuf the frozen
 * contracts define, and nothing in between is this shell's vocabulary.
 *
 * # CB-2 and CB-4
 *
 * Nothing here branches on a `ConnectionState`, a `reason_code` class, a policy
 * verdict or a candidate priority. The severity a subscriber renders on is the
 * **registry's own**, resolved in the core and carried in F-4's `resolved`
 * block; the sentences come from F-10's `tw_render_diagnostic`. A `when (state)`
 * here would be a seventh classifier (R-31).
 */
internal class CoreClient(private val handle: Long) {

    private companion object {
        const val TAG = "TwinVPN.Core"

        /**
         * How long the drain thread sits in one `tw_core_next_event` call.
         *
         * **Not a timeout on anything the core decides.** CD-2 makes timeouts
         * the core's; this bounds how long the thread sits in one call so that
         * shutdown is observed promptly even if `tw_core_wake` is missed, and
         * nothing else depends on it.
         */
        const val DRAIN_TIMEOUT_MS = 250

        /** `twinvpn_mgmt::envelope::LENGTH_PREFIX_BYTES`. */
        const val PREFIX_BYTES = 4

        /** `twinvpn_mgmt::envelope::MAX_ENVELOPE_BYTES`. */
        const val MAX_ENVELOPE_BYTES = 1 shl 20

        /** `twinvpn_mgmt::envelope::MI_VERSION`. */
        const val MI_VERSION = 1
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

    /**
     * Starts the drain thread.
     *
     * **One loop, one thread.** F-6/S-47: exactly one thread may hold the
     * instance for mutation at a time, and `tw_core_next_event` is the blocking
     * call, so it gets a thread of its own rather than a coroutine on a shared
     * dispatcher — blocking a dispatcher worker is how a runtime starves.
     */
    fun start() {
        if (handle == 0L) {
            Log.e(TAG, "no core instance; the event stream cannot be started")
            return
        }
        if (!running.compareAndSet(false, true)) return
        drain = thread(name = "twinvpn-core-events", isDaemon = false) {
            while (running.get()) {
                val frame = NativeBridge.nativeCoreNextEvent(handle, DRAIN_TIMEOUT_MS)
                    ?: continue // a timeout, a wake, or a refusal: ask again.
                decode(frame)?.let(::publish)
            }
        }
    }

    /**
     * Stops the drain thread. Idempotent.
     *
     * `tw_core_wake` is what cancels an in-flight `next_event` rather than
     * waiting out its timeout, and it is why the thread is joined rather than
     * interrupted: a thread killed inside a JNI call leaves the core holding a
     * lock nobody will release.
     */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        if (handle != 0L) NativeBridge.nativeCoreWake(handle)
        drain?.join(1_000)
        drain = null
    }

    /**
     * Asks the core to connect to one peer.
     *
     * Not "connects": the shell has no opinion about whether a connection is
     * possible, which peers exist, or what to do if it fails. It submits an
     * intent and renders whatever comes back on the event stream.
     *
     * @param peerDeviceId the peer's 32-byte `device_id`. **The parameter is
     *   the whole of what the operation means** — `session.connect` names a
     *   peer and refuses `PROTO.MALFORMED_MESSAGE` without one — which is why
     *   the bare-name submission this class used to be limited to could not
     *   express it at all.
     */
    fun requestConnect(peerDeviceId: ByteArray) {
        submit("session.connect", peerDeviceId)
    }

    /** Brings every known session up and arms enforcement. */
    fun requestNetUp() {
        submit("net.up")
    }

    /** Asks the core to disconnect one peer. ADR-0022 LC-2 row 4 makes this durable. */
    fun requestDisconnect(peerDeviceId: ByteArray) {
        submit("session.disconnect", peerDeviceId)
    }

    /**
     * Takes every session down and re-enters `RULESET_BLOCKED`.
     *
     * **MI-K1: this does not clear the latch.** Only ADR-0012 §11.14's
     * authenticated ceremony can, and no path from this class reaches it.
     */
    fun requestNetDown() {
        submit("net.down")
    }

    /**
     * Submits one command, as an MI frame.
     *
     * The refusal — when there is one — is an **F-4 envelope**: a registered
     * code and typed evidence, never a sentence (MI-15). It is published like
     * any other diagnostic rather than swallowed, because F-5 makes a rejected
     * command an event and a shell that dropped it would leave a user watching
     * a button that did nothing.
     */
    private fun submit(operation: String, params: ByteArray = ByteArray(0)) {
        if (handle == 0L) {
            Log.e(TAG, "no core instance; $operation was not submitted")
            return
        }
        val frame = frame(operation, params) ?: run {
            Log.e(TAG, "$operation could not be framed")
            return
        }
        NativeBridge.nativeCoreSubmit(handle, frame)?.let { refusal ->
            render(refusal)?.let(::publish)
        }
    }

    /**
     * One `request` body in an MI frame.
     *
     * `request_id`, `correlation_id` and `idempotency_key` are empty and the
     * ABI ignores them: it is in-process and fire-and-forget, so there is no
     * request to correlate and no retry to deduplicate. They are written out
     * rather than omitted so the frame is the same shape a socket carriage
     * would put on the wire.
     */
    private fun frame(operation: String, params: ByteArray): ByteArray? {
        val body = JSONObject()
            .put("kind", "request")
            .put("operation", operation)
            .put("params", org.json.JSONArray().also { array ->
                for (byte in params) array.put(byte.toInt() and 0xFF)
            })
        val envelope = JSONObject()
            .put("mi_version", MI_VERSION)
            .put("request_id", org.json.JSONArray())
            .put("correlation_id", org.json.JSONArray())
            .put("seq", 0)
            .put("idempotency_key", org.json.JSONArray())
            .put("as_of_ms", 0)
            .put("body", body)

        val json = envelope.toString().toByteArray(Charsets.UTF_8)
        // The cap, checked on the SEND side too, so this shell cannot emit a
        // frame the core would itself refuse.
        if (json.size > MAX_ENVELOPE_BYTES) return null
        return ByteBuffer.allocate(PREFIX_BYTES + json.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(json.size)
            .put(json)
            .array()
    }

    /**
     * Decodes one event frame.
     *
     * # An unknown `body.kind` is an event to ignore, never a parse failure
     *
     * `twinvpn.h` is explicit about the discriminator: *"treat an unknown value
     * as a forward-compatible event to ignore, never as a parse failure."* A
     * shell that threw on a body a newer core added would make every additive
     * change a breaking one.
     */
    private fun decode(frame: ByteArray): Rendered? {
        if (frame.size <= PREFIX_BYTES) return null
        val declared = ByteBuffer.wrap(frame, 0, PREFIX_BYTES).order(ByteOrder.BIG_ENDIAN).int
        // The bound BEFORE the slice: `ownership.md` §6 rule 9 makes an over-cap
        // value a typed refusal, "never a truncation, never a pad".
        if (declared <= 0 || declared > MAX_ENVELOPE_BYTES) return null
        if (frame.size < PREFIX_BYTES + declared) return null

        val json = try {
            JSONObject(String(frame, PREFIX_BYTES, declared, Charsets.UTF_8))
        } catch (_: org.json.JSONException) {
            return null
        }
        val body = json.optJSONObject("body") ?: return null

        return when (body.optString("kind")) {
            "event" -> event(body)
            // MI-19's ORDERED marker. A gap is a fact a subscriber must see —
            // the posture it is showing may be stale — so it is surfaced rather
            // than dropped, and it is not a diagnostic the core emitted.
            "compacted" -> Rendered(
                reasonCode = "MGMT.EVENTS_COMPACTED",
                summary = "",
                nextAction = null,
                severity = Rendered.Severity.WARN,
                userActionable = false,
                protection = Rendered.ProtectionIndicator.UNKNOWN,
                lockdownTag = NativeBridge.LOCKDOWN_UNVERIFIED.toString(),
            )
            else -> null
        }
    }

    /**
     * One `event` body.
     *
     * Only the three diagnostic-bearing topics carry an `ErrorEnvelope`. The
     * others carry a `TransitionEvent` or a `SessionEvent`, whose rendering is
     * the status screen's job and not this class's — a subscriber that needs
     * them takes them from the same stream.
     */
    private fun event(body: JSONObject): Rendered? {
        val payload = body.optJSONArray("payload") ?: return null
        val bytes = ByteArray(payload.length()) { index -> payload.getInt(index).toByte() }
        return when (body.optString("topic")) {
            "diagnostic", "command.rejected" -> render(bytes)
            else -> null
        }
    }

    /**
     * Turns an `ErrorEnvelope` into something a subscriber can present.
     *
     * # CB-4, and the two halves this keeps apart
     *
     * The **attributes** — severity, `user_actionable` — are the registry's,
     * resolved once in the core and carried in F-4's `resolved` block. The
     * **sentences** are F-10's, produced by `tw_render_diagnostic` from the
     * same catalogue. Neither is composed here, and there is no branch on the
     * code itself: a `when (reasonCode)` in this file would be the seventh
     * classifier R-31 names.
     */
    private fun render(envelopeBytes: ByteArray): Rendered? {
        val envelope = try {
            ErrorEnvelope.parseFrom(envelopeBytes)
        } catch (_: com.google.protobuf.InvalidProtocolBufferException) {
            return null
        }
        val resolved = envelope.resolved
        val locale = Locale.getDefault().toLanguageTag()

        // F-10 renders BOTH sentences from the same call, in the requested
        // locale. An empty result is an empty sentence, not an error: ADR-0019
        // LT-3 selects the variant in the core, and a code with no next action
        // legitimately has none.
        val renderedBytes = NativeBridge.nativeRenderDiagnostic(
            envelope.reasonCode,
            envelopeBytes,
            locale,
            ByteArray(0),
        )
        val text = renderedBytes?.toString(Charsets.UTF_8).orEmpty()

        return Rendered(
            reasonCode = envelope.reasonCode,
            summary = text,
            nextAction = if (resolved.userActionable) text.ifEmpty { null } else null,
            severity = severity(resolved.severity),
            userActionable = resolved.userActionable,
            // **O-18's fail-safe direction.** A diagnostic is not a protection
            // assertion, and this class has not queried one — so `UNKNOWN`,
            // which the UI treats as closer to unprotected than to protected.
            // Reporting `PROTECTED` from a value nobody asserted is exactly the
            // "agent's belief about what it configured" ADR-0015 §11.6 rule 1
            // forbids.
            protection = Rendered.ProtectionIndicator.UNKNOWN,
            lockdownTag = NativeBridge.LOCKDOWN_UNVERIFIED.toString(),
        )
    }

    /**
     * The registry's severity, as the generated enum carries it.
     *
     * Total over the enum, with the proto3 zero named: an unset severity is
     * **not** `INFO`. It decodes to the strictest reading this ladder has for
     * "the sender did not say", which is `WARN` — the same reasoning
     * `HealthState::Unspecified` follows, and the reason a four-value model of
     * a five-value enum is a defect.
     */
    private fun severity(value: ErrorSeverity): Rendered.Severity = when (value) {
        ErrorSeverity.ERROR_SEVERITY_INFO -> Rendered.Severity.INFO
        ErrorSeverity.ERROR_SEVERITY_WARN -> Rendered.Severity.WARN
        ErrorSeverity.ERROR_SEVERITY_ERROR -> Rendered.Severity.ERROR
        ErrorSeverity.ERROR_SEVERITY_CRITICAL -> Rendered.Severity.CRITICAL
        ErrorSeverity.ERROR_SEVERITY_UNSPECIFIED,
        ErrorSeverity.UNRECOGNIZED,
        -> Rendered.Severity.WARN
    }

    /** Fans one resolved diagnostic out. Called by the drain thread. */
    private fun publish(rendered: Rendered) {
        for (subscriber in subscribers) subscriber(rendered)
    }
}
