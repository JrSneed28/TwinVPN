package net.twinvpn.android.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import net.twinvpn.android.R

/**
 * The pairing **foundation**: camera, QR render, display. Nothing else.
 *
 * Authority: ADR-0018 §11.2 row 2.7 (the ceremony is the core's; the shell has
 * the camera and the screen), CB-1, CB-2; ADR-0007 §7.4 and §7.5;
 * ADR-0019 §11.10(b) and **S-3**; `docs/implementation/ownership.md` §10.1.
 *
 * # What this screen must not contain, and does not
 *
 * The brief is exact: *"the shell half only: camera, QR render, display. The
 * ceremony, SPAKE2/QR verification and idempotency are the core's. **Do not
 * reimplement any of it.**"*
 *
 * So there is no SPAKE2 here, no transcript, no channel binding, no attempt
 * counter, no expiry check, and no comparison of anything to anything. A scanned
 * payload is handed to the core **as bytes**; the core verifies it, counts the
 * attempt, enforces `pairing.max_failed_runs` and `ceremony_expiry_ms` from
 * `limits.json`, and decides what happens next. A shell that counted attempts
 * would be a second enforcement point for a security-relevant bound, which is
 * the R-31 defect class.
 *
 * # S-3: the offer is optical-confidential
 *
 * ADR-0007 §7.4 makes `pairing_secret` **optical-confidential** — a screenshot, a
 * screen recording, a shoulder, or a screen-sharing session defeats it.
 * ADR-0019 §11.10(b) prescribes the mitigations, and all four are here or in
 * [MainActivity]:
 *
 * | Mitigation | Where |
 * |---|---|
 * | screenshot suppression | `FLAG_SECURE`, set for the whole window in [MainActivity] |
 * | a 120 s visible countdown | `limits.json` `pairing.ceremony_expiry_ms`, **counted down by the core** and rendered here |
 * | no persistence of the offer | nothing in this file writes; the bitmap lives in composition and dies with it |
 * | no clipboard path for the secret | there is no copy affordance, deliberately |
 *
 * # The countdown is the core's clock, not this screen's
 *
 * A `LaunchedEffect` with a `delay(1000)` here would be a second timer on an
 * ambient clock, and ADR-0018 CD-1/CD-2 put every deadline on the injected
 * monotonic clock. The remaining time arrives as an event; this screen renders
 * the number it is given.
 */
@Composable
internal fun PairingScreen() {
    Column(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.pairing_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.pairing_body),
            style = MaterialTheme.typography.bodyMedium,
        )
        // The offer the core minted, if there is one. `null` until the core
        // publishes one: this screen never mints an offer, because minting one
        // means choosing a secret.
        val offer: ByteArray? = null
        if (offer != null) {
            Image(
                bitmap = renderQr(offer).asImageBitmap(),
                contentDescription = stringResource(R.string.pairing_qr_description),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/**
 * Renders bytes as a QR bitmap.
 *
 * Pure display. The payload is `PairingOffer`'s deterministic-CBOR encoding
 * (ADR-0007 §7.4) and this function neither parses nor validates it — which is
 * just as well, because **`PairingOffer` appears nowhere in `contracts/`**
 * (recorded as `ownership.md` §8 **W-21**), so there is nothing generated to
 * parse it with and nothing this shell could legitimately invent.
 *
 * The consequence is reported rather than papered over: until that message has a
 * contract, this screen can render an offer the core hands it but the two sides
 * have no shared, CI-verified definition of what the bytes are.
 */
private fun renderQr(payload: ByteArray, size: Int = 640): Bitmap {
    // ISO-8859-1 is the byte-transparent encoding ZXing's writer expects for
    // binary content: every octet maps to exactly one code point, so the QR
    // carries the CBOR unchanged. A UTF-8 round trip would mangle it.
    val text = String(payload, Charsets.ISO_8859_1)
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bitmap.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
        }
    }
    return bitmap
}
