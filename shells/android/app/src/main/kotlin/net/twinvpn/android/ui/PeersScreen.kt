package net.twinvpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.twinvpn.android.R

/**
 * The peer list.
 *
 * Authority: ADR-0019 §11's presentation contract; ADR-0018 CB-2, CB-4;
 * ADR-0015 §11.4 (a peer label is `SENSITIVE`).
 *
 * # Empty, and honestly so
 *
 * The peer set lives in the core and reaches the UI over ADR-0017's event
 * stream. That binding is blocked on W-38 — `contracts/` defines no command or
 * event message — so there is nothing to list, and this screen says so rather
 * than showing a plausible-looking placeholder.
 *
 * When the binding lands, each row renders a peer label and the sentence the
 * core resolved for that peer's state. It will **not** render a
 * `ConnectionState` this screen mapped to text: that mapping is the core's
 * (CB-4), and doing it here would give the GUI and the CLI on one host two
 * vocabularies for one fact.
 */
@Composable
internal fun PeersScreen() {
    Column(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.peers_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.peers_empty),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
