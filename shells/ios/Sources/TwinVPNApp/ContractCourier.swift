//  ContractCourier.swift — the corrected fetch split, and the conflict it sits on.
//
//  Authority: docs/networking.md §5.4's CORRECTED iOS memory-limit row;
//  ADR-0018 §11.12 (`core-lite`) and §11.16 (m); ADR-0016 PS-24 condition 3;
//  ADR-0022 LC-17 and LC-17a; ADR-0020 ST-30 and ST-31.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  THE SPLIT THIS FILE IMPLEMENTS
//  ===========================================================================
//
//  `docs/networking.md` §5.4's corrected row, verbatim:
//
//    "Corrected — the original wording of this row was a defect. It read
//     'contract fetch/parse and diagnostics live in the app process', and an
//     implementation following it literally builds a DEADLOCK: under
//     `includeAllNetworks` the app process has NO NETWORK, because its traffic is
//     ADR-0012 class 1/2 protected and dropped, and it cannot match class 7 —
//     KS-9(1)'s predicate names the PROVIDER, and iOS has no host firewall to
//     carry an exemption. So the fetch fails exactly when the contract is most
//     needed, and fails silently from the extension's point of view.
//     THE EXTENSION FETCHES (it holds the exempted socket) and hands raw bytes to
//     the app; THE APP PARSES AND VERIFIES."
//
//  ADR-0018 §11.16 (m) records the same as a confirmed reading, and PS-24
//  condition 3 is the mechanism: "A recovery step that requires core-lite to
//  fetch anything is unreachable exactly when it is needed."
//
//  So: the extension fetches. This file receives bytes and hands them to
//  `core-lite` to parse and verify. It never opens a socket.
//
//  ===========================================================================
//  AN UNRESOLVED CONFLICT, REPORTED RATHER THAN RESOLVED HERE
//  ===========================================================================
//
//  Three documents describe this split and they do not agree:
//
//    * networking.md §5.4 (corrected) + ADR-0018 §11.12/§11.16 (m):
//        EXTENSION fetches -> APP (core-lite) parses and verifies.   <-- IMPLEMENTED
//    * ADR-0020 ST-31 ("the iOS courier rule"):
//        APP fetches and structurally validates -> PROVIDER verifies the
//        signature and performs the ST-23 commit.
//    * ADR-0022 LC-17's division table:
//        APP owns "fetch of RelayMap, AccessPolicy, DNSPolicy, trust documents"
//        AND "verification and compilation into a compact pre-validated binary
//        generation"; the extension "reads, NEVER writes".
//
//  The three place the FETCH in two different processes and the VERIFY in two
//  different processes. `mobile-ios` implements ADR-0018 §11.12's reading because
//  the domain brief and §11.16 (m) both name it as the corrected one, and because
//  PS-24 condition 3 shows the app-fetch reading is unreachable under
//  `includeAllNetworks`. The disagreement is reported to the integration lead as
//  a finding rather than settled here.
//
//  What is NOT in dispute, and is honoured either way: ST-30's single opener —
//  "exactly ONE process opens the vault… the UI, the CLI, and any local
//  automation MUST NOT open the store file" — and ST-31's "signature verification
//  and floor enforcement happen at the writer, never at the courier". So whatever
//  this app verifies, it does not WRITE: it returns the verified result over
//  ADR-0017 and the provider commits.

import Foundation
import os

@MainActor
final class ContractCourier {
    private let management: ManagementClient
    private let log = Logger(subsystem: "net.twinvpn.app", category: "contract")

    init(management: ManagementClient = .shared) {
        self.management = management
    }

    /// Asks the extension to fetch, then parses and verifies here.
    ///
    /// There is no `URLSession` in this file, and there must not be. LC-17a's
    /// three normative consequences bind:
    ///
    ///   1. "No recovery step may block on / wait for / message / launch the app
    ///      process." — so this is never on a recovery path; it runs when the
    ///      app happens to be alive, and the extension's own recovery uses the
    ///      last verified generation it already holds.
    ///   2. "Staleness is not a reason to stop; absent or failed verification →
    ///      `BLOCKED` (LC-6) — never a wait on the app."
    ///   3. "The memory-shed ladder MUST NOT evict recovery-path state."
    ///
    /// C-3's memory pressure is what the split buys: parse-and-verify is "a
    /// signature check and a CBOR decode over a multi-KB document", and it
    /// happens in this process, inside the app's budget, not inside the
    /// provider's 12 MB.
    func refreshSignedDocuments() async {
        do {
            // 1. The EXTENSION fetches. It holds the exempted socket; we do not.
            let raw = try await management.send(CoreLite.shared.makeFetchRequest())

            // 2. `core-lite` parses and verifies, HERE. ADR-0018 §11.12's profile
            //    is "the same source containing twinvpn-schema, twinvpn-crypto
            //    (verification only), twinvpn-store, twinvpn-trust and
            //    twinvpn-diag, and NO data-plane crate."
            let verified = try CoreLite.shared.verifySignedDocuments(raw)

            // 3. The verified result goes back over ADR-0017. The PROVIDER
            //    commits it: ST-30's single opener, and ST-31's "signature
            //    verification and floor enforcement happen at the writer, never
            //    at the courier" — this process is the courier even in the
            //    reading where it also verifies.
            _ = try await management.send(CoreLite.shared.makeCommitRequest(verified))
        } catch {
            // A failure here is NOT a failure of the tunnel. LC-17a: "staleness
            // is not a reason to stop", and the extension is already running on
            // the last verified generation it holds. Nothing is escalated and
            // nothing is retried on a schedule this file chooses — the core owns
            // every deadline (CD-1).
            log.notice("contract refresh did not complete; the extension keeps its last verified generation")
        }
    }
}
