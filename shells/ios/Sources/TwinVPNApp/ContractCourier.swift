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
//
//  ===========================================================================
//  BLOCKED: THE THREE OPERATIONS THIS FILE NEEDS ARE NOT IN THE CATALOGUE
//  ===========================================================================
//
//  `makeFetchRequest`, `verifySignedDocuments` and `makeCommitRequest` are NOT
//  implemented in `CoreLite`, and this file does not call them. That is
//  deliberate: there is no honest way to write them today, and writing them
//  anyway would mint a second vocabulary.
//
//  They are not declared as always-throwing stubs either. A request BUILDER has
//  to name an operation, and there is no name to give it — `twinvpn.h`: "a name
//  the catalogue does not contain is MGMT.OP_UNKNOWN". A stub would put three
//  operation-shaped method names into this shell's vocabulary for operations
//  that do not exist, which is the second-vocabulary hazard rather than an
//  escape from it. `refreshSignedDocuments` therefore refuses at the top with
//  the code the core would answer with, and the three-step sequence stays in
//  this comment where it cannot be mistaken for working code.
//
//    * **The fetch and the commit have no operation to name.** ADR-0017 §11.9's
//      table is the whole catalogue and `twinvpn_mgmt::command::CoreCommand` is
//      its verbatim mirror ("MI MUST NOT rename, re-shape, merge, split, or
//      reorder a core command"). Neither contains a row that hands verbatim
//      signed octets in either direction. `policy.get` returns the EFFECTIVE
//      `AccessPolicy`/`DNSPolicy` snapshot, not the signed document, and
//      ADR-0018 §11.14's ADR-0017 row (d) forbids "a method that returns raw
//      store contents". `twinvpn.h` is explicit about what a name off the
//      catalogue produces: "a name the catalogue does not contain is
//      MGMT.OP_UNKNOWN".
//
//    * **The gap is a KNOWN, OPEN amendment obligation, not an oversight.**
//      ADR-0018 §11.14 lists what ADR-0017 still owes, first item: "(a) A method
//      that hands **verbatim signed octets** to the daemon for verification and
//      commit (ST-31)." ST-31a then reversed the courier direction without adding
//      the operation. Until §11.9 carries that row and `CoreCommand` gains it,
//      this shell has nothing to submit.
//
//    * **`verifySignedDocuments` has no ABI path either.** `tw_core_submit`
//      accepts catalogue operations only, so a local `core-lite` verify is
//      reachable exactly when the catalogue row above exists — not before.
//
//  This is the same class of gap as `PairingView`'s `PairingModel`, and it is
//  reported the way `CoreProtocol.swift` reports `stopReason` and
//  `memoryPressure`: named, with the amendment it needs, rather than papered over
//  with an invented operation name that the core would refuse.

import Foundation
import os

@MainActor
final class ContractCourier {
    private let management: ManagementClient
    private let log = Logger(subsystem: "net.twinvpn.app", category: "contract")

    init(management: ManagementClient = .shared) {
        self.management = management
    }

    /// Would ask the extension to fetch, then parse and verify here. **Refuses,
    /// and returns the registered code that says why** — the operation it needs
    /// does not exist yet; see the header and the step list below.
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
    ///
    /// The three steps this would take, once §11.14 (a) exists:
    ///
    ///   1. The EXTENSION fetches. It holds the exempted socket; we do not.
    ///   2. `core-lite` parses and verifies, HERE. ADR-0018 §11.12's profile is
    ///      "the same source containing twinvpn-schema, twinvpn-crypto
    ///      (verification only), twinvpn-store, twinvpn-trust and twinvpn-diag,
    ///      and NO data-plane crate."
    ///   3. The verified result goes back over ADR-0017 and the PROVIDER commits
    ///      it: ST-30's single opener, and ST-31's "signature verification and
    ///      floor enforcement happen at the writer, never at the courier" — this
    ///      process is the courier even in the reading where it also verifies.
    ///
    /// Steps 1 and 3 need the operation ADR-0018 §11.14's ADR-0017 row (a) still
    /// owes, and step 2 is reachable only through step 1. So the whole sequence
    /// refuses here, at the top, with `MGMT.OP_UNKNOWN` — the code `twinvpn.h`
    /// says an off-catalogue name produces, reported before anything is sent
    /// rather than discovered from a round trip that could not have worked.
    ///
    /// **The refusal is not an escalation.** LC-17a: "staleness is not a reason
    /// to stop", and the extension is already running on the last verified
    /// generation it holds. Nothing is retried on a schedule this file chooses —
    /// the core owns every deadline (CD-1) — and `management` is held rather than
    /// dropped because it is the channel steps 1 and 3 will use unchanged.
    @discardableResult
    func refreshSignedDocuments() async -> String {
        log.notice("contract refresh is unavailable on this build (MGMT.OP_UNKNOWN); the extension keeps its last verified generation")
        return ReasonCode.operationUnknown
    }
}
