//  DiagnosticsView.swift — bundle assembly and export, in the APP process.
//
//  Authority: ADR-0018 §11.2 row 2.19 ("on iOS/iPadOS diagnostics run in the app
//  process via the `core-lite` profile"), C-3; ADR-0015 §11.4 (redaction), §11.8
//  (the bundle), §11.9 (4); ADR-0019 §11.8 (Files integration), §11.10 (g);
//  ADR-0022 LC-17's division table.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHY DIAGNOSTICS ARE HERE AND NOT IN THE PROVIDER
//  ===========================================================================
//
//  ADR-0022 LC-17's table assigns to the APP: "diagnostic ring beyond bounded
//  64 KB tail", "diagnostic bundle generation, redaction, rendering". The provider
//  keeps a bounded tail and nothing more, and LC-17's forbidden list names
//  "diagnostic bundle assembly" and "symbolication" explicitly.
//
//  C-3 is why: the provider has 12 MB and a bundle is the largest allocation the
//  product makes.
//
//  ===========================================================================
//  REDACTION IS THE EMITTER'S, NOT THIS VIEW'S
//  ===========================================================================
//
//  ADR-0015 §11.4: "Redaction is applied by the emitter based on the schema
//  classification. **There is no 'scrub the log with regexes before sending'
//  step.**"
//
//  So this file contains no filter, no regex, and no allowlist. It asks
//  `core-lite` for a Tier-1 bundle, and what comes back is already pseudonymised:
//  SENSITIVE values ("endpoints, addresses, iface names, DeviceIdentity, peer IDs,
//  hostnames, SSIDs") arrive as `ipv4-A:port-1`-style tokens, consistent within
//  one bundle and different across bundles. SECRET values ("key material, pairing
//  secrets, packet payloads, tunnel plaintext") have "no code path" at all.
//
//  ===========================================================================
//  THE USER PUSHES. THERE IS NO PULL.
//  ===========================================================================
//
//  ADR-0015 §11.8: the bundle is "signed with `DeviceKey`, rate-limited, pushed by
//  user only — **No remote 'collect a crash report' command exists.**" There is
//  therefore no automatic upload in this file and no background submission.

import SwiftUI
import UniformTypeIdentifiers

struct DiagnosticsView: View {
    @EnvironmentObject private var management: ManagementClient
    @State private var bundle: DiagnosticBundle?
    @State private var isExporting = false
    @State private var reasonCode: String?

    var body: some View {
        // `NavigationView` + `.stack`, not `NavigationStack`. See `StatusView`
        // for why: `NavigationStack` is iOS 16.0+ and §11.9 row 1 fixes the floor
        // at 15.0.
        NavigationView {
            List {
                Section {
                    Button(String(localized: "diagnostics_assemble")) {
                        Task { await assemble() }
                    }
                }

                if let bundle {
                    // ADR-0019 §11.10 (g): "export writes only after the redaction
                    // preview is confirmed". The preview is not a courtesy — it is
                    // the user's opportunity to see what leaves the device, and
                    // the export button does not exist until they have seen it.
                    Section {
                        RedactionPreview(bundle: bundle)
                    }
                    Section {
                        Button(String(localized: "diagnostics_export")) {
                            isExporting = true
                        }
                    }
                }

                if let reasonCode {
                    Section { DiagnosticView(reasonCode: reasonCode, evidence: [:]) }
                }
            }
            .navigationTitle(String(localized: "diagnostics_title"))
            // ADR-0019 §11.8: "iOS/iPadOS: `.fileExporter` into Files, plus the
            // share sheet." The artifact is signed and expiring per ADR-0015
            // §11.9 (4); this view moves it, and does not decide its lifetime.
            .fileExporter(
                isPresented: $isExporting,
                document: bundle.map(DiagnosticDocument.init),
                contentType: .data,
                defaultFilename: bundle?.suggestedFilename ?? "twinvpn-diagnostics") { _ in }
        }
        .navigationViewStyle(.stack)
    }

    /// Assembles the bundle.
    ///
    /// The eight parts ADR-0015 §11.8 requires — environment, **both address
    /// families**, DNS, the candidate ledger, the transport ladder, relay
    /// selection, the verdict, and the enforcement snapshot **for both families**
    /// — are assembled by `core-lite`. This function's whole job is to ask, and to
    /// hand it the bounded tail the provider holds.
    private func assemble() async {
        do {
            // The provider's bounded 64 KB tail (LC-17). Fetched over ADR-0017,
            // because the app cannot read the provider's ring directly — ST-30's
            // single opener means the app does not open the store at all.
            let tail = try await management.send(CoreLite.shared.makeRingTailRequest())
            bundle = try CoreLite.shared.assembleBundle(providerTail: tail)
            reasonCode = nil
        } catch {
            // A bundle that could not be assembled is reported as a registered
            // condition, not as an empty file the user might send anyway.
            //
            // `core-lite`'s own code where it gave one — today
            // `STORE.CUSTODY_DEGRADED`, because `dispatch::disposition` still
            // refuses `diag.bundle.create` — so the user is told what actually
            // stopped it. `PLATFORM.ADAPTER_UNAVAILABLE` covers the other arm:
            // a channel that could not carry the tail request at all
            // (`ManagementChannelError`), which is a different fact.
            reasonCode = (error as? CoreLiteRefusal)?.reasonCode ?? ReasonCode.adapterUnavailable
            bundle = nil
        }
    }
}

/// Shows what will leave the device, before it does.
///
/// ADR-0015 §11.4's pseudonymisation is already applied by the time this renders:
/// `203.0.113.7:51820` has become `ipv4-A:port-1`, "same value → same token
/// within one bundle, different across bundles". This view proves that to the
/// user rather than asking them to trust it.
struct RedactionPreview: View {
    let bundle: DiagnosticBundle

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "diagnostics_redaction_preview"))
                .font(.headline)
            ScrollView {
                Text(bundle.preview)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
            .frame(maxHeight: 240)
        }
    }
}

/// The exportable document.
struct DiagnosticDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    let bundle: DiagnosticBundle

    init(_ bundle: DiagnosticBundle) {
        self.bundle = bundle
    }

    init(configuration: ReadConfiguration) throws {
        // A bundle is written, never read back: it is signed and expiring
        // (ADR-0015 §11.9 (4)), and re-importing one would let a stale artifact
        // be presented as current. ST-8 says the same about attestations: "a
        // stored blob is not evidence of anything at a later date."
        throw CocoaError(.fileReadUnsupportedScheme)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: bundle.signedBytes)
    }
}
