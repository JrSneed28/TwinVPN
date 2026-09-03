//  PairingView.swift — the pairing SHELL HALF, and only that.
//
//  Authority: ADR-0018 §11.2 row 2.7 ("Pairing Subsystem | core: ceremony,
//  SPAKE2/QR verification, idempotency | shell: CAMERA, QR RENDER, DISPLAY");
//  ADR-0007 §7.4 (the C-B ceremony); ADR-0019 S-3; ownership.md §10.1.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  THE DIVISION, WHICH IS THE WHOLE POINT OF THIS FILE
//  ===========================================================================
//
//  §11.2 row 2.7 splits pairing in exactly one place, and `ownership.md` §10.1
//  restates it for this wave: "the shell half only: camera, QR render, display.
//  The ceremony, SPAKE2/QR verification and idempotency are the core's. **Do not
//  reimplement any of it.**"
//
//  So this file:
//    * opens the camera and reports the bytes a QR code contained;
//    * renders bytes the core produced as a QR code;
//    * displays a fingerprint string the core rendered.
//
//  It does NOT:
//    * parse a `PairingOffer`;
//    * derive `pairing_id` or `K_pair`;
//    * compute or compare a `transcript_hash`;
//    * decide whether a scan is valid, expired, or replayed.
//
//  Every one of those is a decision, and every one is in the core. A QR payload
//  that is not a `PairingOffer` is refused BY THE CORE with a registered code;
//  this view cannot tell the difference and must not try.
//
//  ===========================================================================
//  A RESIDUAL ADR-0019 ALREADY STATES
//  ===========================================================================
//
//  S-3: "`isSecureTextEntry`-class protection is *not* available for arbitrary
//  views on iOS — the residual is stated." A rendered QR code containing a
//  pairing secret is on screen, and iOS offers no way to exclude an arbitrary
//  view from a screenshot or a screen recording. §11.10 records the same:
//  "on iOS and iPadOS it cannot be suppressed."
//
//  What this file does instead is bound the EXPOSURE WINDOW: the offer carries
//  `not_after_ms = 120000` (ADR-0007 §7.4), and the view dismisses itself when
//  the core says the offer expired. That is a mitigation, not a fix, and it is
//  labelled as one.

import AVFoundation
import CoreImage.CIFilterBuiltins
import SwiftUI

struct PairingView: View {
    /// The room's light, resolved at the root. DESIGN.md D1 keeps the panels
    /// achromatic; this is the 0.05/0.06 `glassStateTint` and nothing more.
    let tone: StateTone

    @StateObject private var model = PairingModel()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        // `NavigationView` + `.stack`, not `NavigationStack`. See `StatusView`
        // for why: `NavigationStack` is iOS 16.0+ and §11.9 row 1 fixes the floor
        // at 15.0.
        //
        // A `ScrollView`, not a `List`, for the reason DESIGN.md's Floor
        // paragraph gives: `.scrollContentBackground(.hidden)` is iOS 16.0, so a
        // `List` would paint an opaque slab over §3's backdrop.
        NavigationView {
            ScrollView {
                VStack(spacing: Space.betweenPanels) {
                    if let offer = model.renderedOffer {
                        // The C-B ceremony where a camera and a screen exist
                        // (ADR-0007 §7.4). The bytes came from the core; this
                        // draws them.
                        //
                        // §4.1's "pairing frame" is a panel, radius 28. The code
                        // inside keeps its own black-on-white plate: a QR code is
                        // read by a camera, and tinting it with `glassStateTint`
                        // to match the room would be a design choice that costs
                        // the ceremony its scan margin.
                        QRCodeImage(payload: offer)
                            .frame(maxWidth: 320, maxHeight: 320)
                            .accessibilityLabel(String(localized: "pairing_qr_description"))
                            .glassPanel(tone: tone)
                            .panelTransition(reduceMotion: reduceMotion)
                    } else {
                        CameraScanner { payload in
                            // The bytes go straight to the core. This closure
                            // does not look at them.
                            model.submitScannedPayload(payload)
                        }
                        .frame(height: 320)
                        .clipShape(
                            RoundedRectangle(cornerRadius: Radius.panel, style: .continuous))
                        .glass(
                            RoundedRectangle(cornerRadius: Radius.panel, style: .continuous),
                            tone: tone)
                    }

                    if let fingerprint = model.confirmationFingerprint {
                        // ADR-0007 §7.4's third concern: "post-hoc display of the
                        // peer's label and 20-char fingerprint on both ends".
                        // DISPLAY ONLY — the comparison is the user's, and the
                        // acceptance is the core's.
                        //
                        // §5's monospaced role, with its +0.5 tracking, exists
                        // for exactly this string: A11Y-9, "a 20-character
                        // fingerprint is compared by eye, character by character,
                        // and tight tracking is what makes `8`/`B` and `0`/`O` a
                        // coin flip."
                        StyledText(fingerprint, .mono)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .glassCard(tone: tone)
                            .panelTransition(reduceMotion: reduceMotion)
                    }

                    if let code = model.reasonCode {
                        DiagnosticView(reasonCode: code, evidence: model.evidence)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .glassPanel(tone: tone)
                            .panelTransition(reduceMotion: reduceMotion)
                    }
                }
                .padding(.horizontal, Space.screenMargin)
                .padding(.vertical, Space.xl)
            }
            .navigationTitle(String(localized: "pairing_title"))
            .task { await model.begin() }
            .onDisappear { model.end() }
            .animation(Motion.panelAppear, value: model.confirmationFingerprint)
            .animation(Motion.panelAppear, value: model.reasonCode)
        }
        .navigationViewStyle(.stack)
    }
}

/// Renders bytes as a QR code. No interpretation.
struct QRCodeImage: View {
    let payload: Data

    var body: some View {
        if let image = Self.render(payload) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            // A payload that will not encode is reported through the core's
            // catalogue, not as a blank square that looks like a working code
            // nobody can scan.
            DiagnosticView(reasonCode: ReasonCode.adapterUnavailable, evidence: [:])
        }
    }

    private static func render(_ payload: Data) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = payload
        // `.correctionLevel = "H"` so the code survives a scratched screen; this
        // is a rendering choice, which is exactly what CB-4 leaves to the shell.
        filter.correctionLevel = "H"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }
}

/// The camera. Reports bytes; decides nothing.
struct CameraScanner: UIViewControllerRepresentable {
    let onPayload: (Data) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onPayload = onPayload
        return controller
    }

    func updateUIViewController(_ controller: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onPayload: ((Data) -> Void)?
    private let session = AVCaptureSession()

    override func viewDidLoad() {
        super.viewDidLoad()
        configureSession()
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            // No camera. ADR-0023 EM-21 is the reason this is not fatal: "the
            // C-B ceremony does NOT require a camera; it requires a CONFIDENTIAL
            // CHANNEL", and EM-22 gives four enrolment channels. Which one to
            // offer is the core's decision, surfaced as a next action — this
            // view just stops.
            return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.layer.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        Task.detached { [session] in session.startRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard let object = objects.first as? AVMetadataMachineReadableCodeObject,
              let value = object.stringValue else { return }
        // Straight through. No validation, no length check against a
        // `PairingOffer`'s shape, no expiry comparison — every one of those is
        // the core's, and doing any of them here would be a second copy of a
        // ceremony rule that could drift from the first.
        onPayload?(Data(value.utf8))
    }
}
