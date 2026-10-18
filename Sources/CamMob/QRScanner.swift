import AppKit
import AVFoundation
import SwiftUI
import Vision
import DahuaP2P

enum QRScanner {
    /// Decodes every QR code in an image and returns the first payload that looks like a device.
    static func decode(_ image: CGImage) -> [String] {
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr, .dataMatrix, .aztec]
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        guard (try? handler.perform([req])) != nil else { return [] }
        return (req.results ?? []).compactMap { $0.payloadStringValue }
    }

    static func decode(fileURL: URL) -> [String] {
        guard let img = NSImage(contentsOf: fileURL), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return [] }
        return decode(cg)
    }

    static func decodeClipboard() -> [String] {
        let pb = NSPasteboard.general
        if let img = NSImage(pasteboard: pb), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) { return decode(cg) }
        if let urls = pb.readObjects(forClasses: [NSURL.self]) as? [URL], let u = urls.first { return decode(fileURL: u) }
        if let s = pb.string(forType: .string) { return [s] }
        return []
    }

    static func firstDevice(in payloads: [String]) -> DeviceQR? {
        for p in payloads { if let q = DeviceQR.parse(p) { return q } }
        return nil
    }
}

/// Live camera preview that reports the first device QR it sees.
final class CameraScanner: NSObject, ObservableObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    let session = AVCaptureSession()
    @Published var error: String?
    @Published var lastPayload: String?
    var onDevice: ((DeviceQR) -> Void)?
    private let queue = DispatchQueue(label: "cammob.camera")
    private var lastScan = Date.distantPast
    private var done = false

    func start() {
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self else { return }
            guard granted else { DispatchQueue.main.async { self.error = "Camera access denied. Allow CamMob in System Settings → Privacy & Security → Camera." }; return }
            self.queue.async { self.configure() }
        }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device) else {
            DispatchQueue.main.async { self.error = "No camera found." }
            return
        }
        session.beginConfiguration()
        session.sessionPreset = .high
        if session.canAddInput(input) { session.addInput(input) }
        let out = AVCaptureVideoDataOutput()
        out.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        out.alwaysDiscardsLateVideoFrames = true
        out.setSampleBufferDelegate(self, queue: queue)
        if session.canAddOutput(out) { session.addOutput(out) }
        session.commitConfiguration()
        session.startRunning()
    }

    func stop() {
        queue.async { if self.session.isRunning { self.session.stopRunning() } }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !done, Date().timeIntervalSince(lastScan) > 0.25, let pb = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        lastScan = Date()
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr, .dataMatrix, .aztec]
        try? VNImageRequestHandler(cvPixelBuffer: pb, options: [:]).perform([req])
        for r in req.results ?? [] {
            guard let s = r.payloadStringValue else { continue }
            DispatchQueue.main.async { self.lastPayload = s }
            if let q = DeviceQR.parse(s) {
                done = true
                DispatchQueue.main.async { self.onDevice?(q) }
                return
            }
        }
    }
}

struct CameraPreview: NSViewRepresentable {
    let session: AVCaptureSession

    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        v.wantsLayer = true
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspect
        layer.frame = v.bounds
        layer.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        v.layer = layer
        return v
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

struct CameraScanSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var scanner = CameraScanner()
    let onDevice: (DeviceQR) -> Void

    var body: some View {
        VStack(spacing: 10) {
            Text("Hold the DVR's P2P QR code (sticker or on-screen) up to the camera").font(.headline)
            ZStack {
                CameraPreview(session: scanner.session).frame(width: 560, height: 360).background(Color.black).clipShape(RoundedRectangle(cornerRadius: 8))
                if let e = scanner.error { Text(e).foregroundStyle(.red).padding().background(.black.opacity(0.7)) }
            }
            Text(scanner.lastPayload.map { "Seen: \($0)" } ?? "Looking for a QR code…").font(.caption).foregroundStyle(.secondary).lineLimit(2)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction) }
        }
        .padding(16)
        .onAppear {
            scanner.onDevice = { q in onDevice(q); dismiss() }
            scanner.start()
        }
        .onDisappear { scanner.stop() }
    }
}
