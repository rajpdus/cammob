import Foundation
import SwiftUI
import Combine
import DahuaP2P
import DahuaRTSP

/// One live channel: a realm on the device tunnel carrying an RTSP session.
@MainActor
final class ChannelSession: ObservableObject, Identifiable {
    let id: Int
    let channel: Int
    let renderer = VideoRenderer()
    @Published var status: String = "idle"
    @Published var playing = false
    @Published var frames = 0
    @Published var kbps = 0
    private var rtsp: RTSPClient?
    private var bytes = 0
    private var lastRate = Date()

    init(channel: Int) {
        self.id = channel
        self.channel = channel
    }

    func start(tunnel: Tunnel, user: String, password: String, substream: Bool, log: @escaping (String) -> Void) async {
        status = "connecting…"
        do {
            let conn = try await tunnel.connect(port: UInt32(tunnel.rtspPort))
            let url = "rtsp://device/cam/realmonitor?channel=\(channel)&subtype=\(substream ? 1 : 0)"
            var o = RTSPClient.Options(url: url, user: user, password: password)
            o.log = log
            let client = RTSPClient(connection: conn, options: o)
            rtsp = client
            client.onFrame = { [weak self] f in
                guard let self else { return }
                self.renderer.enqueue(f)
                Task { @MainActor in
                    self.frames += 1
                    self.bytes += f.data.count
                    let dt = Date().timeIntervalSince(self.lastRate)
                    if dt >= 2 {
                        self.kbps = Int(Double(self.bytes) * 8 / dt / 1000)
                        self.bytes = 0
                        self.lastRate = Date()
                    }
                    if !self.playing { self.playing = true; self.status = "live" }
                }
            }
            client.onClose = { [weak self] err in
                Task { @MainActor in
                    guard let self else { return }
                    self.playing = false
                    self.status = err.map { "closed: \($0)" } ?? "stopped"
                }
            }
            let track = try await client.start()
            status = "waiting for \(track.codec.rawValue)…"
        } catch {
            status = "\(error)"
            playing = false
        }
    }

    func stop() {
        rtsp?.close()
        rtsp = nil
        playing = false
        status = "stopped"
        renderer.flush()
    }
}

/// Owns one P2P tunnel per opened device and its channel sessions.
@MainActor
final class AppModel: ObservableObject {
    @Published var selected: Device?
    @Published var tunnelStatus: String = ""
    @Published var channels: [ChannelSession] = []
    @Published var log: [String] = []
    @Published var connecting = false
    private var tunnel: Tunnel?
    private var tunnelDevice: Device?
    let store = DeviceStore()
    private var storeSub: AnyCancellable?

    init() {
        // The sidebar observes AppModel; forward the nested store's changes so adds show up.
        storeSub = store.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
    }

    func appendLog(_ s: String) {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        log.append("\(f.string(from: Date())) \(s)")
        if log.count > 400 { log.removeFirst(log.count - 400) }
    }

    nonisolated func logSink(_ s: String) {
        if s.hasPrefix(">>>") || s.hasPrefix("<<<") || s.hasPrefix("rtsp") { return }
        Task { @MainActor in self.appendLog(s) }
    }

    /// Reconnects to the device that was open when the app last quit.
    func restoreLastDevice() {
        guard let id = UserDefaults.standard.string(forKey: "cammob.lastDevice"),
              let d = store.devices.first(where: { $0.id.uuidString.caseInsensitiveCompare(id) == .orderedSame }) else { return }
        open(d)
    }

    func open(_ device: Device) {
        if tunnelDevice?.id == device.id, tunnel != nil, !(tunnel!.isClosed) { return }
        close()
        selected = device
        UserDefaults.standard.set(device.id.uuidString, forKey: "cammob.lastDevice")
        connecting = true
        tunnelStatus = "connecting to \(device.serial) via \(device.transport.rawValue)…"
        let password = store.password(for: device)
        Task {
            do {
                var o = Tunnel.Options(serial: device.serial, username: device.username, password: password)
                o.mode = device.transport
                o.log = { [weak self] s in self?.logSink(s) }
                let t = try await Tunnel.open(o)
                t.onClosed = { [weak self] r in Task { @MainActor in self?.tunnelDropped(r) } }
                tunnel = t
                tunnelDevice = device
                connecting = false
                let ms = Int((t.handshake.timings["sync"] ?? 0) * 1000)
                tunnelStatus = "connected (\(t.handshake.mode.rawValue), \(ms) ms)"
                appendLog("tunnel up: rtsp=\(t.rtspPort) priv=\(t.privatePort) http=\(t.httpPort)")
                channels = (1...max(1, device.channels)).map { ChannelSession(channel: $0) }
                for ch in channels {
                    await ch.start(tunnel: t, user: device.username, password: password, substream: device.substream, log: { [weak self] s in self?.logSink(s) })
                }
            } catch {
                connecting = false
                tunnelStatus = "failed: \(error)"
                appendLog("tunnel failed: \(error)")
            }
        }
    }

    private func tunnelDropped(_ reason: String) {
        tunnelStatus = "disconnected: \(reason)"
        for ch in channels { ch.stop() }
        tunnel = nil
    }

    func close() {
        UserDefaults.standard.removeObject(forKey: "cammob.lastDevice")
        for ch in channels { ch.stop() }
        channels = []
        tunnel?.close()
        tunnel = nil
        tunnelDevice = nil
        tunnelStatus = ""
    }

    func reconnect() {
        guard let d = selected else { return }
        close()
        open(d)
    }
}
