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
    @Published var name: String
    let renderer = VideoRenderer()
    @Published var status: String = "idle"
    @Published var playing = false
    @Published var frames = 0
    @Published var kbps = 0
    private var rtsp: RTSPClient?
    private var stopped = false
    private var bytes = 0
    private var lastRate = Date()

    init(channel: Int, name: String) {
        self.id = channel
        self.channel = channel
        self.name = name
    }

    func start(tunnel: Tunnel, user: String, password: String, substream: Bool, log: @escaping (String) -> Void) async {
        stopped = false
        for attempt in 1...3 {
            if stopped { return }
            // Some cameras never answer a DESCRIBE for their sub stream; fall back to the main stream.
            let sub = substream && attempt == 1
            if await startOnce(tunnel: tunnel, user: user, password: password, substream: sub, log: log) {
                if substream && !sub { log("channel \(channel): using main stream") }
                return
            }
            if attempt == 3 || stopped { return }
            log("channel \(channel): \(status); retry \(attempt)\(substream ? " on main stream" : "")")
            rtsp?.close(); rtsp = nil
            status = "retrying…"
            try? await Task.sleep(nanoseconds: 3_000_000_000)
        }
    }

    private func startOnce(tunnel: Tunnel, user: String, password: String, substream: Bool, log: @escaping (String) -> Void) async -> Bool {
        status = "connecting…"
        do {
            let conn = try await tunnel.connect(port: UInt32(tunnel.rtspPort))
            let url = "rtsp://127.0.0.1/cam/realmonitor?channel=\(channel)&subtype=\(substream ? 1 : 0)"
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
            return true
        } catch {
            status = "\(error)"
            playing = false
            return false
        }
    }

    func stop() {
        stopped = true
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

    /// Bumped on every open/close so a stale open task cannot touch a newer connection.
    private var generation = 0

    func open(_ device: Device) {
        if tunnelDevice?.id == device.id, tunnel != nil, !(tunnel!.isClosed) { return }
        close()
        generation += 1
        let gen = generation
        selected = device
        UserDefaults.standard.set(device.id.uuidString, forKey: "cammob.lastDevice")
        connecting = true
        tunnelStatus = "connecting to \(device.serial) via \(device.transport.rawValue)…"
        Task {
            // Keychain may show an access prompt (the app is ad-hoc signed, so each update is a
            // new code identity); read it off the main actor so the window still appears.
            let password = await Task.detached { [store] in store.password(for: device) }.value
            do {
                var o = Tunnel.Options(serial: device.serial, username: device.username, password: password)
                o.mode = device.transport
                o.log = { [weak self] s in self?.logSink(s) }
                let t = try await Tunnel.open(o)
                guard gen == generation else { t.close(); return }   // user moved on meanwhile
                t.onClosed = { [weak self] r in Task { @MainActor in self?.tunnelDropped(r) } }
                tunnel = t
                tunnelDevice = device
                connecting = false
                let ms = Int((t.handshake.timings["sync"] ?? 0) * 1000)
                tunnelStatus = "connected (\(t.handshake.mode.rawValue), \(ms) ms)"
                appendLog("tunnel up: rtsp=\(t.rtspPort) priv=\(t.privatePort) http=\(t.httpPort)")
                // Show what we know right away; the recorder's own channel list follows.
                let known = device.channelInfo ?? (1...max(1, device.channels)).map { ChannelInfo(number: $0, name: "Channel \($0)") }
                let start: ([ChannelInfo]) async -> Void = { [weak self] list in
                    guard let self, gen == self.generation else { return }
                    if Set(list.map(\.number)) == Set(self.channels.map(\.channel)) {
                        // Same channels, maybe new names: keep the streams running.
                        for ch in self.channels { ch.name = list.first { $0.number == ch.channel }?.name ?? ch.name }
                        return
                    }
                    for ch in self.channels { ch.stop() }
                    self.channels = list.map { ChannelSession(channel: $0.number, name: $0.name) }
                    let sessions = self.channels
                    let log: (String) -> Void = { [weak self] s in self?.logSink(s) }
                    await withTaskGroup(of: Void.self) { group in
                        for ch in sessions {
                            group.addTask { await ch.start(tunnel: t, user: device.username, password: password, substream: device.substream, log: log) }
                        }
                    }
                }
                await start(known)
                do {
                    // Ask the recorder which channels have a camera and what they are called.
                    let cgi = DeviceCGI(tunnel: t, user: device.username, password: password, log: { [weak self] s in self?.logSink(s) })
                    let found = try await withThrowingTimeout(12, what: "channel list") { try await cgi.channels() }
                    guard gen == generation else { return }
                    appendLog("recorder reports \(found.count) channels: \(found.map { "\($0.number) \($0.name)" }.joined(separator: ", "))")
                    if found != device.channelInfo {
                        var d = device
                        d.channelInfo = found
                        d.channels = found.count
                        store.update(d, password: nil)
                        selected = d
                        tunnelDevice = d
                    }
                    await start(found)
                } catch {
                    appendLog("channel list unavailable (\(error)); using \(known.count) channels")
                }
            } catch {
                connecting = false
                tunnelStatus = "failed: \(error)"
                appendLog("tunnel failed: \(error)")
            }
        }
    }

    /// Switches every channel between the main (HD) and sub (SD) stream and remembers it.
    func setHD(_ hd: Bool) {
        guard var d = selected, d.substream == hd else { return }
        d.substream = !hd
        store.update(d, password: nil)
        selected = d
        guard let t = tunnel, !t.isClosed else { return }
        tunnelDevice = d
        for ch in channels { ch.stop() }
        Task {
            let password = await Task.detached { [store] in store.password(for: d) }.value
            for ch in channels {
                await ch.start(tunnel: t, user: d.username, password: password, substream: d.substream, log: { [weak self] s in self?.logSink(s) })
            }
        }
    }

    private func tunnelDropped(_ reason: String) {
        tunnelStatus = "disconnected: \(reason)"
        for ch in channels { ch.stop() }
        tunnel = nil
    }

    func close() {
        generation += 1
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
