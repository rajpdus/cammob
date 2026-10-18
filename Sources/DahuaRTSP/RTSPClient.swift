import Foundation
import DahuaP2P

public enum VideoCodec: String, Sendable { case h264, h265 }

/// One access unit in Annex B form (start codes + NALs). Keyframes carry parameter sets.
public struct VideoFrame: Sendable {
    public var data: Data
    public var keyframe: Bool
    public var codec: VideoCodec
    /// RTP timestamp (90 kHz).
    public var timestamp: UInt32
}

public struct VideoTrack: Sendable {
    public var control: String
    public var payloadType: Int
    public var codec: VideoCodec
    public var paramSets: [Data]
    public var width: Int?
    public var height: Int?
}

public enum RTSPError: Error, CustomStringConvertible {
    case status(String, Int, String)
    case unauthorized
    case noVideoTrack
    case closed
    case timeout(String)
    case garbage

    public var description: String {
        switch self {
        case .status(let m, let c, let s): return "RTSP \(m): \(c) \(s)"
        case .unauthorized: return "RTSP: unauthorized (user/password)"
        case .noVideoTrack: return "no H.264/H.265 video track in the SDP"
        case .closed: return "RTSP connection closed"
        case .timeout(let m): return "RTSP \(m): timeout"
        case .garbage: return "garbage on the RTSP connection"
        }
    }
}

public enum SDP {
    public static func parseVideo(_ sdp: String) -> VideoTrack? {
        var inVideo = false
        var control = ""
        var payloadType = -1
        var codec: VideoCodec?
        var fmtp = ""
        for rawLine in sdp.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("m=") {
                if inVideo { break }
                inVideo = line.hasPrefix("m=video")
                if inVideo { payloadType = Int(line.split(separator: " ").dropFirst(3).first ?? "") ?? -1 }
                continue
            }
            guard inVideo else { continue }
            if line.hasPrefix("a=control:") { control = String(line.dropFirst(10)) }
            if line.hasPrefix("a=rtpmap:") {
                let rest = line.dropFirst(9)
                let parts = rest.split(separator: " ", maxSplits: 1)
                if parts.count == 2, Int(parts[0]) == payloadType {
                    let name = parts[1].split(separator: "/").first.map { $0.uppercased() } ?? ""
                    codec = name == "H264" ? .h264 : (name == "H265" || name == "HEVC") ? .h265 : nil
                }
            }
            if line.hasPrefix("a=fmtp:\(payloadType) ") { fmtp = String(line.dropFirst("a=fmtp:\(payloadType) ".count)) }
        }
        guard let c = codec else { return nil }
        var params: [String: String] = [:]
        for kv in fmtp.split(separator: ";") {
            if let i = kv.firstIndex(of: "=") {
                params[kv[..<i].trimmingCharacters(in: .whitespaces).lowercased()] = kv[kv.index(after: i)...].trimmingCharacters(in: .whitespaces)
            }
        }
        func b64(_ s: String?) -> [Data] { (s ?? "").split(separator: ",").compactMap { Data(base64Encoded: String($0)) } }
        let sets = c == .h264 ? b64(params["sprop-parameter-sets"])
            : b64(params["sprop-vps"]) + b64(params["sprop-sps"]) + b64(params["sprop-pps"])
        return VideoTrack(control: control, payloadType: payloadType, codec: c, paramSets: sets)
    }
}

/// RTP → access units. Drops a frame when a fragment of it went missing.
public final class RTPDepacketizer {
    private let track: VideoTrack
    private let onFrame: (VideoFrame) -> Void
    private var nals: [Data] = []
    private var fu: Data?
    private var timestamp: UInt32?
    private var lastSeq: UInt16?
    private var broken = false
    static let startCode = Data([0, 0, 0, 1])

    public init(track: VideoTrack, onFrame: @escaping (VideoFrame) -> Void) {
        self.track = track
        self.onFrame = onFrame
    }

    public func push(_ rtp: Data) {
        guard rtp.count >= 12, rtp[rtp.startIndex] >> 6 == 2 else { return }
        let b0 = rtp[rtp.startIndex], b1 = rtp[rtp.startIndex + 1]
        let csrc = Int(b0 & 0x0f)
        let hasExt = (b0 & 0x10) != 0
        let padding = (b0 & 0x20) != 0
        let marker = (b1 & 0x80) != 0
        let pt = Int(b1 & 0x7f)
        guard pt == track.payloadType else { return }
        let seq = rtp.u16(2)
        let ts = rtp.u32(4)
        var off = 12 + csrc * 4
        if hasExt, rtp.count >= off + 4 { off += 4 + Int(rtp.u16(off + 2)) * 4 }
        var end = rtp.count
        if padding { end -= Int(rtp[rtp.endIndex - 1]) }
        guard off < end else { return }
        let payload = rtp.subdata(in: (rtp.startIndex + off)..<(rtp.startIndex + end))

        if let last = lastSeq, last &+ 1 != seq { broken = true }
        lastSeq = seq
        if let t = timestamp, t != ts { flush() }
        timestamp = ts
        if track.codec == .h264 { h264(payload) } else { h265(payload) }
        if marker { flush() }
    }

    private func h264(_ p: Data) {
        let t = p[p.startIndex] & 0x1f
        if t >= 1 && t <= 23 { nals.append(p); return }
        if t == 24 { aggregated(p.dropFirst(1)); return }
        if t == 28, p.count > 2 {
            let fuh = p[p.startIndex + 1]
            if fuh & 0x80 != 0 {
                fu = Data([(p[p.startIndex] & 0xe0) | (fuh & 0x1f)])
            } else if fu == nil { broken = true; return }
            fu!.append(p.dropFirst(2))
            if fuh & 0x40 != 0 { nals.append(fu!); fu = nil }
        }
    }

    private func h265(_ p: Data) {
        guard p.count >= 3 else { return }
        let t = (p[p.startIndex] >> 1) & 0x3f
        if t == 48 { aggregated(p.dropFirst(2)); return }
        if t == 49 {
            let fuh = p[p.startIndex + 2]
            if fuh & 0x80 != 0 {
                fu = Data([(p[p.startIndex] & 0x81) | ((fuh & 0x3f) << 1), p[p.startIndex + 1]])
            } else if fu == nil { broken = true; return }
            fu!.append(p.dropFirst(3))
            if fuh & 0x40 != 0 { nals.append(fu!); fu = nil }
            return
        }
        nals.append(p)
    }

    private func aggregated(_ p: Data) {
        var i = p.startIndex
        while i + 2 <= p.endIndex {
            let size = Int(p.u16(i - p.startIndex))
            i += 2
            if i + size > p.endIndex { break }
            nals.append(p.subdata(in: i..<(i + size)))
            i += size
        }
    }

    private func nalType(_ n: Data) -> Int {
        track.codec == .h264 ? Int(n[n.startIndex] & 0x1f) : Int((n[n.startIndex] >> 1) & 0x3f)
    }

    private func flush() {
        let list = nals
        let wasBroken = broken || fu != nil
        nals = []; fu = nil; broken = false
        guard !list.isEmpty, !wasBroken else { return }
        let types = list.map(nalType)
        let key = types.contains { track.codec == .h264 ? $0 == 5 : ($0 >= 16 && $0 <= 21) }
        let hasParams = types.contains { track.codec == .h264 ? ($0 == 7 || $0 == 8) : ($0 >= 32 && $0 <= 34) }
        var out = Data()
        if key && !hasParams { for ps in track.paramSets { out.append(Self.startCode); out.append(ps) } }
        for n in list { out.append(Self.startCode); out.append(n) }
        onFrame(VideoFrame(data: out, keyframe: key, codec: track.codec, timestamp: timestamp ?? 0))
    }
}

/// Minimal RTSP client over a tunnel realm: video only, RTP interleaved on the
/// same connection, depacketized into Annex B access units.
public final class RTSPClient {
    public struct Options {
        public var url: String
        public var user: String?
        public var password: String?
        public var timeout: TimeInterval = 10
        public var log: ((String) -> Void)?
        public init(url: String, user: String? = nil, password: String? = nil) {
            self.url = url; self.user = user; self.password = password
        }
    }

    private struct Response { var code: Int; var status: String; var headers: [String: String]; var body: String }

    private let conn: RealmConnection
    private let o: Options
    private var buf = Data()
    private var cseq = 0
    private let lock = NSLock()
    private var pending: (cseq: Int, cont: CheckedContinuation<Response, Error>)?
    private var auth: (realm: String, nonce: String, basic: Bool)?
    private var sessionID = ""
    private var depacketizer: RTPDepacketizer?
    private var readTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private(set) public var closed = false
    public private(set) var track: VideoTrack?
    public var onFrame: ((VideoFrame) -> Void)?
    public var onClose: ((Error?) -> Void)?
    public private(set) var bytesIn = 0

    public init(connection: RealmConnection, options: Options) {
        self.conn = connection
        self.o = options
        readTask = Task { [weak self] in
            while let self, !self.closed {
                guard let d = await self.conn.read() else { self.finish(RTSPError.closed); return }
                self.onData(d)
            }
        }
    }

    /// DESCRIBE → SETUP (video, interleaved) → PLAY. Frames flow via `onFrame` right after.
    public func start() async throws -> VideoTrack {
        let desc = try await request("DESCRIBE", o.url, ["Accept": "application/sdp"])
        guard let track = SDP.parseVideo(desc.body) else { throw RTSPError.noVideoTrack }
        self.track = track
        let base = desc.headers["content-base"] ?? desc.headers["content-location"] ?? o.url
        let controlURL: String
        if track.control.lowercased().hasPrefix("rtsp://") { controlURL = track.control }
        else if !track.control.isEmpty, track.control != "*" { controlURL = (base.hasSuffix("/") ? base : base + "/") + track.control }
        else { controlURL = base }
        let setup = try await request("SETUP", controlURL, ["Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"])
        let sess = setup.headers["session"] ?? ""
        sessionID = String(sess.split(separator: ";").first ?? "")
        var timeout = 60.0
        if let r = sess.range(of: "timeout=") { timeout = Double(sess[r.upperBound...].prefix { $0.isNumber }) ?? 60 }
        depacketizer = RTPDepacketizer(track: track) { [weak self] f in self?.onFrame?(f) }
        _ = try await request("PLAY", base, ["Range": "npt=0.000-"])
        let interval = max(10, timeout / 2)
        keepaliveTask = Task { [weak self] in
            while let self, !self.closed {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                if self.closed { break }
                _ = try? await self.request("OPTIONS", self.o.url)
            }
        }
        return track
    }

    public func close() {
        if closed { return }
        if !sessionID.isEmpty { _ = send("TEARDOWN", o.url, [:]) }
        finish(nil)
        conn.close()
    }

    private func finish(_ err: Error?) {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        let p = pending
        pending = nil
        lock.unlock()
        keepaliveTask?.cancel()
        p?.cont.resume(throwing: err ?? RTSPError.closed)
        onClose?(err)
    }

    private func authorization(_ method: String, _ url: String) -> String? {
        guard let a = auth, let user = o.user else { return nil }
        let pass = o.password ?? ""
        if a.basic { return "Basic " + Data("\(user):\(pass)".utf8).base64EncodedString() }
        let ha1 = DeviceCrypto.md5Hex("\(user):\(a.realm):\(pass)")
        let ha2 = DeviceCrypto.md5Hex("\(method):\(url)")
        let response = DeviceCrypto.md5Hex("\(ha1):\(a.nonce):\(ha2)")
        return "Digest username=\"\(user)\", realm=\"\(a.realm)\", nonce=\"\(a.nonce)\", uri=\"\(url)\", response=\"\(response)\""
    }

    private func send(_ method: String, _ url: String, _ headers: [String: String]) -> Int {
        lock.lock(); cseq += 1; let n = cseq; lock.unlock()
        var req = "\(method) \(url) RTSP/1.0\r\nCSeq: \(n)\r\nUser-Agent: CamMob\r\n"
        if !sessionID.isEmpty { req += "Session: \(sessionID)\r\n" }
        if let a = authorization(method, url) { req += "Authorization: \(a)\r\n" }
        for (k, v) in headers { req += "\(k): \(v)\r\n" }
        o.log?("rtsp >>> \(method) \(url)")
        try? conn.write(Data((req + "\r\n").utf8))
        return n
    }

    private func request(_ method: String, _ url: String, _ headers: [String: String] = [:]) async throws -> Response {
        for attempt in 0..<2 {
            let res = try await exchange(method, url, headers)
            if res.code == 401, attempt == 0, o.user != nil {
                let h = res.headers["www-authenticate"] ?? ""
                func field(_ name: String) -> String {
                    guard let r = h.range(of: "\(name)=\"") else { return "" }
                    let rest = h[r.upperBound...]
                    return String(rest[..<(rest.firstIndex(of: "\"") ?? rest.endIndex)])
                }
                auth = (realm: field("realm"), nonce: field("nonce"), basic: h.lowercased().hasPrefix("basic"))
                continue
            }
            if res.code >= 300 { throw RTSPError.status(method, res.code, res.status) }
            return res
        }
        throw RTSPError.unauthorized
    }

    private func exchange(_ method: String, _ url: String, _ headers: [String: String]) async throws -> Response {
        if closed { throw RTSPError.closed }
        return try await withThrowingTaskGroup(of: Response.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { cont in
                    let n = self.send(method, url, headers)
                    self.lock.lock(); self.pending = (n, cont); self.lock.unlock()
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(self.o.timeout * 1_000_000_000))
                let p = self.lock.withLock { () -> (cseq: Int, cont: CheckedContinuation<Response, Error>)? in let p = self.pending; self.pending = nil; return p }
                p?.cont.resume(throwing: RTSPError.timeout(method))
                throw RTSPError.timeout(method)
            }
            let r = try await group.next()!
            group.cancelAll()
            return r
        }
    }

    private func onData(_ d: Data) {
        bytesIn += d.count
        buf.append(d)
        while !buf.isEmpty {
            if buf[buf.startIndex] == 0x24 {
                guard buf.count >= 4 else { return }
                let len = Int(buf.u16(2))
                guard buf.count >= 4 + len else { return }
                let channel = buf[buf.startIndex + 1]
                let packet = buf.subdata(in: (buf.startIndex + 4)..<(buf.startIndex + 4 + len))
                buf = buf.subdata(in: (buf.startIndex + 4 + len)..<buf.endIndex)
                if channel == 0 { depacketizer?.push(packet) }
                continue
            }
            guard let headEnd = buf.range(of: Data("\r\n\r\n".utf8)) else {
                if buf.count > 64 * 1024 { finish(RTSPError.garbage) }
                return
            }
            let head = String(decoding: buf[buf.startIndex..<headEnd.lowerBound], as: UTF8.self)
            guard head.hasPrefix("RTSP/") else {
                // Out of sync: resync on the next '$'.
                if let next = buf.dropFirst().firstIndex(of: 0x24) { buf = buf.subdata(in: next..<buf.endIndex) } else { buf = Data() }
                continue
            }
            let lines = head.components(separatedBy: "\r\n")
            let sp = lines[0].split(separator: " ", maxSplits: 2).map(String.init)
            var hdrs: [String: String] = [:]
            for line in lines.dropFirst() {
                if let i = line.firstIndex(of: ":") {
                    hdrs[line[..<i].trimmingCharacters(in: .whitespaces).lowercased()] = line[line.index(after: i)...].trimmingCharacters(in: .whitespaces)
                }
            }
            let len = Int(hdrs["content-length"] ?? "0") ?? 0
            let bodyStart = headEnd.upperBound
            guard buf.endIndex - bodyStart >= len else { return }
            let body = String(decoding: buf[bodyStart..<(bodyStart + len)], as: UTF8.self)
            buf = buf.subdata(in: (bodyStart + len)..<buf.endIndex)
            let res = Response(code: Int(sp.count > 1 ? sp[1] : "0") ?? 0, status: sp.count > 2 ? sp[2] : "", headers: hdrs, body: body)
            o.log?("rtsp <<< \(res.code) \(res.status)")
            lock.lock()
            if let p = pending, Int(hdrs["cseq"] ?? "") == p.cseq {
                pending = nil
                lock.unlock()
                p.cont.resume(returning: res)
            } else {
                lock.unlock()
            }
        }
    }
}
