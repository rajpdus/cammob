import Foundation
import DahuaP2P

/// One video channel as the recorder reports it.
public struct ChannelInfo: Codable, Hashable, Sendable {
    /// 1-based channel number as used in RTSP URLs.
    public var number: Int
    public var name: String
    public init(number: Int, name: String) { self.number = number; self.name = name }
}

/// Minimal client for the recorder's HTTP CGI API over the tunnel (Digest auth, one
/// realm per request because the device answers with `Connection: close`).
public final class DeviceCGI {
    public struct Response { public var code: Int; public var headers: [String: String]; public var body: String }

    private let tunnel: Tunnel
    private let user: String
    private let password: String
    private let log: ((String) -> Void)?

    public init(tunnel: Tunnel, user: String, password: String, log: ((String) -> Void)? = nil) {
        self.tunnel = tunnel; self.user = user; self.password = password; self.log = log
    }

    /// The recorder answered with a non-200 status (the query is unsupported or refused).
    public struct HTTPStatusError: Error, CustomStringConvertible {
        public let code: Int
        public var description: String { "HTTP \(code)" }
    }

    /// GETs `/cgi-bin/<query>`, answering a Digest challenge once. A reply cut short by
    /// the tunnel (shorter than its Content-Length) or a timeout is retried.
    public func get(_ query: String) async throws -> String {
        let path = "/cgi-bin/" + query
        var lastError: Error = P2PError.timeout("http")
        for attempt in 1...3 {
            do {
                var r = try await fetch(path, authorization: nil)
                if r.code == 401, let challenge = r.headers["www-authenticate"] {
                    r = try await fetch(path, authorization: digest(challenge, method: "GET", uri: path))
                }
                guard r.code == 200 else { throw HTTPStatusError(code: r.code) }
                return r.body
            } catch let e as HTTPStatusError {
                throw e
            } catch {
                lastError = error
                log?("http \(query): \(error); attempt \(attempt) of 3")
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        throw lastError
    }

    /// Channels with a camera behind them, in channel order. Names come from the recorder.
    /// Throws when the recorder could not be read reliably, so a caller keeps its last
    /// known list instead of replacing it with a partial one.
    public func channels() async throws -> [ChannelInfo] {
        let titles = Self.parseChannelTitle((try? await get("configManager.cgi?action=getConfig&name=ChannelTitle")) ?? "")
        do {
            let bound = Self.parseCameraAll(try await get("LogicDeviceManager.cgi?action=getCameraAll"), titles: titles)
            if !bound.isEmpty { return bound }
        } catch is HTTPStatusError {
            // Recorders without a camera registry (analog DVRs): every titled channel is live.
        }
        if !titles.isEmpty { return titles }
        throw P2PError.protocolError("no channel list from device")
    }

    // MARK: parsing

    /// `table.ChannelTitle[i].Name=…` → every channel the recorder has, including empty slots.
    public static func parseChannelTitle(_ text: String) -> [ChannelInfo] {
        var out: [ChannelInfo] = []
        for line in text.split(whereSeparator: \.isNewline) {
            guard line.hasPrefix("table.ChannelTitle["), let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq]
            guard key.hasSuffix("].Name"), let open = key.firstIndex(of: "["), let close = key.firstIndex(of: "]"),
                  let i = Int(key[key.index(after: open)..<close]) else { continue }
            out.append(ChannelInfo(number: i + 1, name: String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)))
        }
        return out.sorted { $0.number < $1.number }
    }

    /// `camera[i].…` from LogicDeviceManager getCameraAll → enabled Local/Remote cameras.
    public static func parseCameraAll(_ text: String, titles: [ChannelInfo] = []) -> [ChannelInfo] {
        var entries: [Int: [String: String]] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            guard line.hasPrefix("camera["), let eq = line.firstIndex(of: "="),
                  let close = line.firstIndex(of: "]"), let i = Int(line[line.index(line.startIndex, offsetBy: 7)..<close]) else { continue }
            let key = String(line[line.index(close, offsetBy: 2)..<eq])
            entries[i, default: [:]][key] = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
        }
        var out: [ChannelInfo] = []
        for (_, e) in entries {
            guard e["Enable"] == "true", e["Type"] != "Compose", let ch = Int(e["UniqueChannel"] ?? "") else { continue }
            let title = titles.first { $0.number == ch + 1 }?.name ?? ""
            let name = !title.isEmpty ? title : (e["DeviceInfo.VideoInputs[0].Name"].flatMap { $0.isEmpty ? nil : $0 } ?? "Channel \(ch + 1)")
            out.append(ChannelInfo(number: ch + 1, name: name))
        }
        return out.sorted { $0.number < $1.number }
    }

    // MARK: HTTP

    private func fetch(_ path: String, authorization: String?) async throws -> Response {
        let conn = try await tunnel.connect(port: UInt32(tunnel.httpPort))
        defer { conn.close() }
        var req = "GET \(path) HTTP/1.1\r\nHost: device\r\nUser-Agent: CamMob\r\nConnection: close\r\n"
        if let a = authorization { req += "Authorization: \(a)\r\n" }
        req += "\r\n"
        log?("http >>> GET \(path)")
        try conn.write(Data(req.utf8))
        var raw = Data()
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            guard let chunk = try await withThrowingTimeout(max(0.1, deadline.timeIntervalSinceNow), what: "http read", { await conn.read() }) else { break }
            raw.append(chunk)
            if let r = Self.parse(raw), r.headers["content-length"].flatMap(Int.init).map({ r.body.utf8.count >= $0 }) ?? false { return r }
        }
        guard let r = Self.parse(raw) else { throw P2PError.protocolError("bad HTTP response") }
        if let want = r.headers["content-length"].flatMap(Int.init), r.body.utf8.count < want {
            throw P2PError.protocolError("reply cut short (\(r.body.utf8.count) of \(want) bytes)")
        }
        log?("http <<< \(r.code) \(r.body.utf8.count) B")
        return r
    }

    static func parse(_ raw: Data) -> Response? {
        guard let sep = raw.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: raw[..<sep.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let status = lines.removeFirst().split(separator: " ")
        guard status.count >= 2, let code = Int(status[1]) else { return nil }
        var headers: [String: String] = [:]
        for l in lines {
            guard let c = l.firstIndex(of: ":") else { continue }
            headers[l[..<c].lowercased()] = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
        }
        return Response(code: code, headers: headers, body: String(decoding: raw[sep.upperBound...], as: UTF8.self))
    }

    /// RFC 2617 Digest with qop=auth (the recorder's HTTP server always asks for it).
    func digest(_ challenge: String, method: String, uri: String) -> String {
        var p: [String: String] = [:]
        let body = challenge.hasPrefix("Digest ") ? String(challenge.dropFirst(7)) : challenge
        for part in body.split(separator: ",") {
            guard let eq = part.firstIndex(of: "=") else { continue }
            let k = part[..<eq].trimmingCharacters(in: .whitespaces)
            p[k] = part[part.index(after: eq)...].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        }
        let realm = p["realm"] ?? "", nonce = p["nonce"] ?? ""
        let ha1 = DeviceCrypto.md5Hex("\(user):\(realm):\(password)")
        let ha2 = DeviceCrypto.md5Hex("\(method):\(uri)")
        var fields = "username=\"\(user)\", realm=\"\(realm)\", nonce=\"\(nonce)\", uri=\"\(uri)\""
        let response: String
        if (p["qop"] ?? "").contains("auth") {
            let cnonce = DeviceCrypto.randomBytes(8).map { String(format: "%02x", $0) }.joined()
            response = DeviceCrypto.md5Hex("\(ha1):\(nonce):00000001:\(cnonce):auth:\(ha2)")
            fields += ", qop=auth, nc=00000001, cnonce=\"\(cnonce)\""
        } else {
            response = DeviceCrypto.md5Hex("\(ha1):\(nonce):\(ha2)")
        }
        if let o = p["opaque"] { fields += ", opaque=\"\(o)\"" }
        return "Digest " + fields + ", response=\"\(response)\""
    }
}
