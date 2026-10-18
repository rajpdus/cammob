import Foundation

/// Client identity presented to the Easy4ip cloud (WSSE UsernameToken). These
/// are the shared client credentials every official Dahua client uses; the
/// device password is never sent to the cloud.
/// How requests are serialized. Dahua's 2024+ cloud/firmware (DMSS 6.7.x
/// era) rejects the legacy SmartPSS shape with 403 DevPwd_* errors even when
/// the crypto is right, so the app dialect mirrors the DMSS/gCMOB client:
/// version headers, x-pcs-request-id, X-ToUType, random signed CSeq, local
/// time with numeric offset, and an extended p2p-channel body.
public struct Dialect: Sendable {
    public var app: Bool
    public var version = "6.7.15"
    public var sversion = "1.1.0"
    public var touType = "Client/Dmss_Android"
    public static let legacy = Dialect(app: false)
    public static let dmss = Dialect(app: true)
}

public struct CloudCredentials: Sendable {
    public var server: String
    public var username: String
    public var userKey: String
    public var dialect: Dialect = .legacy

    public var name: String { server.hasPrefix("instaon") ? "instaon" : "easy4ip" }

    public init(server: String, username: String, userKey: String, dialect: Dialect = .legacy) {
        self.server = server
        self.username = username
        self.userKey = userKey
        self.dialect = dialect
    }

    /// CP Plus "InstaOn" devices (gCMOB/iCMOB) register with CP Plus's own
    /// Easy4ip-protocol cloud. Values from gCMOB 3.4.1's encrypted properties
    /// (P2P_SERVER_OVERSEAS / P2P_PORT / P2P_AK_OVERSEA / P2P_SK_OVERSEA).
    public static let instaon = CloudCredentials(
        server: "instaonserver.com:8800",
        username: "89d61b61dc9a69fdcc03e4ff3a3be2f5",
        userKey: "993c7d7c95542c684c30ff9a9b831249",
        dialect: .dmss)

    public static let easy4ip = CloudCredentials(
        server: "www.easy4ipcloud.com:8800",
        username: "cba1b29e32cb17aa46b8ff9e73c7f40b",
        userKey: "996103384cdf19179e19243e959bbf8b")
}

/// A parsed DH-HTTP response. The XML body is flattened: `<body><US>x</US></body>` → `body/US`.
public struct DHResponse: Sendable {
    public var code: Int
    public var status: String
    public var headers: [String: String]
    public var body: [String: String]
    public var raw: String

    public var cseq: Int? { headers["CSeq"].flatMap { Int($0) } }
}

public enum DHHTTP {
    public static func flattenXML(_ xml: String) -> [String: String] {
        var out: [String: String] = [:]
        var stack: [String] = []
        var i = xml.startIndex
        while i < xml.endIndex {
            if xml[i] == "<" {
                guard let close = xml[i...].firstIndex(of: ">") else { break }
                let tag = xml[xml.index(after: i)..<close]
                i = xml.index(after: close)
                if tag.hasPrefix("?") || tag.hasPrefix("!") { continue }
                if tag.hasPrefix("/") { _ = stack.popLast(); continue }
                let selfClosing = tag.hasSuffix("/")
                let name = tag.split(whereSeparator: { $0 == " " || $0 == "/" }).first.map(String.init) ?? ""
                if !selfClosing { stack.append(name) }
            } else {
                let next = xml[i...].firstIndex(of: "<") ?? xml.endIndex
                let text = xml[i..<next].trimmingCharacters(in: .whitespacesAndNewlines)
                if !text.isEmpty, !stack.isEmpty { out[stack.joined(separator: "/")] = text }
                i = next
            }
        }
        return out
    }

    public static func parseResponse(_ raw: String) throws -> DHResponse {
        let normalized = raw.replacingOccurrences(of: "\r\n", with: "\n")
        let parts = normalized.components(separatedBy: "\n\n")
        let head = parts[0]
        let bodyText = parts.dropFirst().joined(separator: "\n\n")
        let lines = head.components(separatedBy: "\n")
        let statusParts = lines[0].split(separator: " ", maxSplits: 2).map(String.init)
        guard statusParts.count >= 2, let code = Int(statusParts[1]) else {
            throw P2PError.protocolError("bad DH status line: \(lines[0])")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            if let idx = line.firstIndex(of: ":") {
                headers[String(line[..<idx]).trimmingCharacters(in: .whitespaces)] =
                    String(line[line.index(after: idx)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        return DHResponse(code: code, status: statusParts.count > 2 ? statusParts[2] : "", headers: headers,
                          body: flattenXML(bodyText), raw: raw)
    }

    static func created(_ c: CloudCredentials) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        if c.dialect.app {
            f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssxxx"   // local time, numeric offset (+05:30)
            f.timeZone = TimeZone.current
        } else {
            f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
            f.timeZone = TimeZone(identifier: "UTC")
        }
        return f.string(from: Date())
    }

    static func wsseBlock(_ c: CloudCredentials) -> String {
        // The app draws a signed int32 nonce (negatives included).
        let nonce: Int = c.dialect.app ? Int(Int32(bitPattern: DeviceCrypto.randomNonce())) : Int(DeviceCrypto.randomNonce() & 0x7fff_ffff)
        let created = created(c)
        let digest = DeviceCrypto.sha1Base64("\(nonce)\(created)DHP2P:\(c.username):\(c.userKey)")
        return "Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"\(c.username)\", PasswordDigest=\"\(digest)\", Nonce=\"\(nonce)\", Created=\"\(created)\"\r\n"
    }

    public struct RequestOptions {
        public var pcsID: String? = nil   // x-pcs-request-id (p2p-channel)
        public var warmup = false         // stun-style probe: ToUType only, no auth
        public var auth = true
        public init() {}
    }

    public static func buildRequest(path: String, cseq: Int, body: String?, credentials c: CloudCredentials, options o: RequestOptions = RequestOptions()) -> Data {
        let method = body == nil ? "DHGET" : "DHPOST"
        var s = "\(method) \(path) HTTP/1.1\r\n"
        if c.dialect.app {
            if !o.warmup {
                s += "X-Version: \(c.dialect.version)\r\nX-Sversion: \(c.dialect.sversion)\r\n"
            }
            if let p = o.pcsID { s += "x-pcs-request-id: \(p)\r\n" }
            s += "X-ToUType: \(c.dialect.touType)\r\n"
            s += "CSeq: \(Int32(truncatingIfNeeded: cseq))\r\n"
            if o.auth && !o.warmup { s += wsseBlock(c) }
        } else {
            s += "CSeq: \(cseq)\r\n"
            if o.auth { s += wsseBlock(c) }
        }
        if let b = body { s += "Content-Type: \r\nContent-Length: \(b.utf8.count)\r\n" }
        s += "\r\n" + (body ?? "")
        return Data(s.utf8)
    }

    static func isResponse(_ d: Data) -> Bool {
        d.count > 9 && d.prefix(5) == Data("HTTP/".utf8)
    }
}

/// One UDP socket speaking DH-HTTP with several peers at once. Responses are
/// matched to waiters by sender and CSeq; everything else (PTCP, STUN) goes to
/// `onOther`, so the tunnel can share the socket the cloud saw us on.
public final class DHSocket {
    public let socket: UDPSocket
    public let credentials: CloudCredentials
    public var log: ((String) -> Void)?
    public var onOther: ((Data, Endpoint) -> Void)?

    private let q = DispatchQueue(label: "dahua.dhsocket")
    private var cseq = 0
    private struct Waiter {
        let id: Int
        let from: Endpoint
        let cseqs: Set<Int>?
        let cont: CheckedContinuation<DHResponse, Error>
    }
    private var waiters: [Waiter] = []
    private var early: [(from: Endpoint, res: DHResponse)] = []
    private var nextWaiterID = 0
    private var closed = false

    public init(credentials: CloudCredentials = .easy4ip, localPort: UInt16 = 0) throws {
        self.credentials = credentials
        socket = try UDPSocket(localPort: localPort)
        socket.onDatagram = { [weak self] data, ep in self?.receive(data, from: ep) }
        socket.start()
    }

    public var localPort: UInt16 { socket.localPort }

    private func receive(_ data: Data, from ep: Endpoint) {
        guard DHHTTP.isResponse(data) else {
            onOther?(data, ep)
            return
        }
        guard let res = try? DHHTTP.parseResponse(String(decoding: data, as: UTF8.self)) else { return }
        log?("<<< \(ep) \(res.code) \(res.status) \(res.body)")
        q.async {
            if let idx = self.waiters.firstIndex(where: { $0.from == ep && Self.matches($0.cseqs, res) }) {
                let w = self.waiters.remove(at: idx)
                w.cont.resume(returning: res)
            } else {
                self.early.append((ep, res))
                if self.early.count > 64 { self.early.removeFirst() }
            }
        }
    }

    private static func matches(_ cseqs: Set<Int>?, _ res: DHResponse) -> Bool {
        guard let cseqs, let c = res.cseq else { return true }
        return cseqs.contains(c)
    }

    public func send(_ data: Data, to ep: Endpoint) {
        try? socket.send(data, to: ep)
    }

    /// Sends a request and returns its CSeq without waiting.
    @discardableResult
    public func request(_ ep: Endpoint, _ path: String, body: String? = nil, options: DHHTTP.RequestOptions = DHHTTP.RequestOptions(), cseq: Int? = nil) -> Int {
        let n = cseq ?? q.sync { () -> Int in
            if credentials.dialect.app { return Int(Int32(bitPattern: DeviceCrypto.randomNonce())) }
            self.cseq += 1; return self.cseq
        }
        log?(">>> \(ep) \(body == nil ? "DHGET" : "DHPOST") \(path)\(body.map { " " + $0 } ?? "")")
        send(DHHTTP.buildRequest(path: path, cseq: n, body: body, credentials: credentials, options: options), to: ep)
        return n
    }

    /// Waits for the next response from `ep` (optionally for one of `cseqs`).
    public func read(_ ep: Endpoint, timeout: TimeInterval, cseqs: Set<Int>? = nil) async throws -> DHResponse {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<DHResponse, Error>) in
            q.async {
                if self.closed { cont.resume(throwing: P2PError.closed("socket")); return }
                if let idx = self.early.firstIndex(where: { $0.from == ep && Self.matches(cseqs, $0.res) }) {
                    cont.resume(returning: self.early.remove(at: idx).res)
                    return
                }
                self.nextWaiterID += 1
                let id = self.nextWaiterID
                self.waiters.append(Waiter(id: id, from: ep, cseqs: cseqs, cont: cont))
                self.q.asyncAfter(deadline: .now() + timeout) {
                    if let idx = self.waiters.firstIndex(where: { $0.id == id }) {
                        let w = self.waiters.remove(at: idx)
                        w.cont.resume(throwing: P2PError.timeout("waiting for \(ep)"))
                    }
                }
            }
        }
    }

    /// Waits for a final (>= 200) response, skipping provisional ones.
    public func readFinal(_ ep: Endpoint, timeout: TimeInterval, cseqs: Set<Int>? = nil) async throws -> DHResponse {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            let remaining = max(0.05, deadline.timeIntervalSinceNow)
            let res = try await read(ep, timeout: remaining, cseqs: cseqs)
            if res.code >= 200 { return res }
        }
    }

    /// Request + final response, retried on timeout. Throws on >= 300.
    public func call(_ ep: Endpoint, _ path: String, body: String? = nil, timeout: TimeInterval = 2.5, tries: Int = 3, options: DHHTTP.RequestOptions = DHHTTP.RequestOptions()) async throws -> DHResponse {
        var cseqs = Set<Int>()
        var lastError: Error = P2PError.timeout(path)
        for _ in 0..<tries {
            cseqs.insert(request(ep, path, body: body, options: options))
            do {
                let res = try await readFinal(ep, timeout: timeout, cseqs: cseqs)
                if res.code >= 300 { throw DHStatusError(path: path, code: res.code, status: res.status) }
                return res
            } catch let e as DHStatusError {
                throw e
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    public func close() {
        q.sync {
            closed = true
            for w in waiters { w.cont.resume(throwing: P2PError.closed("socket")) }
            waiters.removeAll()
        }
        socket.close()
    }
}

public struct DHStatusError: Error, CustomStringConvertible {
    public var path: String
    public var code: Int
    public var status: String
    public var description: String { "\(path): \(code) \(status)" }
}
