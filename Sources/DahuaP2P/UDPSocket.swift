import Foundation

/// An IPv4 UDP endpoint. `host` is always a dotted-quad address.
public struct Endpoint: Hashable, CustomStringConvertible, Sendable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var description: String { "\(host):\(port)" }

    /// Parses "host:port" and resolves the host to an IPv4 address.
    public static func resolve(_ address: String) throws -> Endpoint {
        guard let colon = address.lastIndex(of: ":") else { throw P2PError.invalidAddress(address) }
        let host = String(address[..<colon])
        guard let port = UInt16(address[address.index(after: colon)...]), port > 0 else {
            throw P2PError.invalidAddress(address)
        }
        if host.isEmpty { throw P2PError.invalidAddress(address) }
        if host.split(separator: ".").count == 4, host.allSatisfy({ $0.isNumber || $0 == "." }) {
            return Endpoint(host: host, port: port)
        }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, nil, &hints, &res)
        guard rc == 0, let info = res else { throw P2PError.dnsFailed(host) }
        defer { freeaddrinfo(res) }
        var addr = sockaddr_in()
        memcpy(&addr, info.pointee.ai_addr, Int(MemoryLayout<sockaddr_in>.size))
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var sin = addr.sin_addr
        inet_ntop(AF_INET, &sin, &buf, socklen_t(INET_ADDRSTRLEN))
        return Endpoint(host: String(cString: buf), port: port)
    }

    func sockaddr() -> sockaddr_in {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &sa.sin_addr)
        return sa
    }
}

public enum P2PError: Error, CustomStringConvertible {
    case invalidAddress(String)
    case dnsFailed(String)
    case socket(String)
    case timeout(String)
    case protocolError(String)
    case deviceOffline(String)
    case deviceBusy
    case authRequired
    case authFailed(String)
    case closed(String)

    public var description: String {
        switch self {
        case .invalidAddress(let a): return "invalid address \(a)"
        case .dnsFailed(let h): return "DNS lookup failed for \(h)"
        case .socket(let s): return "socket error: \(s)"
        case .timeout(let s): return "timeout: \(s)"
        case .protocolError(let s): return "protocol error: \(s)"
        case .deviceOffline(let s): return "device \(s) is not online in the cloud"
        case .deviceBusy: return "device did not join the relay (busy with another session?)"
        case .authRequired: return "device requires channel authentication (user/password)"
        case .authFailed(let s): return "authentication failed: \(s)"
        case .closed(let s): return "closed: \(s)"
        }
    }
}

/// A bound IPv4 UDP socket that delivers every datagram, with its sender, to a
/// callback on a private reader thread. One socket serves the whole handshake
/// and the tunnel: the cloud learns our NAT mapping from the port we bound.
public final class UDPSocket {
    private let fd: Int32
    public let localPort: UInt16
    private let readerQueue = DispatchQueue(label: "dahua.udp.reader", qos: .userInitiated)
    private var closedFlag = false
    private let lock = NSLock()
    public var onDatagram: ((Data, Endpoint) -> Void)?
    public private(set) var bytesIn: Int = 0
    public private(set) var bytesOut: Int = 0

    public init(localPort: UInt16 = 0) throws {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw P2PError.socket("socket(): \(String(cString: strerror(errno)))") }
        var rcv: Int32 = 4 * 1024 * 1024
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, socklen_t(MemoryLayout<Int32>.size))
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = localPort.bigEndian
        sa.sin_addr.s_addr = INADDR_ANY
        let rc = withUnsafePointer(to: &sa) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else {
            Darwin.close(fd)
            throw P2PError.socket("bind(): \(String(cString: strerror(errno)))")
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) }
        }
        self.fd = fd
        self.localPort = UInt16(bigEndian: bound.sin_port)
    }

    public func start() {
        readerQueue.async { [weak self] in self?.readLoop() }
    }

    private func readLoop() {
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &fromLen) }
            }
            if n < 0 {
                if errno == EINTR { continue }
                return
            }
            lock.lock(); let closed = closedFlag; bytesIn += n + 28; lock.unlock()
            if closed { return }
            var cbuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sin = from.sin_addr
            inet_ntop(AF_INET, &sin, &cbuf, socklen_t(INET_ADDRSTRLEN))
            let ep = Endpoint(host: String(cString: cbuf), port: UInt16(bigEndian: from.sin_port))
            onDatagram?(Data(buf[0..<n]), ep)
        }
    }

    public func send(_ data: Data, to ep: Endpoint) throws {
        var sa = ep.sockaddr()
        let n = data.withUnsafeBytes { raw -> Int in
            withUnsafePointer(to: &sa) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, data.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if n < 0 { throw P2PError.socket("sendto(): \(String(cString: strerror(errno)))") }
        lock.lock(); bytesOut += n + 28; lock.unlock()
    }

    public func close() {
        lock.lock()
        if closedFlag { lock.unlock(); return }
        closedFlag = true
        lock.unlock()
        shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)
    }

    deinit { close() }
}


public enum LocalNetwork {
    /// Non-loopback IPv4 addresses of this host, primary interface first.
    public static func ipv4Addresses() -> [String] {
        var out: [String] = []
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return out }
        defer { freeifaddrs(ifap) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let i = p {
            if let sa = i.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET), (i.pointee.ifa_flags & UInt32(IFF_UP)) != 0, (i.pointee.ifa_flags & UInt32(IFF_LOOPBACK)) == 0 {
                var sin = sockaddr_in()
                memcpy(&sin, sa, MemoryLayout<sockaddr_in>.size)
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                var a = sin.sin_addr
                inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
                let s = String(cString: buf)
                if !s.hasPrefix("169.254."), !out.contains(s) {
                    let name = String(cString: i.pointee.ifa_name)
                    if name == "en0" { out.insert(s, at: 0) } else { out.append(s) }
                }
            }
            p = i.pointee.ifa_next
        }
        return out
    }
}
