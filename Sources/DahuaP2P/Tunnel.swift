import Foundation

/// A TCP connection to one port on the device, carried as a PTCP "realm".
public final class RealmConnection {
    public let id: UInt32
    public let remotePort: UInt32
    private weak var tunnel: Tunnel?
    private let lock = NSLock()
    private var buffer = Data()
    private var waiter: CheckedContinuation<Data?, Never>?
    private var eof = false
    public private(set) var bytesIn = 0

    init(id: UInt32, remotePort: UInt32, tunnel: Tunnel) {
        self.id = id
        self.remotePort = remotePort
        self.tunnel = tunnel
    }

    /// Returns the next chunk of received bytes, or nil at EOF.
    public func read() async -> Data? {
        await withCheckedContinuation { cont in
            lock.lock()
            if !buffer.isEmpty {
                let d = buffer; buffer = Data(); lock.unlock(); cont.resume(returning: d); return
            }
            if eof { lock.unlock(); cont.resume(returning: nil); return }
            waiter = cont
            lock.unlock()
        }
    }

    public func write(_ data: Data) throws {
        guard let t = tunnel, !t.isClosed else { throw P2PError.closed("tunnel") }
        lock.lock(); let closed = eof; lock.unlock()
        if closed { throw P2PError.closed("realm") }
        t.session.sendData(realm: id, data)
    }

    public func close() {
        tunnel?.disconnect(self)
        remoteClosed()
    }

    public var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return eof }

    func push(_ data: Data) {
        lock.lock()
        bytesIn += data.count
        if let w = waiter {
            waiter = nil
            lock.unlock()
            w.resume(returning: data)
            return
        }
        buffer.append(data)
        lock.unlock()
    }

    func remoteClosed() {
        lock.lock()
        if eof { lock.unlock(); return }
        eof = true
        let w = waiter
        waiter = nil
        let pending = buffer
        buffer = Data()
        lock.unlock()
        if let w { w.resume(returning: pending.isEmpty ? nil : pending) }
    }
}

/// A PTCP tunnel to a Dahua device: TCP connections to the device's own ports
/// (RTSP 554, HTTP 80, 37777…) carried as realms over one PTCP session.
public final class Tunnel {
    public struct Options {
        public var serial: String
        public var username: String?
        public var password: String?
        public var mode: TransportMode = .relay
        /// Clouds to try in order; a device unknown to one is looked up in the next.
        public var clouds: [CloudCredentials] = [.instaon, .easy4ip]
        public var timeout: TimeInterval = 8
        /// Keep retrying while the device is busy (it holds a closed relay
        /// session for ~15–20 s) for up to this long. 0 = single attempt.
        public var busyRetry: TimeInterval = 35
        public var log: ((String) -> Void)?

        public init(serial: String, username: String? = nil, password: String? = nil) {
            self.serial = serial
            self.username = username
            self.password = password
        }
    }

    public let session: PTCPSession
    public let handshake: HandshakeResult
    private let sock: DHSocket
    private let log: ((String) -> Void)?
    private let lock = NSLock()
    private var realms: [UInt32: RealmConnection] = [:]
    private var pendingBinds: [UInt32: CheckedContinuation<Bool, Never>] = [:]
    private var pendingDiscs: [UInt32: CheckedContinuation<Void, Never>] = [:]
    private let gate = AsyncGate()
    private(set) public var closeReason: String?
    public var onClosed: ((String) -> Void)?

    static let bindTimeout: TimeInterval = 8
    static let busyRetryWait: TimeInterval = 4
    static let discTimeout: TimeInterval = 2

    private init(sock: DHSocket, handshake: HandshakeResult, log: ((String) -> Void)?) {
        self.sock = sock
        self.handshake = handshake
        self.session = handshake.session
        self.log = log
        session.onBody = { [weak self] b in self?.onBody(b) }
        session.onClosed = { [weak self] r in self?.close(r) }
    }

    public static func open(_ opts: Options) async throws -> Tunnel {
        let deadline = Date().addingTimeInterval(opts.busyRetry)
        var attempt = 0
        var cloudIndex = 0
        while true {
            attempt += 1
            let cloud = opts.clouds[cloudIndex]
            let sock = try DHSocket(credentials: cloud)
            sock.log = opts.log
            do {
                var h = HandshakeOptions(serial: opts.serial, username: opts.username, password: opts.password)
                h.mode = opts.mode
                h.cloud = cloud
                h.timeout = opts.timeout
                opts.log?("looking up \(opts.serial) on \(cloud.name) (\(cloud.server))")
                let hs = try await Handshake.run(sock, h, log: opts.log)
                return Tunnel(sock: sock, handshake: hs, log: opts.log)
            } catch {
                sock.close()
                if case P2PError.deviceOffline = error, cloudIndex + 1 < opts.clouds.count {
                    opts.log?("not registered on \(cloud.name), trying the next cloud")
                    cloudIndex += 1
                    continue
                }
                guard case P2PError.deviceBusy = error, Date().addingTimeInterval(Tunnel.busyRetryWait) < deadline else { throw error }
                opts.log?("device busy (attempt \(attempt)), retrying in \(Int(Tunnel.busyRetryWait)) s")
                try await Task.sleep(nanoseconds: UInt64(Tunnel.busyRetryWait * 1_000_000_000))
            }
        }
    }

    public var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closeReason != nil }
    public var rtspPort: Int { handshake.info?.rtspport ?? 554 }
    public var privatePort: Int { handshake.info?.privport ?? 37777 }
    public var httpPort: Int { handshake.info?.httpport ?? 80 }
    public var stats: (udpIn: Int, udpOut: Int, ptcp: PTCPSession.Stats) { (sock.socket.bytesIn, sock.socket.bytesOut, session.stats) }

    /// Opens a TCP connection to `port` on the device. Binds are serialized:
    /// the device handles one realm negotiation at a time.
    public func connect(port: UInt32) async throws -> RealmConnection {
        try await gate.run {
            if self.isClosed { throw P2PError.closed("tunnel (\(self.closeReason ?? ""))") }
            let id = UInt32.random(in: 1..<0x7fff_ffff)
            let realm = RealmConnection(id: id, remotePort: port, tunnel: self)
            self.lock.withLock { self.realms[id] = realm }
            let ok: Bool = await withCheckedContinuation { cont in
                self.lock.withLock { self.pendingBinds[id] = cont }
                self.session.send(PTCP.bindBody(realm: id, port: port))
                DispatchQueue.global().asyncAfter(deadline: .now() + Tunnel.bindTimeout) {
                    self.lock.lock()
                    let c = self.pendingBinds.removeValue(forKey: id)
                    self.lock.unlock()
                    c?.resume(returning: false)
                }
            }
            if !ok {
                self.lock.withLock { self.realms[id] = nil }
                throw P2PError.timeout("device refused or ignored the connection to port \(port)")
            }
            self.log?("realm \(String(id, radix: 16)) connected to device port \(port)")
            return realm
        }
    }

    func disconnect(_ realm: RealmConnection) {
        lock.lock()
        guard realms.removeValue(forKey: realm.id) != nil, closeReason == nil else { lock.unlock(); return }
        lock.unlock()
        session.send(PTCP.statusBody(realm: realm.id, "DISC"))
        // Hold the gate briefly so the device can release the realm before the next bind.
        let id = realm.id
        Task {
            try? await gate.run {
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    self.lock.withLock { self.pendingDiscs[id] = cont }
                    DispatchQueue.global().asyncAfter(deadline: .now() + Tunnel.discTimeout) {
                        self.lock.lock()
                        let c = self.pendingDiscs.removeValue(forKey: id)
                        self.lock.unlock()
                        c?.resume()
                    }
                }
            }
        }
    }

    private func onBody(_ b: PTCP.Body) {
        switch b {
        case .data(let realmID, let data):
            lock.lock(); let r = realms[realmID]; lock.unlock()
            r?.push(data)
        case .status(let realmID, let status):
            if status == "CONN" {
                lock.lock(); let c = pendingBinds.removeValue(forKey: realmID); lock.unlock()
                c?.resume(returning: true)
            } else if status == "DISC" {
                log?("realm \(String(realmID, radix: 16)) DISC from device")
                lock.lock()
                let bind = pendingBinds.removeValue(forKey: realmID)
                let disc = pendingDiscs.removeValue(forKey: realmID)
                let r = realms.removeValue(forKey: realmID)
                lock.unlock()
                bind?.resume(returning: false)
                disc?.resume()
                r?.remoteClosed()
            }
        case .command(let code, let payload, _):
            log?("ptcp command 0x\(String(code, radix: 16)) (\(payload.count) B)")
        default:
            break
        }
    }

    public func close(_ reason: String = "closed") {
        lock.lock()
        if closeReason != nil { lock.unlock(); return }
        closeReason = reason
        let rs = Array(realms.values)
        realms.removeAll()
        let binds = Array(pendingBinds.values); pendingBinds.removeAll()
        let discs = Array(pendingDiscs.values); pendingDiscs.removeAll()
        lock.unlock()
        for r in rs { r.remoteClosed() }
        for b in binds { b.resume(returning: false) }
        for d in discs { d.resume() }
        if !session.isClosed { session.close(reason) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { self.sock.close() }
        onClosed?(reason)
    }
}

/// Serializes async work: each `run` waits for the previous one to finish.
actor AsyncGate {
    private var tail: Task<Void, Never>?

    func run<T>(_ body: @escaping @Sendable () async throws -> T) async throws -> T {
        let previous = tail
        let task = Task<T, Error> {
            await previous?.value
            return try await body()
        }
        tail = Task { _ = try? await task.value }
        return try await task.value
    }
}
