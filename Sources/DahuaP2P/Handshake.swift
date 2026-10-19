import Foundation

/// How the PTCP path to the device is established.
public enum TransportMode: String, Sendable, CaseIterable {
    /// Through Dahua's relay agent. Works behind carrier-grade NAT / 4G.
    case relay
    /// UDP hole punch straight to the device (needs a punchable NAT on both ends).
    case direct
}

public struct HandshakeOptions: Sendable {
    public var serial: String
    public var username: String?
    public var password: String?
    public var mode: TransportMode = .relay
    public var cloud: CloudCredentials = .easy4ip
    public var timeout: TimeInterval = 8
    public var joinTimeout: TimeInterval = 3
    /// Representative device port advertised in ClientId (app dialect).
    public var forwardPort: Int = 554
    /// App dialect: try a UDP hole punch before settling on the relay agent.
    public var allowPunch: Bool = true

    public init(serial: String, username: String? = nil, password: String? = nil) {
        self.serial = serial
        self.username = username
        self.password = password
    }
}

public struct HandshakeResult {
    /// Where PTCP datagrams go: the relay agent, or the device itself.
    public var peer: Endpoint
    public var session: PTCPSession
    public var info: DeviceCrypto.DeviceInfo?
    public var devicePublicAddr: String?
    public var deviceLocalAddr: String?
    public var mode: TransportMode
    public var timings: [String: TimeInterval]
}

/// Easy4ip handshake: locate the device by serial and get a PTCP path to it.
///
///   main   /probe/p2psrv, /online/p2psrv/{SN} → P2P server, /online/relay → relay
///   p2psrv /probe/device/{SN}, /info/device/{SN} (randsalt, ports)
///   main   /device/{SN}/p2p-channel          (answered later with the device's addresses)
///   relay  /relay/agent → token + agent;  agent /relay/start/{token}
///   main   /device/{SN}/relay-channel        (device is told to join the agent)
///   relay: PTCP SYNC via agent ⇄ device SYNC
///   direct: sign from agent (0x17), STUN-like punch to the device, SYNC, 0x19/0x1A/0x1B
public enum Handshake {
    public static func run(_ sock: DHSocket, _ opts: HandshakeOptions, log: ((String) -> Void)? = nil) async throws -> HandshakeResult {
        let t0 = Date()
        var timings: [String: TimeInterval] = [:]
        func mark(_ k: String) { timings[k] = Date().timeIntervalSince(t0) }
        let serial = opts.serial

        let main = try Endpoint.resolve(opts.cloud.server)
        let app = opts.cloud.dialect.app
        if app {
            var w = DHHTTP.RequestOptions(); w.warmup = true; w.auth = false
            _ = try? await sock.call(main, "/online/stun", timeout: 2, tries: 1, options: w)
        } else {
            _ = try await sock.call(main, "/probe/p2psrv")
        }
        let online: DHResponse
        do {
            online = try await sock.call(main, "/online/p2psrv/\(serial)")
        } catch let e as DHStatusError where e.code == 404 {
            throw P2PError.deviceOffline(serial)
        }
        guard let us = online.body["body/US"] else { throw P2PError.deviceOffline(serial) }
        let relayRes = try await sock.call(main, "/online/relay")
        guard let relayAddr = relayRes.body["body/Address"] else { throw P2PError.protocolError("cloud returned no relay server") }
        mark("cloud")
        log?("p2p server \(us), relay \(relayAddr)")

        let p2psrv = try Endpoint.resolve(us)
        do {
            _ = try await sock.call(p2psrv, "/probe/device/\(serial)")
        } catch let e as DHStatusError where e.code == 404 {
            throw P2PError.deviceOffline(serial)
        }
        var info: DeviceCrypto.DeviceInfo?
        do {
            let res = try await sock.call(p2psrv, "/info/device/\(serial)", timeout: 2, tries: 1)
            if let enc = res.body["body/Info"] { info = try DeviceCrypto.decryptDeviceInfo(enc) }
        } catch {
            log?("device info unavailable: \(error)")
        }
        mark("p2psrv")
        log?("device info randsalt=\(info?.randsalt != nil) rtsp=\(info?.rtspport ?? 0) priv=\(info?.privport ?? 0)")

        // Channel request (answered by the main server once the device has replied).
        let cid = DeviceCrypto.randomBytes(8)
        let identify = cid.map { String(format: app ? "%02x" : "%x", $0) }.joined(separator: " ")
        // The app lists every local IPv4 and ends with "<bindIP>:<port>".
        let ips = LocalNetwork.ipv4Addresses()
        let bindIP = ips.first ?? "127.0.0.1"
        let localAddr = app ? (ips.dropFirst().joined(separator: ",") + (ips.count > 1 ? "," : bindIP + ",") + "\(bindIP):\(sock.localPort)")
                            : "127.0.0.1:\(sock.localPort)"
        let pcsID = DeviceCrypto.randomBytes(16).map { String(format: "%02x", $0) }.joined()
        let clientID = DeviceCrypto.randomBytes(16).map { String(format: "%02x", $0) }.joined() + ":\(opts.forwardPort)"
        let appTail = "<NatValueT>0</NatValueT><version>\(opts.cloud.dialect.version)</version><sVersion>\(opts.cloud.dialect.sversion)</sVersion>"
        let appEnd = "<Pid>0</Pid><ClientId>\(clientID)</ClientId>"
        var deviceKey: Data?
        var nonce: UInt32 = 0
        let randsalt = info?.randsalt ?? ""
        let needsAuth = !(opts.username ?? "").isEmpty && !(opts.password ?? "").isEmpty && !randsalt.isEmpty
        let channelBody: String
        if needsAuth {
            let key = DeviceCrypto.deviceKey(user: opts.username!, password: opts.password!, randsalt: randsalt)
            deviceKey = key
            nonce = DeviceCrypto.randomNonce()
            let encAddr = try DeviceCrypto.encryptAddr(key: key, nonce: nonce, localAddr)
            let auth = DeviceCrypto.deviceAuthXML(user: opts.username!, key: key, nonce: nonce, randsalt: randsalt, payload: encAddr)
            channelBody = app
                ? "<body>\(auth)<Identify>\(identify)</Identify><IpEncrptV2>true</IpEncrptV2>\(appTail)<LocalAddr>\(encAddr)</LocalAddr>\(appEnd)</body>"
                : "<body>\(auth)<Identify>\(identify)</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>\(encAddr)</LocalAddr><version>5.0.0</version></body>"
        } else {
            channelBody = app
                ? "<body><Identify>\(identify)</Identify><IpEncrpt>true</IpEncrpt>\(appTail)<LocalAddr>\(localAddr)</LocalAddr>\(appEnd)</body>"
                : "<body><Identify>\(identify)</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>\(localAddr)</LocalAddr><version>5.0.0</version></body>"
        }
        var chOpts = DHHTTP.RequestOptions()
        if app { chOpts.pcsID = pcsID }
        let channelCseq = sock.request(main, "/device/\(serial)/p2p-channel", body: channelBody, options: chOpts)

        // Relay agent.
        let relay = try Endpoint.resolve(relayAddr)
        let agentRes = try await sock.call(relay, "/relay/agent")
        guard let token = agentRes.body["body/Token"], let agentAddr = agentRes.body["body/Agent"] else {
            throw P2PError.protocolError("relay returned no agent")
        }
        let agent = try Endpoint.resolve(agentAddr)
        _ = try await sock.call(agent, "/relay/start/\(token)", body: "<body><Client>:0</Client></body>")
        mark("agent")

        let channel = try await sock.readFinal(main, timeout: opts.timeout, cseqs: [channelCseq])
        if channel.code == 403 { throw needsAuth ? P2PError.authFailed("device rejected the user/password") : P2PError.authRequired }
        if channel.code >= 300 { throw P2PError.protocolError("p2p-channel: \(channel.code) \(channel.status)") }
        var deviceLocal = channel.body["body/LocalAddr"]
        let devicePub = channel.body["body/PubAddr"]
        let respNonce = channel.body["body/Nonce"].flatMap { UInt32($0) } ?? 0
        if needsAuth, let key = deviceKey, let enc = deviceLocal, respNonce != 0 {
            let dec = try? DeviceCrypto.decryptAddr(key: key, nonce: respNonce, enc)
            // Only trust a clean "a.b.c.d:port"; the device uses another IV for this field on some firmware.
            deviceLocal = dec.flatMap { d in (try? Endpoint.resolve(d)) != nil && d.allSatisfy({ $0.isNumber || $0 == "." || $0 == ":" }) ? d : nil }
        }
        mark("channel")
        log?("device pub=\(devicePub ?? "-") local=\(deviceLocal ?? "-")")

        // Authorize the agent for this device.
        var relayBody = "<body><agentAddr>\(agentAddr)</agentAddr></body>"
        if needsAuth, let key = deviceKey {
            // A fresh nonce: reusing the channel nonce draws 403 DevPwd_InvalidNonce on 6.7.x firmware.
            let auth = DeviceCrypto.deviceAuthXML(user: opts.username!, key: key, nonce: DeviceCrypto.randomNonce(), randsalt: randsalt, payload: "")
            relayBody = "<body>\(auth)<agentAddr>\(agentAddr)</agentAddr></body>"
        }
        sock.request(main, "/device/\(serial)/relay-channel", body: relayBody)
        // The agent confirms the device joined within ~100 ms, or never (device busy).
        do {
            _ = try await sock.readFinal(agent, timeout: opts.joinTimeout)
        } catch {
            throw P2PError.deviceBusy
        }
        mark("relay-channel")

        switch opts.mode {
        case .relay:
            let session = PTCPSession { [weak sock] d in sock?.send(d, to: agent) }
            session.log = log
            sock.onOther = { [weak session] msg, from in
                if from == agent { session?.input(msg) }
            }
            try await waitForSync(session, timeout: opts.timeout, what: "through the relay")
            mark("sync")
            if app, let pub = devicePub, opts.allowPunch {
                // App-parity data path: STUN punch to the device, then SYNC only (no token auth).
                if let direct = try? await appPunch(sock, cid: cid, pub: pub, local: deviceLocal, timeout: 4, log: log) {
                    session.close("switched to direct channel")
                    mark("punch")
                    log?("direct punched channel to \(direct.peer) (app dialect)")
                    return HandshakeResult(peer: direct.peer, session: direct.session, info: info, devicePublicAddr: devicePub,
                                           deviceLocalAddr: deviceLocal, mode: .direct, timings: timings)
                }
                log?("direct punch failed, staying on the relay agent")
            }
            log?("relay handshake done in \(Int(timings["sync"]! * 1000)) ms via agent \(agentAddr)")
            return HandshakeResult(peer: agent, session: session, info: info, devicePublicAddr: devicePub,
                                   deviceLocalAddr: deviceLocal, mode: .relay, timings: timings)

        case .direct:
            guard let pub = devicePub else { throw P2PError.protocolError("no device public address") }
            // Sign from the agent over a throwaway PTCP session.
            let agentSession = PTCPSession { [weak sock] d in sock?.send(d, to: agent) }
            agentSession.heartbeats = false
            var signCont: CheckedContinuation<Data, Error>?
            let signLock = NSLock()
            agentSession.onBody = { body in
                if case .command(let code, let payload, _) = body, code == PTCP.BodyType.sign || (code != PTCP.BodyType.sync && !payload.isEmpty) {
                    signLock.lock(); let c = signCont; signCont = nil; signLock.unlock()
                    c?.resume(returning: payload)
                }
            }
            sock.onOther = { [weak agentSession] msg, from in
                if from == agent { agentSession?.input(msg) }
            }
            try await waitForSync(agentSession, timeout: opts.timeout, what: "from the agent")
            let sign: Data = try await withThrowingTimeout(opts.timeout, what: "sign from agent") {
                try await withCheckedThrowingContinuation { cont in
                    signLock.lock(); signCont = cont; signLock.unlock()
                    agentSession.send(PTCP.commandBody(PTCP.BodyType.signRequest))
                }
            }
            agentSession.close("sign obtained")
            mark("sign")
            log?("got sign (\(sign.count) B)")

            let result = try await directPunch(sock, cid: cid, pub: pub, local: deviceLocal, sign: sign, opts: opts, log: log)
            mark("sync")
            return HandshakeResult(peer: result.peer, session: result.session, info: info, devicePublicAddr: devicePub,
                                   deviceLocalAddr: deviceLocal, mode: .direct, timings: timings)
        }
    }

    static func waitForSync(_ session: PTCPSession, timeout: TimeInterval, what: String) async throws {
        try await withThrowingTimeout(timeout, what: "device did not answer PTCP SYNC \(what)") {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let lock = NSLock()
                var done = false
                let prev = session.onBody
                session.onBody = { body in
                    if case .sync = body {
                        lock.lock(); let d = done; done = true; lock.unlock()
                        if !d { session.onBody = prev; cont.resume() }
                    } else {
                        prev?(body)
                    }
                }
                session.send(PTCP.syncBody())
            }
        }
    }

    /// STUN-like hole punch and PTCP authentication straight to the device.
    static func directPunch(_ sock: DHSocket, cid: Data, pub: String, local: String?, sign: Data,
                            opts: HandshakeOptions, log: ((String) -> Void)?) async throws -> (peer: Endpoint, session: PTCPSession) {
        let pubEP = try Endpoint.resolve(pub)
        let localEP = local.flatMap { try? Endpoint.resolve($0) }
        let inverted = Data(cid.map { ~$0 })
        let cookie = DeviceCrypto.randomBytes(4)
        let transID = DeviceCrypto.randomBytes(12)
        var req = Data([0xff, 0xfe, 0xff, 0xe7])
        req.append(cookie); req.append(transID)
        req.append(contentsOf: [0x7f, 0xd5, 0xff, 0xf7])
        req.append(inverted)
        req.append(contentsOf: [0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe])
        var addr = Data([UInt8(pubEP.port >> 8), UInt8(pubEP.port & 0xff)])
        addr.append(contentsOf: pubEP.host.split(separator: ".").map { UInt8($0) ?? 0 })
        req.append(Data(addr.map { ~$0 }))

        var lastError: Error = P2PError.timeout("direct punch")
        for attempt in 1...3 {
            log?("direct punch attempt \(attempt) to \(pubEP)\(localEP.map { " and \($0)" } ?? "")")
            let raw = RawWaiter(sock: sock)
            sock.send(req, to: pubEP)
            if let l = localEP, l != pubEP { sock.send(req, to: l) }
            do {
                let (resp, from) = try await raw.next(timeout: 8) { from in from == pubEP || (localEP != nil && from == localEP!) }
                guard resp.count >= 20 else { throw P2PError.protocolError("short STUN reply") }
                let peer = from
                var confirm = Data([0xfe, 0xfe, 0xff, 0xf3])
                confirm.append(cookie)
                confirm.append(resp.subdata(in: 8..<20))
                confirm.append(contentsOf: [0x7f, 0xd6, 0xff, 0xf7])
                confirm.append(inverted)
                sock.send(confirm, to: peer)
                // Drain the rest of the STUN exchange (~250 ms).
                try? await Task.sleep(nanoseconds: 300_000_000)
                raw.stop()

                let session = PTCPSession { [weak sock] d in sock?.send(d, to: peer) }
                session.log = log
                var authAck: CheckedContinuation<Void, Error>?
                let lock = NSLock()
                session.onBody = { body in
                    if case .command(let code, _, _) = body, code == PTCP.BodyType.authAck {
                        lock.lock(); let c = authAck; authAck = nil; lock.unlock()
                        c?.resume()
                    }
                }
                sock.onOther = { [weak session] msg, f in if f == peer { session?.input(msg) } }
                try await waitForSync(session, timeout: opts.timeout, what: "directly")
                try await withThrowingTimeout(opts.timeout, what: "device did not acknowledge auth") {
                    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                        lock.lock(); authAck = cont; lock.unlock()
                        session.send(PTCP.commandBody(PTCP.BodyType.auth, payload: sign))
                    }
                }
                session.send(PTCP.commandBody(PTCP.BodyType.authFin))
                log?("direct PTCP session established with \(peer)")
                return (peer, session)
            } catch {
                raw.stop()
                lastError = error
                log?("direct attempt \(attempt) failed: \(error)")
            }
        }
        throw lastError
    }
}

extension Handshake {
    /// DMSS-era punch: STUN init to pub+local, confirm, drain, then PTCP SYNC only.
    static func appPunch(_ sock: DHSocket, cid: Data, pub: String, local: String?, timeout: TimeInterval,
                         log: ((String) -> Void)?) async throws -> (peer: Endpoint, session: PTCPSession) {
        let pubEP = try Endpoint.resolve(pub)
        let localEP = local.flatMap { try? Endpoint.resolve($0) }
        let inverted = Data(cid.map { ~$0 })
        let cookie = DeviceCrypto.randomBytes(4)
        let transID = DeviceCrypto.randomBytes(12)
        var req = Data([0xff, 0xfe, 0xff, 0xe7])
        req.append(cookie); req.append(transID)
        req.append(contentsOf: [0x7f, 0xd5, 0xff, 0xf7])
        req.append(inverted)
        req.append(contentsOf: [0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe])
        var addr = Data([UInt8(pubEP.port >> 8), UInt8(pubEP.port & 0xff)])
        addr.append(contentsOf: pubEP.host.split(separator: ".").map { UInt8($0) ?? 0 })
        req.append(Data(addr.map { ~$0 }))

        let raw = RawWaiter(sock: sock)
        defer { raw.stop() }
        log?("STUN punch to \(pubEP)\(localEP.map { " and \($0)" } ?? "")")
        let deadline = Date().addingTimeInterval(timeout)
        var sent = 0
        var reply: (Data, Endpoint)?
        while Date() < deadline, reply == nil {
            if sent < 3 {
                sock.send(req, to: pubEP)
                if let l = localEP, l != pubEP { sock.send(req, to: l) }
                sent += 1
            }
            if let (d, from) = try? await raw.next(timeout: 1.3, where: { from in from == pubEP || (localEP != nil && from == localEP!) }) {
                guard d.count >= 20 else { continue }
                let magic = Array(d.prefix(4))
                if magic == [0xfe, 0xfe, 0xff, 0xe7] {
                    reply = (d, from)
                } else if magic == [0xff, 0xfe, 0xff, 0xe7], d.count >= 40 {
                    // Device-initiated cross STUN: answer it.
                    var resp = Data([0xfe, 0xfe, 0xff, 0xe7])
                    resp.append(d.subdata(in: 4..<8)); resp.append(d.subdata(in: 8..<20))
                    resp.append(contentsOf: [0x7f, 0xd6, 0xff, 0xf7]); resp.append(inverted)
                    resp.append(contentsOf: [0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]); resp.append(d.subdata(in: 34..<40))
                    sock.send(resp, to: from)
                    log?("answered device cross-STUN from \(from)")
                }
            }
        }
        guard let (_, peer) = reply else { log?("no STUN reply after \(sent) attempts"); throw P2PError.timeout("STUN punch") }
        log?("STUN response from \(peer)")
        var confirm = Data([0xfe, 0xfe, 0xff, 0xf3])
        confirm.append(cookie); confirm.append(transID)
        confirm.append(contentsOf: [0x7f, 0xd6, 0xff, 0xf7]); confirm.append(inverted)
        for _ in 0..<5 { sock.send(confirm, to: peer) }
        try? await Task.sleep(nanoseconds: 300_000_000)
        raw.stop()

        let session = PTCPSession { [weak sock] d in sock?.send(d, to: peer) }
        session.log = log
        let fallback = sock.onOther
        sock.onOther = { [weak session] msg, f in if f == peer { session?.input(msg) } else { fallback?(msg, f) } }
        do {
            try await waitForSync(session, timeout: 3, what: "on the punched channel")
        } catch {
            session.close("punch sync failed")
            sock.onOther = fallback
            throw error
        }
        return (peer, session)
    }
}

/// Collects raw (non DH-HTTP) datagrams from chosen senders for the STUN
/// exchange; everything else keeps flowing to the previous handler.
final class RawWaiter {
    private let sock: DHSocket
    private let lock = NSLock()
    private var cont: CheckedContinuation<(Data, Endpoint), Error>?
    private var filter: ((Endpoint) -> Bool)?
    private var generation = 0
    private let previous: ((Data, Endpoint) -> Void)?

    init(sock: DHSocket) {
        self.sock = sock
        self.previous = sock.onOther
        sock.onOther = { [weak self] d, ep in self?.deliver(d, ep) }
    }

    private func deliver(_ d: Data, _ ep: Endpoint) {
        lock.lock()
        if let f = filter, f(ep), let c = cont {
            cont = nil
            lock.unlock()
            c.resume(returning: (d, ep))
            return
        }
        lock.unlock()
        previous?(d, ep)
    }

    func next(timeout: TimeInterval, where f: @escaping (Endpoint) -> Bool) async throws -> (Data, Endpoint) {
        try await withCheckedThrowingContinuation { c in
            lock.lock()
            generation += 1
            let gen = generation
            cont = c
            filter = f
            lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self else { return }
                self.lock.lock()
                guard self.generation == gen, let pending = self.cont else { self.lock.unlock(); return }
                self.cont = nil
                self.lock.unlock()
                pending.resume(throwing: P2PError.timeout("waiting for device STUN reply"))
            }
        }
    }

    /// Restores the previous datagram handler and fails any pending wait.
    func stop() {
        lock.lock()
        let c = cont
        cont = nil
        generation += 1
        lock.unlock()
        sock.onOther = previous
        c?.resume(throwing: P2PError.closed("raw waiter"))
    }
}

/// Runs `body` with a deadline. On timeout the body's task is cancelled and
/// `P2PError.timeout(what)` is thrown.
public func withThrowingTimeout<T: Sendable>(_ seconds: TimeInterval, what: String, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw P2PError.timeout(what)
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}
