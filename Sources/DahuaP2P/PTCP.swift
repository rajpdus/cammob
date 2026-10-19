import Foundation

/// PTCP ("phony TCP"): Dahua's reliable byte stream over UDP.
///
/// Header (24 bytes): "PTCP" | sent | recv | pid | lmid | rmid (u32 big-endian).
/// `sent` is the byte offset of this datagram's body in the sender's stream,
/// `recv` the cumulative ACK of the other direction. An empty body is a pure ACK.
/// Body: type(1) | length(3) | realm(4) | padding(4) | data.
public enum PTCP {
    public static let headerSize = 24
    public static let maxData = 1280

    public enum BodyType {
        public static let sync: UInt8 = 0x00
        public static let data: UInt8 = 0x10
        public static let bind: UInt8 = 0x11
        public static let status: UInt8 = 0x12
        public static let heartbeat: UInt8 = 0x13
        public static let signRequest: UInt8 = 0x17
        public static let sign: UInt8 = 0x18
        public static let auth: UInt8 = 0x19
        public static let authAck: UInt8 = 0x1a
        public static let authFin: UInt8 = 0x1b
    }

    public struct Packet {
        public var sent: UInt32
        public var recv: UInt32
        public var pid: UInt32
        public var lmid: UInt32
        public var rmid: UInt32
        public var body: Data

        public func encode() -> Data {
            var d = Data(capacity: PTCP.headerSize + body.count)
            d.append(contentsOf: [0x50, 0x54, 0x43, 0x50])
            d.appendU32(sent); d.appendU32(recv); d.appendU32(pid); d.appendU32(lmid); d.appendU32(rmid)
            d.append(body)
            return d
        }

        public static func decode(_ d: Data) -> Packet? {
            guard d.count >= PTCP.headerSize, d.prefix(4) == Data([0x50, 0x54, 0x43, 0x50]) else { return nil }
            return Packet(sent: d.u32(4), recv: d.u32(8), pid: d.u32(12), lmid: d.u32(16), rmid: d.u32(20),
                          body: d.count > PTCP.headerSize ? d.subdata(in: PTCP.headerSize..<d.count) : Data())
        }
    }

    public enum Body {
        case sync
        case data(realm: UInt32, data: Data)
        case bind(realm: UInt32, port: UInt32)
        case status(realm: UInt32, status: String)
        case heartbeat
        case command(code: UInt8, payload: Data, raw: Data)
    }

    static func typeHeader(_ type: UInt8, len: Int, realm: UInt32) -> Data {
        var d = Data(capacity: 12)
        d.appendU32((UInt32(type) << 24) | (UInt32(len) & 0xffffff))
        d.appendU32(realm)
        d.appendU32(0)
        return d
    }

    /// Body types whose 12-byte header carries the payload length.
    static let framedTypes: Set<UInt8> = [BodyType.data, BodyType.bind, BodyType.status, BodyType.heartbeat]
    public static func syncBody() -> Data { Data([0x00, 0x03, 0x01, 0x00]) }
    public static func heartbeatBody() -> Data { typeHeader(BodyType.heartbeat, len: 0, realm: 0) }
    public static func dataBody(realm: UInt32, _ data: Data) -> Data {
        var d = typeHeader(BodyType.data, len: data.count, realm: realm); d.append(data); return d
    }
    public static func bindBody(realm: UInt32, port: UInt32) -> Data {
        var d = typeHeader(BodyType.bind, len: 8, realm: realm)
        d.appendU32(port)
        d.append(contentsOf: [0x7f, 0x00, 0x00, 0x01])
        return d
    }
    public static func statusBody(realm: UInt32, _ status: String) -> Data {
        var d = typeHeader(BodyType.status, len: status.utf8.count, realm: realm); d.append(Data(status.utf8)); return d
    }
    /// Handshake commands (0x17–0x1B): 12-byte header with the type, then payload.
    public static func commandBody(_ type: UInt8, payload: Data = Data()) -> Data {
        var d = typeHeader(type, len: 0, realm: 0); d.append(payload); return d
    }

    public static func parseBody(_ b: Data) -> Body {
        guard let code = b.first else { return .command(code: 0xff, payload: Data(), raw: b) }
        if code == BodyType.sync { return .sync }
        if b.count < 12 { return .command(code: code, payload: b.count > 4 ? b.subdata(in: 4..<b.count) : Data(), raw: b) }
        let realm = b.u32(4)
        switch code {
        case BodyType.data:
            let len = Int(b.u32(0) & 0xffffff)
            let end = min(b.count, 12 + len)
            return .data(realm: realm, data: b.subdata(in: 12..<end))
        case BodyType.bind:
            return .bind(realm: realm, port: b.count >= 16 ? b.u32(12) : 0)
        case BodyType.status:
            let s = String(decoding: b.subdata(in: 12..<b.count), as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: "\0"))
            return .status(realm: realm, status: s)
        case BodyType.heartbeat:
            return .heartbeat
        default:
            return .command(code: code, payload: b.subdata(in: 12..<b.count), raw: b)
        }
    }

    /// a comes after b in 32-bit wrap-around space.
    @inline(__always) static func seqAfter(_ a: UInt32, _ b: UInt32) -> Bool {
        let d = a &- b
        return d != 0 && d < 0x8000_0000
    }
}

public extension Data {
    mutating func appendU32(_ v: UInt32) {
        var be = v.bigEndian
        Swift.withUnsafeBytes(of: &be) { append(contentsOf: $0) }
    }
    func u32(_ offset: Int) -> UInt32 {
        let i = startIndex + offset
        return UInt32(self[i]) << 24 | UInt32(self[i + 1]) << 16 | UInt32(self[i + 2]) << 8 | UInt32(self[i + 3])
    }
    func u16(_ offset: Int) -> UInt16 {
        let i = startIndex + offset
        return UInt16(self[i]) << 8 | UInt16(self[i + 1])
    }
}

/// Reliable, ordered PTCP stream with one peer. Through the relay datagrams get
/// lost and reordered, so the receiver only advances `recv` over contiguous
/// bytes, parks early datagrams until the gap is filled, never delivers a byte
/// twice, and retransmits its own bodies until the peer acknowledges them.
public final class PTCPSession {
    public struct Options {
        public var ackDelay: TimeInterval = 0.02
        public var heartbeat: TimeInterval = 5
        public var rto: TimeInterval = 0.5
        public var maxRetries = 8
        public var idleTimeout: TimeInterval = 60
        public var stallTimeout: TimeInterval = 20
        public init() {}
    }

    public struct Stats {
        public var datagramsIn = 0, datagramsOut = 0, retransmitsOut = 0, duplicatesIn = 0, outOfOrderIn = 0, gapsFilled = 0
    }

    private struct Outstanding {
        let offset: UInt32
        let body: Data
        let pid: UInt32
        var lastSentAt: Date
        var tries: Int
    }

    public let queue = DispatchQueue(label: "dahua.ptcp")
    private let transmit: (Data) -> Void
    private let o: Options
    public var log: ((String) -> Void)?
    public var onBody: ((PTCP.Body) -> Void)?
    public var onClosed: ((String) -> Void)?
    public var heartbeats = true

    private var sndNext: UInt32 = 0
    private var sndUna: UInt32 = 0
    private var count: UInt32 = 0
    private var lmid: UInt32
    private var outstanding: [Outstanding] = []
    private var rcvNext: UInt32 = 0
    private var early: [UInt32: Data] = [:]
    private var inbox = Data()
    /// Set PTCP_TRACE=1 to log every received packet.
    static let trace = ProcessInfo.processInfo.environment["PTCP_TRACE"] != nil
    private var lastPeerLmid: UInt32 = 0
    private var ackPending = false
    private var timer: DispatchSourceTimer?
    private var lastHeardAt = Date()
    private var lastHeartbeatAt = Date()
    private var lastAckProgressAt = Date()
    private(set) var closedReason: String?
    public private(set) var stats = Stats()

    public init(options: Options = Options(), transmit: @escaping (Data) -> Void) {
        self.o = options
        self.transmit = transmit
        self.lmid = UInt32.random(in: 1..<0x7fff_ffff)
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 0.1, repeating: 0.1)
        t.setEventHandler { [weak self] in self?.tick() }
        timer = t
        t.resume()
    }

    public var isClosed: Bool { queue.sync { closedReason != nil } }
    public var unacked: UInt32 { queue.sync { sndNext &- sndUna } }

    // MARK: output

    /// Queues a body for reliable delivery (callable from any thread).
    public func send(_ body: Data) {
        queue.async { self.sendLocked(body) }
    }

    public func sendData(realm: UInt32, _ data: Data) {
        queue.async {
            var i = data.startIndex
            while i < data.endIndex {
                let end = min(i + PTCP.maxData, data.endIndex)
                self.sendLocked(PTCP.dataBody(realm: realm, data[i..<end]))
                i = end
            }
        }
    }

    private func sendLocked(_ body: Data) {
        if closedReason != nil { return }
        let isSync = body.count == 4 && body[body.startIndex] == PTCP.BodyType.sync
        let pid: UInt32 = isSync ? 0x0002_ffff : (0xffff - (count & 0xffff))
        if !isSync { count &+= 1 }
        if outstanding.isEmpty { lastAckProgressAt = Date() }
        let o = Outstanding(offset: sndNext, body: body, pid: pid, lastSentAt: Date(), tries: 0)
        outstanding.append(o)
        sndNext &+= UInt32(body.count)
        transmitBody(offset: o.offset, pid: pid, body: body)
    }

    private func transmitBody(offset: UInt32, pid: UInt32, body: Data) {
        ackPending = false
        stats.datagramsOut += 1
        let p = PTCP.Packet(sent: offset, recv: rcvNext, pid: pid, lmid: lmid, rmid: lastPeerLmid, body: body)
        lmid &+= 1
        transmit(p.encode())
    }

    private func sendAck() {
        ackPending = false
        if closedReason != nil { return }
        stats.datagramsOut += 1
        let p = PTCP.Packet(sent: sndNext, recv: rcvNext, pid: 0xffff - (count & 0xffff), lmid: lmid, rmid: lastPeerLmid, body: Data())
        lmid &+= 1
        transmit(p.encode())
    }

    private func scheduleAck(immediate: Bool = false) {
        if immediate { sendAck(); return }
        if ackPending { return }
        ackPending = true
        queue.asyncAfter(deadline: .now() + o.ackDelay) { [weak self] in
            guard let self, self.ackPending else { return }
            self.sendAck()
        }
    }

    // MARK: input

    /// Feeds one datagram from the peer (any thread). Returns false if it was not PTCP.
    @discardableResult
    public func input(_ datagram: Data) -> Bool {
        guard let p = PTCP.Packet.decode(datagram) else { return false }
        queue.async { self.inputLocked(p) }
        return true
    }

    private func inputLocked(_ p: PTCP.Packet) {
        if closedReason != nil { return }
        stats.datagramsIn += 1
        if PTCPSession.trace, !p.body.isEmpty {
            log?("ptcp in sent=\(p.sent) recv=\(p.recv) len=\(p.body.count) type=0x\(String(p.body[p.body.startIndex], radix: 16)) rcvNext=\(rcvNext)")
        }
        lastHeardAt = Date()
        lastPeerLmid = p.lmid
        onPeerAck(p.recv)
        if p.body.isEmpty { return }
        let len = UInt32(p.body.count)
        if p.sent == rcvNext {
            accept(p.body)
            while let next = early.removeValue(forKey: rcvNext) {
                stats.gapsFilled += 1
                accept(next)
            }
            scheduleAck(immediate: !early.isEmpty)
        } else if PTCP.seqAfter(p.sent, rcvNext) {
            if early[p.sent] == nil {
                stats.outOfOrderIn += 1
                if early.count < 4096 { early[p.sent] = p.body }
            } else {
                stats.duplicatesIn += 1
            }
            scheduleAck(immediate: true)
        } else {
            let end = p.sent &+ len
            if PTCP.seqAfter(end, rcvNext) {
                let skip = Int(rcvNext &- p.sent)
                accept(p.body.subdata(in: (p.body.startIndex + skip)..<p.body.endIndex))
            } else {
                stats.duplicatesIn += 1
            }
            scheduleAck(immediate: true)
        }
    }

    /// The peer numbers bytes, not bodies: a retransmitted datagram may bundle several
    /// bodies or start mid-body, so received bytes are reassembled as a stream and
    /// framed by each body's own length header.
    private func accept(_ bytes: Data) {
        rcvNext &+= UInt32(bytes.count)
        inbox.append(bytes)
        while !inbox.isEmpty {
            let type = inbox[inbox.startIndex]
            guard PTCP.framedTypes.contains(type) else {
                // SYNC and handshake commands carry no usable length; one per datagram.
                let b = inbox; inbox = Data(); onBody?(PTCP.parseBody(b)); return
            }
            guard inbox.count >= 12 else { return }
            let total = 12 + Int(inbox.u32(0) & 0xffffff)
            guard inbox.count >= total else { return }
            let b = inbox.subdata(in: inbox.startIndex..<(inbox.startIndex + total))
            inbox = inbox.subdata(in: (inbox.startIndex + total)..<inbox.endIndex)
            onBody?(PTCP.parseBody(b))
        }
    }

    private func onPeerAck(_ ack: UInt32) {
        guard PTCP.seqAfter(ack, sndUna), !PTCP.seqAfter(ack, sndNext) else { return }
        sndUna = ack
        lastAckProgressAt = Date()
        while let first = outstanding.first {
            let end = first.offset &+ UInt32(first.body.count)
            if PTCP.seqAfter(end, ack) { break }
            outstanding.removeFirst()
        }
    }

    // MARK: timers

    private func tick() {
        if closedReason != nil { return }
        let now = Date()
        for i in outstanding.indices {
            let rto = o.rto * pow(2.0, Double(outstanding[i].tries))
            if now.timeIntervalSince(outstanding[i].lastSentAt) < rto { break }
            if outstanding[i].tries >= o.maxRetries { closeLocked("peer stopped acknowledging"); return }
            outstanding[i].tries += 1
            outstanding[i].lastSentAt = now
            stats.retransmitsOut += 1
            log?("ptcp: retransmit offset \(outstanding[i].offset) (\(outstanding[i].body.count) B, try \(outstanding[i].tries))")
            transmitBody(offset: outstanding[i].offset, pid: outstanding[i].pid, body: outstanding[i].body)
        }
        if !outstanding.isEmpty, now.timeIntervalSince(lastAckProgressAt) > o.stallTimeout { closeLocked("stalled"); return }
        if now.timeIntervalSince(lastHeardAt) > o.idleTimeout { closeLocked("peer silent"); return }
        if heartbeats, now.timeIntervalSince(lastHeartbeatAt) >= o.heartbeat {
            lastHeartbeatAt = now
            sendLocked(PTCP.heartbeatBody())
        }
    }

    public func close(_ reason: String = "closed") {
        queue.async { self.closeLocked(reason) }
    }

    private func closeLocked(_ reason: String) {
        if closedReason != nil { return }
        closedReason = reason
        timer?.cancel()
        timer = nil
        log?("ptcp: session closed (\(reason))")
        onClosed?(reason)
    }
}
