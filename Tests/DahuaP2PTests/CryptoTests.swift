import XCTest
@testable import DahuaP2P
@testable import DahuaRTSP

final class CryptoTests: XCTestCase {
    func testDeviceKeyIsUppercaseMD5() {
        let key = DeviceCrypto.deviceKey(user: "admin", password: "hunter2", randsalt: "abc123")
        let expected = DeviceCrypto.md5Hex("admin:Login to abc123:hunter2").uppercased()
        XCTAssertEqual(String(decoding: key, as: UTF8.self), expected)
        XCTAssertEqual(key.count, 32)
    }

    func testPBKDF2KnownVectors() {
        // RFC 7914 vectors for PBKDF2-HMAC-SHA256("password", "salt", iter, 32)
        let one = DeviceCrypto.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 1, length: 32)
        XCTAssertEqual(one.map { String(format: "%02x", $0) }.joined(), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        let two = DeviceCrypto.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 2, length: 32)
        XCTAssertEqual(two.map { String(format: "%02x", $0) }.joined(), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    func testAddrRoundTrip() throws {
        let key = DeviceCrypto.deviceKey(user: "admin", password: "password", randsalt: "SALT1")
        let ct = try DeviceCrypto.encryptAddr(key: key, nonce: 12345, "127.0.0.1:49300")
        XCTAssertNotEqual(ct, "127.0.0.1:49300")
        XCTAssertEqual(try DeviceCrypto.decryptAddr(key: key, nonce: 12345, ct), "127.0.0.1:49300")
        XCTAssertNotEqual(try DeviceCrypto.decryptAddr(key: key, nonce: 12346, ct), "127.0.0.1:49300")
    }

    func testDeviceInfoRoundTrip() throws {
        let json = Data(#"{"httpport":80,"privport":37777,"randsalt":"abcd","rtspport":554,"tlsprivport":0}"#.utf8)
        let enc = try DeviceCrypto.aesOFB(key: DeviceCrypto.deviceInfoKey, iv: DeviceCrypto.deviceInfoIV, data: json)
        let info = try DeviceCrypto.decryptDeviceInfo(enc.base64EncodedString())
        XCTAssertEqual(info.randsalt, "abcd")
        XCTAssertEqual(info.rtspport, 554)
    }

    func testWSSEDigest() {
        // SHA1 base64 of nonce+created+"DHP2P:user:key" matches the official client format.
        let d = DeviceCrypto.sha1Base64("1" + "2020-01-01T00:00:00Z" + "DHP2P:u:k")
        XCTAssertEqual(d.count, 28)
    }
}

final class DHHTTPTests: XCTestCase {
    func testParseResponse() throws {
        let raw = "HTTP/1.1 200 OK\r\nCSeq: 3\r\nContent-Length: 40\r\n\r\n<body><US>1.2.3.4:8803</US><Address>5.6.7.8:9000</Address></body>"
        let r = try DHHTTP.parseResponse(raw)
        XCTAssertEqual(r.code, 200)
        XCTAssertEqual(r.cseq, 3)
        XCTAssertEqual(r.body["body/US"], "1.2.3.4:8803")
        XCTAssertEqual(r.body["body/Address"], "5.6.7.8:9000")
    }

    func testParseLFOnly() throws {
        let r = try DHHTTP.parseResponse("HTTP/1.1 100 Continue\nCSeq: 1\n\n")
        XCTAssertEqual(r.code, 100)
    }

    func testRequestFormat() {
        let d = DHHTTP.buildRequest(path: "/probe/p2psrv", cseq: 1, body: nil, credentials: .easy4ip)
        let s = String(decoding: d, as: UTF8.self)
        XCTAssertTrue(s.hasPrefix("DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\""))
        XCTAssertTrue(s.hasSuffix("\r\n\r\n"))
    }
}

final class PTCPTests: XCTestCase {
    func testPacketRoundTrip() {
        let p = PTCP.Packet(sent: 1, recv: 2, pid: 0xffff, lmid: 4, rmid: 5, body: PTCP.syncBody())
        let d = p.encode()
        XCTAssertEqual(d.count, 28)
        XCTAssertEqual(d.prefix(4), Data("PTCP".utf8))
        let q = PTCP.Packet.decode(d)!
        XCTAssertEqual(q.sent, 1); XCTAssertEqual(q.recv, 2); XCTAssertEqual(q.pid, 0xffff); XCTAssertEqual(q.lmid, 4); XCTAssertEqual(q.rmid, 5)
        if case .sync = PTCP.parseBody(q.body) {} else { XCTFail("expected sync") }
    }

    func testBodies() {
        let bind = PTCP.bindBody(realm: 0x11223344, port: 554)
        XCTAssertEqual(bind.count, 20)
        XCTAssertEqual(Array(bind.prefix(4)), [0x11, 0, 0, 8])
        if case .bind(let realm, let port) = PTCP.parseBody(bind) { XCTAssertEqual(realm, 0x11223344); XCTAssertEqual(port, 554) } else { XCTFail() }
        let data = PTCP.dataBody(realm: 7, Data([1, 2, 3]))
        XCTAssertEqual(Array(data.prefix(4)), [0x10, 0, 0, 3])
        if case .data(let realm, let d) = PTCP.parseBody(data) { XCTAssertEqual(realm, 7); XCTAssertEqual(d, Data([1, 2, 3])) } else { XCTFail() }
        if case .status(let realm, let s) = PTCP.parseBody(PTCP.statusBody(realm: 9, "CONN")) { XCTAssertEqual(realm, 9); XCTAssertEqual(s, "CONN") } else { XCTFail() }
        if case .heartbeat = PTCP.parseBody(PTCP.heartbeatBody()) {} else { XCTFail() }
        if case .command(let code, let payload, _) = PTCP.parseBody(PTCP.commandBody(0x19, payload: Data([9, 9]))) { XCTAssertEqual(code, 0x19); XCTAssertEqual(payload, Data([9, 9])) } else { XCTFail() }
    }

    /// Two sessions wired back to back through a lossy, reordering link must
    /// still deliver every body in order.
    func testReliableDeliveryOverLossyLink() {
        var a: PTCPSession!
        var b: PTCPSession!
        let lock = NSLock()
        var dropNext = 0
        var delayed: [Data] = []
        func link(_ to: @escaping () -> PTCPSession?) -> (Data) -> Void {
            return { d in
                lock.lock()
                dropNext += 1
                let drop = dropNext % 5 == 0
                let hold = dropNext % 7 == 0
                lock.unlock()
                if drop { return }
                if hold { lock.lock(); delayed.append(d); lock.unlock(); return }
                let target = to()
                DispatchQueue.global().async { target?.input(d) }
                lock.lock(); let flush = delayed; delayed.removeAll(); lock.unlock()
                for x in flush { DispatchQueue.global().async { target?.input(x) } }
            }
        }
        var opts = PTCPSession.Options(); opts.rto = 0.1; opts.heartbeat = 100
        a = PTCPSession(options: opts, transmit: link { b })
        b = PTCPSession(options: opts, transmit: link { a })
        let exp = expectation(description: "all bodies")
        var received: [Int] = []
        b.onBody = { body in
            if case .data(_, let d) = body {
                lock.lock(); received.append(Int(d.u32(0))); let n = received.count; lock.unlock()
                if n == 200 { exp.fulfill() }
            }
        }
        for i in 0..<200 {
            var d = Data(); d.appendU32(UInt32(i)); d.append(Data(repeating: 0xab, count: 100))
            a.send(PTCP.dataBody(realm: 1, d))
        }
        wait(for: [exp], timeout: 20)
        XCTAssertEqual(received, Array(0..<200))
        XCTAssertGreaterThan(a.stats.retransmitsOut, 0)
        a.close(); b.close()
    }
}

final class RTSPTests: XCTestCase {
    func testSDPParse() {
        let sdp = """
        v=0
        m=audio 0 RTP/AVP 8
        a=control:trackID=1
        m=video 0 RTP/AVP 96
        a=control:trackID=0
        a=rtpmap:96 H264/90000
        a=fmtp:96 packetization-mode=1;profile-level-id=640028;sprop-parameter-sets=Z2QAKKzZQHgCJ+XARAAAAwAEAAADAPA8YMZY,aO48sA==
        """
        let t = SDP.parseVideo(sdp)!
        XCTAssertEqual(t.codec, .h264)
        XCTAssertEqual(t.payloadType, 96)
        XCTAssertEqual(t.control, "trackID=0")
        XCTAssertEqual(t.paramSets.count, 2)
    }

    func testFUAReassembly() {
        let track = VideoTrack(control: "", payloadType: 96, codec: .h264, paramSets: [Data([0x67, 1]), Data([0x68, 2])])
        var frames: [VideoFrame] = []
        let dp = RTPDepacketizer(track: track) { frames.append($0) }
        func rtp(seq: UInt16, ts: UInt32, marker: Bool, payload: [UInt8]) -> Data {
            var d = Data([0x80, (marker ? 0x80 : 0) | 96]); d.append(contentsOf: [UInt8(seq >> 8), UInt8(seq & 0xff)]); d.appendU32(ts); d.appendU32(1); d.append(contentsOf: payload); return d
        }
        // IDR NAL (type 5) split in two FU-A fragments.
        dp.push(rtp(seq: 1, ts: 1000, marker: false, payload: [0x7c, 0x85, 0xaa, 0xbb]))
        dp.push(rtp(seq: 2, ts: 1000, marker: true, payload: [0x7c, 0x45, 0xcc, 0xdd]))
        XCTAssertEqual(frames.count, 1)
        XCTAssertTrue(frames[0].keyframe)
        // SPS + PPS prepended, then the IDR NAL with start codes.
        XCTAssertEqual(Array(frames[0].data), [0,0,0,1,0x67,1, 0,0,0,1,0x68,2, 0,0,0,1,0x65,0xaa,0xbb,0xcc,0xdd])
    }
}

final class DeviceQRTests: XCTestCase {
    func testShapes() {
        XCTAssertEqual(DeviceQR.parse("{SN:5G0A1B2C3D4E5F6,DT:DVR,SC:ABCD1234}"), DeviceQR(serial: "5G0A1B2C3D4E5F6", deviceType: "DVR", securityCode: "ABCD1234"))
        XCTAssertEqual(DeviceQR.parse("{SN:5G0A1B2C3D4E5F6;DT:NVR}"), DeviceQR(serial: "5G0A1B2C3D4E5F6", deviceType: "NVR"))
        XCTAssertEqual(DeviceQR.parse("DVR,5G0A1B2C3D4E5F6")?.serial, "5G0A1B2C3D4E5F6")
        XCTAssertEqual(DeviceQR.parse("  5G0A1B2C3D4E5F6\n")?.serial, "5G0A1B2C3D4E5F6")
        XCTAssertEqual(DeviceQR.parse("http://x/?a=1&SN:5G0A1B2C3D4E5F6&b")?.serial, "5G0A1B2C3D4E5F6")
        XCTAssertEqual(DeviceQR.parse("{DeviceID:ABC123,DT:IPC}")?.serial, "ABC123")
        XCTAssertNil(DeviceQR.parse("https://example.com/not-a-device"))
        XCTAssertNil(DeviceQR.parse(""))
    }
}

final class GzipQRTests: XCTestCase {
    func testGzipRoundTripViaFoundation() throws {
        // gzip produced by the system `gzip` tool of "{SN:5G0TESTSERIAL01,DT:DVR}"
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-c", "-n"]
        let inPipe = Pipe(), outPipe = Pipe(); p.standardInput = inPipe; p.standardOutput = outPipe
        try p.run()
        inPipe.fileHandleForWriting.write(Data("{SN:5G0TESTSERIAL01,DT:DVR}".utf8)); try inPipe.fileHandleForWriting.close()
        let gz = outPipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        XCTAssertEqual(String(decoding: Gzip.decompress(gz)!, as: UTF8.self), "{SN:5G0TESTSERIAL01,DT:DVR}")
        let q = DeviceQR.parse(gz.base64EncodedString())
        XCTAssertEqual(q?.serial, "5G0TESTSERIAL01"); XCTAssertEqual(q?.deviceType, "DVR")
        XCTAssertNil(DeviceQR.parse(gz.base64EncodedString().uppercased()), "corrupted base64 must not be taken as a serial")
    }

    func testJSON() {
        XCTAssertEqual(DeviceQR.parse(#"{"SN":"ABC123DEF456","DT":"NVR","SC":"X1"}"#), DeviceQR(serial: "ABC123DEF456", deviceType: "NVR", securityCode: "X1"))
    }
}

final class DeviceCardTests: XCTestCase {
    func testCardArray() throws {
        let json = #"[{"deviceName":"Home","ip":"5G0TESTSERIAL01","port":"37777","userName":"admin","passWord":"pw","channelCount":8,"deviceType":4,"moduleType":0},{"deviceName":"Office","ip":"192.168.1.5","port":"37777","userName":"admin","passWord":"x","channelCount":4,"deviceType":1}]"#
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-c", "-n"]
        let i = Pipe(), o = Pipe(); p.standardInput = i; p.standardOutput = o
        try p.run(); i.fileHandleForWriting.write(Data(json.utf8)); try i.fileHandleForWriting.close()
        let gz = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        let cards = DeviceQR.parseAll(gz.base64EncodedString())
        XCTAssertEqual(cards.count, 1, "IP devices are skipped")
        XCTAssertEqual(cards[0].serial, "5G0TESTSERIAL01"); XCTAssertEqual(cards[0].name, "Home")
        XCTAssertEqual(cards[0].username, "admin"); XCTAssertEqual(cards[0].password, "pw"); XCTAssertEqual(cards[0].channels, 8)
        XCTAssertTrue(cards[0].isCard)
        let protected = DeviceQR.parseAll("DMSS:d41d8cd98f00b204e9800998ecf8427e:" + gz.base64EncodedString())
        XCTAssertEqual(protected.first?.serial, "5G0TESTSERIAL01")
    }
}

final class DeviceCGITests: XCTestCase {
    func testChannelTitle() {
        let t = "table.ChannelTitle[0].Name=Front\ntable.ChannelTitle[1].Name=CP IP Cam\ntable.ChannelTitle[2].Name=Channel3\n"
        let c = DeviceCGI.parseChannelTitle(t)
        XCTAssertEqual(c.map(\.number), [1, 2, 3])
        XCTAssertEqual(c[0].name, "Front")
    }

    func testCameraAllOnlyEnabled() {
        let t = """
        camera[0].DeviceInfo.VideoInputs[0].Name=Channel1
        camera[0].Enable=true
        camera[0].Type=Remote
        camera[0].UniqueChannel=0
        camera[1].DeviceInfo.VideoInputs[0].Name=Gate
        camera[1].Enable=true
        camera[1].Type=Remote
        camera[1].UniqueChannel=5
        camera[2].DeviceInfo.VideoInputs[0].Name=Channel7
        camera[2].Enable=false
        camera[2].Type=Remote
        camera[2].UniqueChannel=6
        camera[3].Type=Compose
        camera[3].UniqueChannel=41
        """
        let titles = [ChannelInfo(number: 1, name: "Front")]
        let c = DeviceCGI.parseCameraAll(t, titles: titles)
        XCTAssertEqual(c.map(\.number), [1, 6])
        XCTAssertEqual(c.map(\.name), ["Front", "Gate"])
    }

    func testHTTPParse() {
        let raw = Data("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"r\", qop=\"auth\", nonce=\"n\"\r\nCONTENT-LENGTH: 0\r\n\r\n".utf8)
        let r = DeviceCGI.parse(raw)
        XCTAssertEqual(r?.code, 401)
        XCTAssertEqual(r?.headers["content-length"], "0")
        XCTAssertTrue(r?.headers["www-authenticate"]?.hasPrefix("Digest") ?? false)
    }
}

final class PTCPReassemblyTests: XCTestCase {
    private func collect(_ feed: (PTCPSession) -> Void) -> [PTCP.Body] {
        let s = PTCPSession(transmit: { _ in })
        var got: [PTCP.Body] = []
        let lock = NSLock()
        s.onBody = { b in lock.withLock { got.append(b) } }
        feed(s)
        Thread.sleep(forTimeInterval: 0.2)
        return lock.withLock { got }
    }

    private func payloads(_ bodies: [PTCP.Body]) -> [String] {
        bodies.compactMap { if case .data(_, let d) = $0 { return String(decoding: d, as: UTF8.self) } else { return nil } }
    }

    func testTwoBodiesInOneDatagram() {
        let body = PTCP.dataBody(realm: 1, Data("AAA".utf8)) + PTCP.dataBody(realm: 1, Data("BBBB".utf8))
        let got = collect { s in
            _ = s.input(PTCP.Packet(sent: 0, recv: 0, pid: 1, lmid: 1, rmid: 1, body: body).encode())
        }
        XCTAssertEqual(payloads(got), ["AAA", "BBBB"])
    }

    func testBodySplitAcrossDatagramsAndOverlap() {
        let body = PTCP.dataBody(realm: 1, Data("0123456789".utf8))
        let first = body.subdata(in: 0..<15), second = body.subdata(in: 15..<body.count)
        let got = collect { s in
            _ = s.input(PTCP.Packet(sent: 0, recv: 0, pid: 1, lmid: 1, rmid: 1, body: first).encode())
            // Retransmit that starts inside already-received bytes and completes the body.
            _ = s.input(PTCP.Packet(sent: 10, recv: 0, pid: 1, lmid: 1, rmid: 1, body: body.subdata(in: 10..<15) + second).encode())
        }
        XCTAssertEqual(payloads(got), ["0123456789"])
    }
}

final class DeviceCGITruncationTests: XCTestCase {
    func testShortBodyIsDetectedFromContentLength() {
        let raw = Data("HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 100\r\n\r\ncamera[0].Enable=true\n".utf8)
        let r = DeviceCGI.parse(raw)!
        let want = r.headers["content-length"].flatMap(Int.init)!
        XCTAssertLessThan(r.body.utf8.count, want)
    }
}

final class PTCPLegacyStatusTests: XCTestCase {
    func testStatusWithZeroLengthHeader() {
        var body = PTCP.typeHeader(PTCP.BodyType.status, len: 0, realm: 0x1234)
        body.append(Data("CONN".utf8))
        let s = PTCPSession(transmit: { _ in })
        var got: PTCP.Body?
        let lock = NSLock()
        s.onBody = { b in lock.withLock { got = b } }
        _ = s.input(PTCP.Packet(sent: 0, recv: 0, pid: 1, lmid: 1, rmid: 1, body: body).encode())
        Thread.sleep(forTimeInterval: 0.2)
        guard case .status(let realm, let status)? = lock.withLock({ got }) else { return XCTFail("no status body") }
        XCTAssertEqual(realm, 0x1234)
        XCTAssertEqual(status, "CONN")
    }
}
