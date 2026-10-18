import Foundation
import DahuaP2P
import DahuaRTSP

// camtool: command-line harness for the P2P tunnel and RTSP stream.
//
//   camtool probe  <SERIAL>                              handshake only, print device info
//   camtool stream <SERIAL> -u USER -p PASS [-c 1] [-s 1] [-n 50] [-o out.h264]
//   camtool tunnel <SERIAL> [-u USER -p PASS] -l 1554 [-r 554]   expose a device port on 127.0.0.1
// Options: -m relay|direct (default relay), -v (verbose protocol trace)

struct Args {
    var command = ""
    var serial = ""
    var user: String?
    var pass: String?
    var channel = 1
    var subtype = 1
    var frames = 50
    var out: String?
    var localPort: UInt16 = 1554
    var remotePort: UInt32 = 554
    var mode: TransportMode = .relay
    var verbose = false
    var clouds: [CloudCredentials] = [.instaon, .easy4ip]
}

func parseArgs() -> Args {
    var a = Args()
    var it = CommandLine.arguments.dropFirst().makeIterator()
    guard let cmd = it.next() else { usage() }
    a.command = cmd
    guard let sn = it.next() else { usage() }
    a.serial = sn
    while let f = it.next() {
        switch f {
        case "-u": a.user = it.next()
        case "-p": a.pass = it.next()
        case "-c": a.channel = Int(it.next() ?? "1") ?? 1
        case "-s": a.subtype = Int(it.next() ?? "1") ?? 1
        case "-n": a.frames = Int(it.next() ?? "50") ?? 50
        case "-o": a.out = it.next()
        case "-l": a.localPort = UInt16(it.next() ?? "1554") ?? 1554
        case "-r": a.remotePort = UInt32(it.next() ?? "554") ?? 554
        case "-m": a.mode = TransportMode(rawValue: it.next() ?? "relay") ?? .relay
        case "-C":
            switch it.next() ?? "" {
            case "instaon": a.clouds = [.instaon]
            case "easy4ip": a.clouds = [.easy4ip]
            default: a.clouds = [.instaon, .easy4ip]
            }
        case "-v": a.verbose = true
        default: usage()
        }
    }
    if a.pass == nil, let env = ProcessInfo.processInfo.environment["CAM_PASSWORD"] { a.pass = env }
    return a
}

func usage() -> Never {
    FileHandle.standardError.write(Data("""
    usage: camtool qr <image.png|jpg>
           camtool probe|stream|tunnel <SERIAL> [-u USER] [-p PASS|$CAM_PASSWORD] [-c CH] [-s SUBTYPE] [-n FRAMES] [-o FILE] [-l LOCALPORT] [-r REMOTEPORT] [-m relay|direct] [-C instaon|easy4ip|auto] [-v]\n
    """.utf8))
    exit(2)
}

func log(_ s: String) {
    let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"
    FileHandle.standardError.write(Data("\(f.string(from: Date())) \(s)\n".utf8))
}

if CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "qr" {
    // camtool qr <image>: decode the device QR and print the serial.
    let payloads = QRImage.decode(path: CommandLine.arguments[2])
    if payloads.isEmpty { log("no QR code found"); exit(1) }
    for p in payloads {
        let qs = DeviceQR.parseAll(p)
        if qs.isEmpty { print("unrecognized payload: \(p.prefix(80))"); continue }
        for q in qs { print("serial=\(q.serial) name=\(q.name ?? "-") type=\(q.deviceType ?? "-") user=\(q.username ?? "-") password=\(q.password == nil ? "-" : "(present)") channels=\(q.channels ?? 0) sc=\(q.securityCode ?? "-")") }
    }
    exit(0)
}

if CommandLine.arguments.count >= 5, CommandLine.arguments[1] == "raw" {
    // camtool raw <instaon|easy4ip> <host:port|main> <path> [body] [header: value]...
    let cloud: CloudCredentials = CommandLine.arguments[2] == "easy4ip" ? .easy4ip : .instaon
    let target = CommandLine.arguments[3]
    let path = CommandLine.arguments[4]
    var body: String? = nil
    var extra: [String] = []
    for a in CommandLine.arguments.dropFirst(5) { if a.contains(": ") { extra.append(a) } else { body = a } }
    let sem = DispatchSemaphore(value: 0)
    Task {
        do {
            let sock = try DHSocket(credentials: cloud)
            let ep = try Endpoint.resolve(target == "main" ? cloud.server : target)
            var req = String(decoding: DHHTTP.buildRequest(path: path, cseq: 1, body: body, credentials: cloud), as: UTF8.self)
            if !extra.isEmpty {
                let marker = "\r\nAuthorization:"
                req = req.replacingOccurrences(of: marker, with: "\r\n" + extra.joined(separator: "\r\n") + marker)
            }
            sock.onOther = { d, from in print("<<< \(from) raw \(d.count) B: \(String(decoding: d.prefix(300), as: UTF8.self))") }
            print(">>> \(ep)\n\(req)")
            sock.send(Data(req.utf8), to: ep)
            let deadline = Date().addingTimeInterval(4)
            while Date() < deadline {
                if let r = try? await sock.read(ep, timeout: max(0.1, deadline.timeIntervalSinceNow)) {
                    print("<<< \(r.code) \(r.status)\n\(r.raw)")
                }
            }
            sock.close()
        } catch { print("error: \(error)") }
        sem.signal()
    }
    sem.wait()
    exit(0)
}

let args = parseArgs()
var opts = Tunnel.Options(serial: args.serial, username: args.user, password: args.pass)
opts.mode = args.mode
opts.clouds = args.clouds
opts.log = args.verbose ? { log($0) } : { s in if !s.hasPrefix(">>>") && !s.hasPrefix("<<<") { log(s) } }

let sem = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0

Task {
    do {
        log("opening \(args.mode.rawValue) tunnel to \(args.serial)…")
        let tunnel = try await Tunnel.open(opts)
        let hs = tunnel.handshake
        log("tunnel up in \(Int((hs.timings["sync"] ?? 0) * 1000)) ms via \(hs.peer) (mode \(hs.mode.rawValue))")
        if let info = hs.info {
            log("device ports: rtsp=\(info.rtspport ?? 554) priv=\(info.privport ?? 37777) http=\(info.httpport ?? 80) tlspriv=\(info.tlsprivport ?? 0) randsalt=\(info.randsalt != nil ? "yes" : "no")")
        }
        switch args.command {
        case "probe":
            tunnel.close()
        case "stream":
            let conn = try await tunnel.connect(port: UInt32(tunnel.rtspPort))
            let url = "rtsp://device/cam/realmonitor?channel=\(args.channel)&subtype=\(args.subtype)"
            var ro = RTSPClient.Options(url: url, user: args.user, password: args.pass)
            ro.log = args.verbose ? { log($0) } : nil
            let rtsp = RTSPClient(connection: conn, options: ro)
            var count = 0
            var bytes = 0
            let fh: FileHandle? = args.out.flatMap { FileManager.default.createFile(atPath: $0, contents: nil); return FileHandle(forWritingAtPath: $0) }
            let t0 = Date()
            rtsp.onFrame = { f in
                count += 1; bytes += f.data.count
                fh?.write(f.data)
                if f.keyframe || count % 25 == 0 { log("frame \(count) \(f.codec.rawValue) \(f.keyframe ? "KEY" : "   ") \(f.data.count) B ts=\(f.timestamp)") }
                if count >= args.frames {
                    let dt = Date().timeIntervalSince(t0)
                    log("received \(count) frames, \(bytes) B in \(String(format: "%.1f", dt)) s (\(Int(Double(bytes) * 8 / dt / 1000)) kbit/s)")
                    let st = tunnel.stats
                    log("udp in=\(st.udpIn) out=\(st.udpOut) ptcp in=\(st.ptcp.datagramsIn) out=\(st.ptcp.datagramsOut) retx=\(st.ptcp.retransmitsOut) ooo=\(st.ptcp.outOfOrderIn) dup=\(st.ptcp.duplicatesIn)")
                    rtsp.close()
                    tunnel.close()
                    sem.signal()
                }
            }
            rtsp.onClose = { err in if let err { log("rtsp closed: \(err)"); exitCode = 1; sem.signal() } }
            let track = try await rtsp.start()
            log("playing \(track.codec.rawValue) (pt \(track.payloadType), \(track.paramSets.count) param sets)")
            return
        case "tunnel":
            let server = try LocalForwarder(port: args.localPort, remotePort: args.remotePort, tunnel: tunnel, log: log)
            log("listening on 127.0.0.1:\(args.localPort) → device:\(args.remotePort); e.g. ffplay -rtsp_transport tcp \"rtsp://USER:PASS@127.0.0.1:\(args.localPort)/cam/realmonitor?channel=1&subtype=1\"")
            tunnel.onClosed = { r in log("tunnel closed: \(r)"); server.stop(); sem.signal() }
            return
        default:
            usage()
        }
    } catch {
        log("error: \(error)")
        exitCode = 1
    }
    sem.signal()
}

sem.wait()
exit(exitCode)
