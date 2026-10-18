import Foundation

/// A device described by a QR code. Two families exist:
///
/// * The sticker / on-screen P2P code of a recorder (mirrored from gCMOB's
///   ScanPresenter.handleOverSeaSN / CaptureActivity):
///   `{SN:…,DT:DVR,SC:…,DI:…}`, `{SN:…;DT:…}`, `DVR,SN`, a bare serial, or any `SN:` run.
/// * gCMOB's own "device card" (Device Manager → export QR, ImportQRCaredHelper):
///   base64(gzip(JSON array of devices)), optionally prefixed `DMSS:<md5(pwd)>:`.
///   Each object carries deviceName, ip (the serial for P2P devices), userName,
///   passWord, channelCount, deviceType, port.
public struct DeviceQR: Equatable, Sendable {
    public var serial: String
    public var deviceType: String?
    public var securityCode: String?
    public var deviceID: String?
    public var name: String?
    public var username: String?
    public var password: String?
    public var channels: Int?
    /// True when the code came from a gCMOB device card (credentials included).
    public var isCard = false

    public init(serial: String, deviceType: String? = nil, securityCode: String? = nil, deviceID: String? = nil,
                name: String? = nil, username: String? = nil, password: String? = nil, channels: Int? = nil, isCard: Bool = false) {
        self.serial = serial; self.deviceType = deviceType; self.securityCode = securityCode; self.deviceID = deviceID
        self.name = name; self.username = username; self.password = password; self.channels = channels; self.isCard = isCard
    }

    public static func parse(_ raw: String) -> DeviceQR? { parseAll(raw).first }

    public static func parseAll(_ raw: String, depth: Int = 0) -> [DeviceQR] {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, depth < 3 else { return [] }

        // Password-protected device card: DMSS:<md5>:<base64>. The payload itself is not encrypted.
        if s.hasPrefix("DMSS:") {
            let parts = s.components(separatedBy: ":")
            if parts.count >= 3 { s = parts[2...].joined(separator: ":") }
        }
        // base64(gzip(…)) — gCMOB inflates before parsing. Base64 is case-sensitive, so the
        // text must be left untouched up to here.
        let compact = s.filter { !$0.isWhitespace }
        if compact.count >= 24, compact.hasPrefix("H4sI"), let b = Data(base64Encoded: compact), let inflated = Gzip.decompress(b) {
            return parseAll(String(decoding: inflated, as: UTF8.self), depth: depth + 1)
        }
        // JSON array of device cards, or a single JSON object.
        if s.hasPrefix("["), let arr = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [[String: Any]] {
            return arr.compactMap(fromCard)
        }
        if s.hasPrefix("{"), s.contains("\""), let obj = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any] {
            if let card = fromCard(obj) { return [card] }
            var q = DeviceQR(serial: "")
            for (k, v) in obj {
                let val = (v as? String) ?? (v as? NSNumber).map { "\($0)" } ?? ""
                switch k.uppercased() {
                case "SN", "DEVICEID", "SERIAL", "SERIALNO": q.serial = val
                case "DT", "DEVICETYPE", "TYPE": q.deviceType = val
                case "SC", "SECURITYCODE", "REGCODE": q.securityCode = val
                case "DI": q.deviceID = val
                default: break
                }
            }
            return q.serial.isEmpty ? [] : [q]
        }
        if s.hasPrefix("{"), s.hasSuffix("}") {
            let body = s.dropFirst().dropLast()
            return fields(body, sep: body.contains(";") ? ";" : ",").map { [$0] } ?? []
        }
        if s.contains("SN:") {
            let start = s.range(of: "SN:")!.upperBound
            let sn = s[start...].prefix { $0.isLetter || $0.isNumber }
            return sn.isEmpty ? [] : [DeviceQR(serial: String(sn))]
        }
        if s.contains(",") {
            let parts = s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { return [DeviceQR(serial: parts[1], deviceType: parts[0])] }
            if parts.count == 4 { return [DeviceQR(serial: parts[0], deviceType: "VTO", username: parts[1], password: parts[2])] }
            return []
        }
        if s.contains(":") || s.contains(" ") || s.count > 32 { return [] }
        return [DeviceQR(serial: s)]
    }

    private static func fromCard(_ o: [String: Any]) -> DeviceQR? {
        guard let ip = o["ip"] as? String, !ip.isEmpty else { return nil }
        let deviceType = (o["deviceType"] as? NSNumber)?.intValue ?? -1
        // deviceType 0/4 are P2P (serial) devices in gCMOB; anything with dots is an IP/DDNS entry.
        guard deviceType == 0 || deviceType == 4 || !ip.contains(".") else { return nil }
        var q = DeviceQR(serial: ip, isCard: true)
        q.name = o["deviceName"] as? String
        q.username = o["userName"] as? String
        q.password = o["passWord"] as? String
        q.channels = (o["channelCount"] as? NSNumber)?.intValue
        q.deviceType = deviceType >= 0 ? "type\(deviceType)" : nil
        return q
    }

    private static func fields(_ body: Substring, sep: Character) -> DeviceQR? {
        var q = DeviceQR(serial: "")
        for part in body.split(separator: sep) {
            let p = part.trimmingCharacters(in: .whitespaces)
            if let v = value(p, "SN:") { q.serial = v }
            else if let v = value(p, "DeviceID:") { q.serial = v }
            else if let v = value(p, "DT:") { q.deviceType = v }
            else if let v = value(p, "SC:") { q.securityCode = v }
            else if let v = value(p, "DI:") { q.deviceID = v }
        }
        return q.serial.isEmpty ? nil : q
    }

    private static func value(_ part: String, _ key: String) -> String? {
        guard let r = part.range(of: key) else { return nil }
        let v = part[r.upperBound...].trimmingCharacters(in: .whitespaces)
        return v.isEmpty ? nil : v
    }
}
