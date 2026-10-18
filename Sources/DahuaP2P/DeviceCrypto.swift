import Foundation
import CommonCrypto
import CryptoKit

/// Cryptography used by the Easy4ip handshake, as implemented by the official
/// clients (see re/NOTES.md for the evidence trail).
public enum DeviceCrypto {
    static let deviceInfoKey = Data("kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf".utf8)
    static let deviceInfoIV = Data("MydvJw*Iw1w&i^kk".utf8)
    static let ipEncryptIV = Data("2z52*lk9o6HRyJrf".utf8)

    public struct DeviceInfo: Decodable, Sendable {
        public var httpport: Int?
        public var privport: Int?
        public var randsalt: String?
        public var rtspport: Int?
        public var tlsprivport: Int?
    }

    /// Decrypts the base64 `Info` field of `/info/device/{serial}`.
    public static func decryptDeviceInfo(_ b64: String) throws -> DeviceInfo {
        guard let ct = Data(base64Encoded: b64) else { throw P2PError.protocolError("device info is not base64") }
        let pt = try aesOFB(key: deviceInfoKey, iv: deviceInfoIV, data: ct)
        // The JSON may carry trailing padding/garbage; cut at the last brace.
        guard let end = pt.lastIndex(of: UInt8(ascii: "}")) else { throw P2PError.protocolError("device info is not JSON") }
        let json = pt[pt.startIndex...end]
        return try JSONDecoder().decode(DeviceInfo.self, from: Data(json))
    }

    /// key = uppercase hex MD5("user:Login to {randsalt}:pass"), used as raw ASCII bytes.
    public static func deviceKey(user: String, password: String, randsalt: String) -> Data {
        let raw = "\(user):Login to \(randsalt):\(password)"
        let digest = Insecure.MD5.hash(data: Data(raw.utf8))
        return Data(digest.map { String(format: "%02X", $0) }.joined().utf8)
    }

    public static func randomNonce() -> UInt32 {
        var n: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &n) { SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!) }
        return n
    }

    public static func randomBytes(_ count: Int) -> Data {
        var d = Data(count: count)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return d
    }

    /// AES-256-OFB under PBKDF2-SHA256(key, "\(nonce)", 20000), base64.
    public static func encryptAddr(key: Data, nonce: UInt32, _ plain: String) throws -> String {
        let dk = pbkdf2SHA256(password: key, salt: Data(String(nonce).utf8), iterations: 20000, length: 32)
        return try aesOFB(key: dk, iv: ipEncryptIV, data: Data(plain.utf8)).base64EncodedString()
    }

    public static func decryptAddr(key: Data, nonce: UInt32, _ b64: String) throws -> String {
        guard let ct = Data(base64Encoded: b64) else { throw P2PError.protocolError("address is not base64") }
        let dk = pbkdf2SHA256(password: key, salt: Data(String(nonce).utf8), iterations: 20000, length: 32)
        let pt = try aesOFB(key: dk, iv: ipEncryptIV, data: ct)
        return String(decoding: pt, as: UTF8.self)
    }

    /// The `<CreateDate>…<UserName>` fragment that authenticates a channel request.
    public static func deviceAuthXML(user: String, key: Data, nonce: UInt32, randsalt: String, payload: String, now: Date = Date()) -> String {
        let curdate = Int(now.timeIntervalSince1970)
        let message = "\(nonce)\(curdate)\(payload)"
        let mac = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key))
        let auth = Data(mac).base64EncodedString()
        return "<CreateDate>\(curdate)</CreateDate><DevAuth>\(auth)</DevAuth><Nonce>\(nonce)</Nonce><RandSalt>\(randsalt)</RandSalt><UserName>\(user)</UserName>"
    }

    public static func pbkdf2SHA256(password: Data, salt: Data, iterations: Int, length: Int) -> Data {
        var out = Data(count: length)
        let rc = out.withUnsafeMutableBytes { outPtr in
            password.withUnsafeBytes { pw in
                salt.withUnsafeBytes { st in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         pw.baseAddress?.assumingMemoryBound(to: Int8.self), password.count,
                                         st.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                                         outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), length)
                }
            }
        }
        precondition(rc == kCCSuccess, "PBKDF2 failed")
        return out
    }

    /// AES in OFB mode (a stream mode: encrypt == decrypt, no padding).
    public static func aesOFB(key: Data, iv: Data, data: Data) throws -> Data {
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { v in
                CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeOFB), CCAlgorithm(kCCAlgorithmAES),
                                        CCPadding(ccNoPadding), v.baseAddress, k.baseAddress, key.count,
                                        nil, 0, 0, 0, &cryptor)
            }
        }
        guard status == kCCSuccess, let c = cryptor else { throw P2PError.protocolError("AES init failed (\(status))") }
        defer { CCCryptorRelease(c) }
        let outLen = data.count + 16
        var out = Data(count: outLen)
        var moved = 0
        let rc = data.withUnsafeBytes { inp in
            out.withUnsafeMutableBytes { o in
                CCCryptorUpdate(c, inp.baseAddress, data.count, o.baseAddress, outLen, &moved)
            }
        }
        guard rc == kCCSuccess else { throw P2PError.protocolError("AES update failed (\(rc))") }
        return out.prefix(moved)
    }

    public static func md5Hex(_ s: String) -> String {
        Insecure.MD5.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public static func sha1Base64(_ s: String) -> String {
        Data(Insecure.SHA1.hash(data: Data(s.utf8))).base64EncodedString()
    }
}
