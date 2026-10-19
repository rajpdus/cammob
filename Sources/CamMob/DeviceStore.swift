import Foundation
import Security
import DahuaP2P
import DahuaRTSP

struct Device: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String
    var serial: String
    var username: String
    var channels: Int = 4
    var substream: Bool = true
    var mode: String = TransportMode.relay.rawValue
    /// Channels as last reported by the recorder (nil until the first connection).
    var channelInfo: [ChannelInfo]? = nil

    var transport: TransportMode { TransportMode(rawValue: mode) ?? .relay }
}

/// Devices live in UserDefaults; passwords live in the login Keychain.
final class DeviceStore: ObservableObject {
    @Published private(set) var devices: [Device] = []
    private let key = "cammob.devices"

    init() { load() }

    private func load() {
        if let d = UserDefaults.standard.data(forKey: key), let list = try? JSONDecoder().decode([Device].self, from: d) {
            devices = list
        }
    }

    private func save() {
        if let d = try? JSONEncoder().encode(devices) { UserDefaults.standard.set(d, forKey: key) }
    }

    func add(_ device: Device, password: String) {
        devices.append(device)
        Keychain.set(password, account: device.id.uuidString)
        save()
    }

    func update(_ device: Device, password: String?) {
        if let i = devices.firstIndex(where: { $0.id == device.id }) { devices[i] = device }
        if let p = password { Keychain.set(p, account: device.id.uuidString) }
        save()
    }

    func remove(_ device: Device) {
        devices.removeAll { $0.id == device.id }
        Keychain.delete(account: device.id.uuidString)
        save()
    }

    func password(for device: Device) -> String { Keychain.get(account: device.id.uuidString) ?? "" }
}

enum Keychain {
    static let service = "com.rajpdus.cammob"

    static func set(_ value: String, account: String) {
        delete(account: account)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecValueData as String: Data(value.utf8)]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func get(account: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(decoding: d, as: UTF8.self)
    }

    static func delete(account: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
    }
}
