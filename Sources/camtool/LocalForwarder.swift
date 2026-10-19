import Foundation
import Network
import DahuaP2P

/// Exposes a device port on a local TCP port so ffplay/VLC can use the tunnel.
final class LocalForwarder {
    private let listener: NWListener
    private let tunnel: Tunnel
    private let remotePort: UInt32
    private let log: (String) -> Void

    init(port: UInt16, remotePort: UInt32, tunnel: Tunnel, log: @escaping (String) -> Void) throws {
        self.tunnel = tunnel
        self.remotePort = remotePort
        self.log = log
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
        listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] c in self?.accept(c) }
        listener.start(queue: .global())
    }

    private func accept(_ client: NWConnection) {
        client.start(queue: .global())
        Task {
            do {
                let realm = try await tunnel.connect(port: remotePort)
                log("local client → realm \(String(realm.id, radix: 16))")
                // device → client
                Task {
                    while let d = await realm.read() {
                        client.send(content: d, completion: .contentProcessed { _ in })
                    }
                    // Flush queued sends before closing; cancel() alone drops them.
                    client.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                completion: .contentProcessed { _ in client.cancel() })
                }
                // client → device
                func pump() {
                    client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, err in
                        if let data, !data.isEmpty { try? realm.write(data) }
                        if done || err != nil { realm.close(); return }
                        pump()
                    }
                }
                pump()
            } catch {
                log("forward failed: \(error)")
                client.cancel()
            }
        }
    }

    func stop() { listener.cancel() }
}
