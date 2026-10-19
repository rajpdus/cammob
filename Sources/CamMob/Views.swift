import SwiftUI
import DahuaP2P

extension Notification.Name { static let cammobAddDevice = Notification.Name("cammob.addDevice") }

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @State private var showAdd = false
    @State private var editing: Device?
    @State private var showLog = false

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(get: { model.selected }, set: { d in if let d { model.open(d) } })) {
                ForEach(model.store.devices) { d in
                    VStack(alignment: .leading) {
                        Text(d.name).font(.headline)
                        Text(d.serial).font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(d)
                    .contextMenu {
                        Button("Edit…") { editing = d }
                        Button("Remove", role: .destructive) { if model.selected?.id == d.id { model.close(); model.selected = nil }; model.store.remove(d) }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
            .safeAreaInset(edge: .bottom) {
                Button { showAdd = true } label: { Label("Add Device", systemImage: "plus").frame(maxWidth: .infinity) }
                    .padding(8)
                    .background(.bar)
            }
            .onReceive(NotificationCenter.default.publisher(for: .cammobAddDevice)) { _ in showAdd = true }
        } detail: {
            if model.selected == nil {
                ContentUnavailableView("No device selected", systemImage: "video", description: Text("Add your DVR by its P2P serial number, then select it."))
            } else {
                LiveView()
            }
        }
        .sheet(isPresented: $showAdd) { DeviceSheet(device: nil) }
        .sheet(item: $editing) { d in DeviceSheet(device: d) }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if let d = model.selected {
                    Picker("Quality", selection: Binding(get: { !d.substream }, set: { model.setHD($0) })) {
                        Text("SD").tag(false)
                        Text("HD").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .help("SD streams the recorder's sub stream; HD streams the main stream")
                    Button { model.reconnect() } label: { Label("Reconnect", systemImage: "arrow.clockwise") }
                    Button { model.close(); model.selected = nil } label: { Label("Disconnect", systemImage: "xmark.circle") }
                }
                Toggle(isOn: $showLog) { Label("Log", systemImage: "list.bullet.rectangle") }
            }
        }
        .inspector(isPresented: $showLog) { LogView() }
        .onAppear {
            let env = ProcessInfo.processInfo.environment
            if env["CAMMOB_OPEN_ADD"] != nil { showAdd = true }
            // Test hook: import a device-card / serial QR image and open the first device.
            if let path = env["CAMMOB_IMPORT_QR"], let q = QRScanner.firstDevice(in: QRScanner.decode(fileURL: URL(fileURLWithPath: path))) {
                var d = Device(name: q.name ?? q.serial, serial: q.serial, username: q.username ?? "admin")
                d.channels = q.channels ?? 4
                model.store.add(d, password: q.password ?? "")
                model.open(d)
                return
            }
            model.restoreLastDevice()
        }
    }
}

struct LiveView: View {
    @EnvironmentObject var model: AppModel
    @State private var enlarged: Int?

    var columns: [GridItem] {
        let n = model.channels.count
        let cols = n <= 1 ? 1 : n <= 4 ? 2 : n <= 9 ? 3 : 4
        return Array(repeating: GridItem(.flexible(), spacing: 4), count: cols)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if model.connecting { ProgressView().controlSize(.small) }
                Text(model.tunnelStatus).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 8).padding(.vertical, 4)
            GeometryReader { geo in
                if let e = enlarged, let ch = model.channels.first(where: { $0.channel == e }) {
                    ChannelTile(session: ch)
                        .onTapGesture { enlarged = nil }
                        .help("Click to go back to all channels")
                } else {
                    ScrollView {
                        LazyVGrid(columns: columns, spacing: 4) {
                            ForEach(model.channels) { ch in
                                ChannelTile(session: ch)
                                    .frame(height: max(120, (geo.size.width / CGFloat(columns.count)) * 9 / 16))
                                    .onTapGesture { enlarged = ch.channel }
                                    .help("Click to view this channel full size")
                            }
                        }
                        .padding(4)
                    }
                }
            }
        }
        .background(Color.black.opacity(0.9))
    }
}

struct ChannelTile: View {
    @ObservedObject var session: ChannelSession

    var body: some View {
        ZStack(alignment: .topLeading) {
            VideoLayerView(renderer: session.renderer)
            HStack(spacing: 6) {
                Circle().fill(session.playing ? Color.green : Color.orange).frame(width: 8, height: 8)
                Text("\(session.channel) · \(session.name)").bold().lineLimit(1)
                if session.playing { Text("\(session.kbps) kbit/s") } else { Text(session.status).lineLimit(1) }
            }
            .font(.caption)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 4))
            .foregroundStyle(.white)
            .padding(6)
        }
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct DeviceSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let device: Device?
    @State private var name = ""
    @State private var serial = ""
    @State private var username = "admin"
    @State private var password = ""
    @State private var channels = 4
    @State private var substream = true
    @State private var mode: TransportMode = .relay
    @State private var showCamera = false
    @State private var scanMessage: String?

    private func apply(_ q: DeviceQR?, from source: String) {
        guard let q else { scanMessage = "No device QR code found in \(source)."; return }
        serial = q.serial
        if let n = q.name, !n.isEmpty { name = n } else if name.isEmpty, let t = q.deviceType { name = "\(t) \(q.serial.suffix(4))" }
        if let u = q.username, !u.isEmpty { username = u }
        if let p = q.password, !p.isEmpty { password = p }
        if let c = q.channels, c > 0 { channels = min(64, c) }
        scanMessage = q.isCard ? "Imported gCMOB device card: \(q.serial), \(q.channels ?? 0) channels, user \(q.username ?? "?")"
            : "Scanned \(q.serial)\(q.deviceType.map { " (\($0))" } ?? "")"
    }

    private func pickImage() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.message = "Choose a photo or screenshot of the DVR's P2P QR code"
        if panel.runModal() == .OK, let url = panel.url {
            apply(QRScanner.firstDevice(in: QRScanner.decode(fileURL: url)), from: url.lastPathComponent)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(device == nil ? "Add DVR / NVR" : "Edit Device").font(.title2).bold()
                Spacer()
                Menu {
                    Button("Scan with Camera…") { showCamera = true }
                    Button("From Image File…") { pickImage() }
                    Button("From Clipboard") { apply(QRScanner.firstDevice(in: QRScanner.decodeClipboard()), from: "the clipboard") }
                } label: { Label("Scan QR", systemImage: "qrcode.viewfinder") }
                .fixedSize()
            }
            if let m = scanMessage { Text(m).font(.caption).foregroundStyle(.secondary) }
            Form {
                TextField("Name", text: $name)
                TextField("Serial number (P2P SN)", text: $serial).textFieldStyle(.roundedBorder)
                TextField("Username", text: $username)
                SecureField("Password", text: $password)
                if let info = device?.channelInfo {
                    Text("Channels: \(info.count) (reported by the recorder)")
                } else {
                    Stepper("Channels: \(channels) (detected on first connection)", value: $channels, in: 1...64)
                }
                Toggle("Use sub stream (lower bandwidth)", isOn: $substream)
                Picker("Transport", selection: $mode) {
                    Text("Relay (works behind CGNAT/4G)").tag(TransportMode.relay)
                    Text("Direct P2P (hole punch)").tag(TransportMode.direct)
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(device == nil ? "Add" : "Save") {
                    let sn = serial.trimmingCharacters(in: .whitespacesAndNewlines)
                    var d = device ?? Device(name: name, serial: sn, username: username)
                    d.name = name.isEmpty ? sn : name
                    d.serial = sn
                    d.username = username
                    d.channels = channels
                    d.substream = substream
                    d.mode = mode.rawValue
                    if device == nil { model.store.add(d, password: password) }
                    else { model.store.update(d, password: password.isEmpty ? nil : password) }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(serial.trimmingCharacters(in: .whitespaces).isEmpty || username.isEmpty || (device == nil && password.isEmpty))
            }
        }
        .padding(20)
        .frame(width: 440)
        .sheet(isPresented: $showCamera) { CameraScanSheet { q in apply(q, from: "camera") } }
        .onDrop(of: [.image, .fileURL], isTargeted: nil) { providers in
            for p in providers {
                if p.hasItemConformingToTypeIdentifier("public.file-url") {
                    p.loadItem(forTypeIdentifier: "public.file-url") { item, _ in
                        if let d = item as? Data, let u = URL(dataRepresentation: d, relativeTo: nil) {
                            let q = QRScanner.firstDevice(in: QRScanner.decode(fileURL: u))
                            DispatchQueue.main.async { apply(q, from: u.lastPathComponent) }
                        }
                    }
                    return true
                }
            }
            return false
        }
        .onAppear {
            if let d = device {
                name = d.name; serial = d.serial; username = d.username; channels = d.channels; substream = d.substream; mode = d.transport
            }
        }
    }
}

struct LogView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(model.log.enumerated()), id: \.offset) { i, line in
                        Text(line).font(.system(.caption, design: .monospaced)).textSelection(.enabled).id(i)
                    }
                }
                .padding(8)
            }
            .onChange(of: model.log.count) { _, n in if n > 0 { proxy.scrollTo(n - 1) } }
        }
        .inspectorColumnWidth(min: 260, ideal: 360)
    }
}
