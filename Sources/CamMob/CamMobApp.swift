import SwiftUI
import AppKit

@main
struct CamMobApp: App {
    @StateObject private var model = AppModel()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup("CamMob") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 900, minHeight: 560)
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Add Device…") { NotificationCenter.default.post(name: .cammobAddDevice, object: nil) }
                    .keyboardShortcut("n", modifiers: .command)
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Running from `swift run` has no bundle: make it a regular foreground app.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
