// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CamMob",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DahuaP2P", targets: ["DahuaP2P"]),
        .library(name: "DahuaRTSP", targets: ["DahuaRTSP"]),
        .executable(name: "CamMob", targets: ["CamMob"]),
        .executable(name: "camtool", targets: ["camtool"]),
    ],
    targets: [
        .target(
            name: "DahuaP2P",
            path: "Sources/DahuaP2P",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .target(
            name: "DahuaRTSP",
            dependencies: ["DahuaP2P"],
            path: "Sources/DahuaRTSP",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "CamMob",
            dependencies: ["DahuaP2P", "DahuaRTSP"],
            path: "Sources/CamMob",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("VideoToolbox"),
                .linkedFramework("AVFoundation"),
                .linkedFramework("Security"),
                .linkedFramework("Vision"),
            ]
        ),
        .executableTarget(
            name: "camtool",
            dependencies: ["DahuaP2P", "DahuaRTSP"],
            path: "Sources/camtool",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.linkedFramework("Vision"), .linkedFramework("ImageIO")]
        ),
        .testTarget(
            name: "DahuaP2PTests",
            dependencies: ["DahuaP2P", "DahuaRTSP"],
            path: "Tests/DahuaP2PTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
