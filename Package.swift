// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "VPNGUI",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "VPNGUI", targets: ["VPNGUI"]),
               .executable(name: "VPNHelper", targets: ["VPNHelper"]),
               .executable(name: "VPNSupervisor", targets: ["VPNSupervisor"])],
    targets: [
        // Per-connection C supervisor (fd-only inputs), executed by the helper.
        .executableTarget(name: "VPNSupervisor"),
        // posix_spawn/probe/process-identity primitives. No authorization APIs.
        .target(name: "ProcessBridge", publicHeadersPath: "include"),
        // Contracts shared by app and helper: XPC protocol, typed messages, validation, trust policy.
        .target(name: "VPNHelperShared", linkerSettings: [.linkedFramework("Security")]),
        // Helper policy/state, independent of the XPC transport (also driven by local checks).
        .target(name: "VPNHelperCore", dependencies: ["VPNHelperShared", "ProcessBridge"],
                linkerSettings: [.linkedFramework("Security")]),
        // LaunchDaemon registered with SMAppService.daemon(plistName:).
        .executableTarget(name: "VPNHelper", dependencies: ["VPNHelperCore", "VPNHelperShared"]),
        // The app links VPNHelperCore only to run the local checks against real helper code
        // over anonymous XPC listeners; production connects to the Mach service.
        .executableTarget(name: "VPNGUI", dependencies: ["VPNHelperShared", "VPNHelperCore", "ProcessBridge"],
                          linkerSettings: [.linkedFramework("Security"), .linkedFramework("AppKit"),
                                           .linkedFramework("ServiceManagement")])
    ]
)
