import AppKit
import ServiceManagement
import VPNHelperShared

/// A single fixed operation, run as the logged-in user. No shell, root execution,
/// PID arguments, custom paths or helper commands. XPC uses the production trust policy.
@MainActor
enum Maintenance {
    static let argument = "--prepare-for-maintenance"
    static func run() -> Int32 {
        guard CommandLine.arguments == [CommandLine.arguments[0], argument], getuid() != 0,
              case .trusted(let team) = CodeTrust.localPolicy() else {
            fputs("Maintenance requires a signed app, a normal user and no extra arguments.\n", stderr)
            return 1
        }
        // Cocoa's normal quit request reaches applicationShouldTerminate: cancellation
        // and pending cleanup are respected. Never forceTerminate or signal a PID.
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: HelperConstants.appIdentifier)
            .filter { $0.processIdentifier != getpid() }
        for app in running {
            guard app.terminate() else { return fail("Quit was refused. Use Sair in the installed app, then retry.") }
        }
        guard wait(125, { running.allSatisfy(\.isTerminated) }) else {
            return fail("Quit was cancelled or cleanup timed out. The bundle was preserved.")
        }
        let registrar = DaemonRegistrar()
        if registrar.status == .notRegistered {
            return serviceIsAbsent() ? 0 : fail("A service from another bundle is still registered. Remove it in the old app first.")
        }
        // Pending approval cannot have started a session. Unregister still must succeed.
        let client = HelperClient.production(team: team)
        if registrar.status == .enabled {
            var result: Bool?
            client.request(.prepareForMaintenance, timeout: 20) { reply in
                if case .success(.done) = reply { result = true } else { result = false }
            }
            guard wait(25, { result != nil }), result == true else {
                client.invalidate()
                return fail("Helper did not prove global idle. For a legacy installation, use Remover serviço in the old app first.")
            }
        } else if registrar.status != .requiresApproval || !serviceIsAbsent() {
            return fail("Service registration is unavailable or belongs to another bundle; bundle preserved.")
        }
        var finished = false
        var error: Error?
        registrar.unregister { error = $0; finished = true }
        guard wait(30, { finished }), error == nil, registrar.status == .notRegistered else {
            client.request(.cancelMaintenance) { _ in }
            _ = wait(1, { false })
            client.invalidate()
            return fail("Unregister failed or timed out; bundle preserved. Check Gerenciar serviço.")
        }
        client.invalidate()
        guard wait(10, { serviceIsAbsent() }) else {
            return fail("Launch service still exists after unregister; bundle preserved.")
        }
        return 0
    }

    /// Read-only, fixed system lookup. A registration attached to the old bundle
    /// must not be mistaken for a fresh install just because this bundle says absent.
    static func serviceIsAbsent() -> Bool {
        let process = Process()
        let errors = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "system/" + HelperConstants.helperIdentifier]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        do { try process.run() } catch { return false }
        let output = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return absentServiceReply(status: process.terminationStatus, stderr: String(decoding: output, as: UTF8.self))
    }
    static func absentServiceReply(status: Int32, stderr: String) -> Bool {
        status == 113 && stderr.contains("Could not find service \"" + HelperConstants.helperIdentifier + "\" in domain for system")
    }
    static func wait(_ seconds: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition(), Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return condition()
    }
    private static func fail(_ message: String) -> Int32 { fputs(message + "\n", stderr); return 1 }
}
