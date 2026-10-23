import Foundation
import Darwin
import os
import VPNHelperCore
import VPNHelperShared

// LaunchDaemon registered by the app with SMAppService.daemon(plistName:).
// Started on demand by launchd when the app connects to the Mach service; exits when
// idle. Production configuration is fixed here: nothing in the environment, arguments
// or files can select local-check fixtures or relax the code-signing policy.

let log = Logger(subsystem: HelperConstants.helperIdentifier, category: "helper")

guard geteuid() == 0, getuid() == 0 else {
    FileHandle.standardError.write(Data("VPNHelper só é iniciado pelo launchd como root.\n".utf8))
    exit(78)
}
signal(SIGPIPE, SIG_IGN)
umask(0o022)

let policy = CodeTrust.localPolicy()
let clientRequirement: String?
let supervisorRequirement: String?
switch policy {
case .trusted(let team):
    clientRequirement = CodeTrust.requirement(identifier: HelperConstants.appIdentifier, team: team)
    supervisorRequirement = CodeTrust.requirement(identifier: HelperConstants.supervisorIdentifier, team: team)
case .unavailable(let reason):
    // Fail closed: the listener refuses every connection.
    log.error("Serviço sem assinatura confiável: \(reason, privacy: .public)")
    clientRequirement = nil
    supervisorRequirement = nil
}

// The kernel's record of our own image path (argv[0] is caller-controlled).
var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
var pathSize = UInt32(pathBuffer.count)
guard _NSGetExecutablePath(&pathBuffer, &pathSize) == 0 else { exit(78) }
let executable = URL(fileURLWithPath: String(cString: pathBuffer)).resolvingSymlinksInPath()
let supervisor = executable.deletingLastPathComponent().appendingPathComponent("VPNSupervisor").path
let nobody: (uid_t, gid_t) = (uid_t(bitPattern: -2), gid_t(bitPattern: -2))

let core = HelperCore(HelperCore.Configuration(
    stateDirectory: HelperConstants.stateDirectory,
    ownership: .production,
    supervisorSource: supervisor,
    supervisorRequirement: supervisorRequirement ?? "never",
    helperVersion: HelperConstants.fullVersion,
    probeIdentity: nobody,
    authorizer: SystemAdminAuthorizer(),
    idleTimeout: 30,
    onIdle: { log.info("Ocioso; encerrando até a próxima conexão."); exit(0) }))

let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
signal(SIGTERM, SIG_IGN)
terminate.setEventHandler {
    // launchd (or unregister) asked us to exit: stop own sessions normally and wait, bounded.
    core.shutdown(timeout: 15)
    exit(0)
}
terminate.resume()

let delegate = HelperListenerDelegate(core: core, clientRequirement: clientRequirement)
let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
if let clientRequirement { listener.setConnectionCodeSigningRequirement(clientRequirement) }
listener.delegate = delegate
listener.resume()
log.info("Serviço \(HelperConstants.fullVersion, privacy: .public) pronto (protocolo \(HelperConstants.protocolVersion)).")
dispatchMain()
