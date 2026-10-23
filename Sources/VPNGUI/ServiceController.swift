import Foundation
import AppKit
import ServiceManagement
import CryptoKit
import VPNHelperShared

/// Registration API used by the controller. Production: SMAppService.daemon(plistName:).
@MainActor
protocol ServiceRegistrar: AnyObject {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister(completion: @escaping (Error?) -> Void)
    func openSystemSettings()
}

@MainActor
final class DaemonRegistrar: ServiceRegistrar {
    private let service = SMAppService.daemon(plistName: HelperConstants.plistName)
    var status: SMAppService.Status { service.status }
    func register() throws { try service.register() }
    func unregister(completion: @escaping (Error?) -> Void) {
        service.unregister { error in DispatchQueue.main.async { completion(error) } }
    }
    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// What the app can transport to the helper; the manager depends only on this.
@MainActor
protocol SessionTransport: AnyObject {
    /// nil when new sessions may start; otherwise a reason for the user.
    var unavailableReason: String? { get }
    var capabilities: RuntimeCapabilities? { get }
    func start(_ request: ConnectionRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void)
    func stop(_ token: String, completion: @escaping (HelperFailure?) -> Void)
}

/// Real state of the privileged service: registration (SMAppService) plus an
/// authenticated handshake. `enabled` alone never counts as healthy.
@MainActor
final class ServiceController: ObservableObject, SessionTransport {
    enum Health: Equatable {
        case checking
        case unsigned(String)
        case notRegistered
        case requiresApproval
        case notFound
        case unresponsive(String)
        case incompatible(String)
        case outdated(String)
        case runtimeMissing(String)
        case userNotAuthorized
        case ready

        var title: String {
            switch self {
            case .checking: return "Verificando o serviço…"
            case .unsigned: return "Assinatura necessária"
            case .notRegistered: return "Serviço não ativado"
            case .requiresApproval: return "Aprovação pendente em Ajustes"
            case .notFound: return "Serviço não encontrado no app"
            case .unresponsive: return "Serviço não responde"
            case .incompatible: return "Serviço incompatível"
            case .outdated: return "Atualização do serviço necessária"
            case .runtimeMissing: return "openfortivpn não aprovado"
            case .userNotAuthorized: return "Usuário não autorizado"
            case .ready: return "Serviço pronto"
            }
        }
        var detail: String {
            switch self {
            case .checking: return "Consultando o registro e o serviço privilegiado."
            case .unsigned(let reason): return reason + " Veja o guia de ativação no README."
            case .notRegistered: return "Use Ativar serviço. O macOS pedirá a aprovação do item em Ajustes do Sistema › Geral › Itens de Início."
            case .requiresApproval: return "Habilite OpenFortiDesk em Ajustes do Sistema › Geral › Itens de Início › Permitir em segundo plano e volte ao app."
            case .notFound: return "O bundle não contém o LaunchDaemon esperado. Use o app gerado por scripts/build.sh."
            case .unresponsive(let reason): return "O serviço está habilitado, mas o handshake autenticado falhou: \(reason)"
            case .incompatible(let reason): return reason
            case .outdated(let version): return "O serviço registrado é \(version); este app é \(HelperConstants.fullVersion). Use Atualizar serviço (desconecta antes)."
            case .runtimeMissing(let reason): return reason + " Use Aprovar openfortivpn… (requer administrador)."
            case .userNotAuthorized: return "Um administrador precisa autorizar este usuário do macOS: use Aprovar openfortivpn…."
            case .ready: return "Conectar não pede senha de administrador enquanto o serviço estiver habilitado e íntegro."
            }
        }
        var symbol: String {
            switch self {
            case .ready: return "checkmark.shield"
            case .checking: return "hourglass"
            case .requiresApproval, .notRegistered, .runtimeMissing, .userNotAuthorized, .outdated: return "exclamationmark.shield"
            default: return "xmark.shield"
            }
        }
    }

    @Published private(set) var health: Health = .checking
    @Published private(set) var status: HelperStatus?
    @Published private(set) var busy = false
    @Published var message: String?
    @Published var inspection: RuntimeInspection?
    @Published private(set) var blockNewSessions = false
    let policy: CodeTrust.Policy
    let registrar: ServiceRegistrar?
    let client: HelperClient?
    weak var manager: VPNManager?
    /// Poll interval/limit while waiting for sessions to end before unregistering.
    var cleanupPoll: TimeInterval = 0.3
    var cleanupLimit: TimeInterval = 120

    init(policy: CodeTrust.Policy, registrar: ServiceRegistrar?, client: HelperClient?) {
        self.policy = policy
        self.registrar = registrar
        self.client = client
        client?.onStatus = { [weak self] status in self?.apply(status) }
        client?.onLost = { [weak self] in
            guard let self else { return }
            self.manager?.transportLost()
            if self.health == .ready { self.health = .unresponsive("conexão perdida; use Verificar novamente.") }
        }
        client?.onEvents = { [weak self] batch in self?.manager?.receive(batch) }
    }

    /// Production wiring; local checks never reach the Mach service.
    static func production() -> ServiceController {
        let policy = CodeTrust.localPolicy()
        if MenuBarCoordinator.isLocalChecks {
            return ServiceController(policy: .unavailable(reason: "Executor de verificações locais: serviço real desativado."), registrar: nil, client: nil)
        }
        if case .trusted(let team) = policy {
            return ServiceController(policy: policy, registrar: DaemonRegistrar(), client: .production(team: team))
        }
        return ServiceController(policy: policy, registrar: DaemonRegistrar(), client: nil)
    }

    var canConnect: Bool { unavailableReason == nil }
    var isRegistered: Bool {
        guard let registrar else { return false }
        return [.enabled, .requiresApproval].contains(registrar.status)
    }
    var unavailableReason: String? {
        if blockNewSessions { return "O serviço está sendo removido ou atualizado; novas conexões aguardam." }
        if health == .ready, status?.runtime != nil { return nil }
        return "\(health.title). \(health.detail)"
    }
    var capabilities: RuntimeCapabilities? { status?.runtime?.capabilities }

    var bundleLocationWarning: String? {
        let path = Bundle.main.bundleURL.path
        return path.hasPrefix("/Applications/") ? nil :
            "O app está em \(path). Para uso real, instale-o em /Applications antes de ativar o serviço (o registro aponta para este bundle)."
    }

    /// Homebrew changed since approval: informational, the protected copy keeps running.
    var sourceDrift: String? {
        guard let runtime = status?.runtime,
              let data = FileManager.default.contents(atPath: runtime.sourcePath) else { return nil }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return digest == runtime.sourceSHA256 ? nil :
            "O openfortivpn em \(runtime.sourcePath) mudou desde a aprovação. A cópia aprovada (\(runtime.version)) continua em uso; aprove novamente para atualizar."
    }

    // MARK: Status

    func refresh() {
        if case .unavailable(let reason) = policy { health = .unsigned(reason); status = nil; return }
        guard let registrar else { health = .notFound; return }
        switch registrar.status {
        case .notRegistered: health = .notRegistered; status = nil
        case .requiresApproval: health = .requiresApproval; status = nil
        case .notFound: health = .notFound; status = nil
        case .enabled: handshake()
        @unknown default: health = .unresponsive("estado de registro desconhecido"); status = nil
        }
    }

    private func handshake() {
        guard let client else { health = .unresponsive("cliente indisponível"); return }
        if health != .ready { health = .checking }
        client.request(.status) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(.status(let status)): self.apply(status)
            case .success(.failure(let failure)), .failure(let failure):
                self.status = nil
                self.health = failure.code == .incompatibleProtocol ? .incompatible(failure.message) : .unresponsive(failure.message)
            case .success: self.health = .unresponsive("resposta inesperada")
            }
        }
    }

    func apply(_ status: HelperStatus) {
        self.status = status
        if status.helperVersion != HelperConstants.fullVersion { health = .outdated(status.helperVersion) }
        else if status.runtime == nil { health = .runtimeMissing(status.runtimeProblem ?? "Nenhum openfortivpn aprovado.") }
        else if !status.userAuthorized { health = .userNotAuthorized }
        else { health = .ready }
    }

    // MARK: Actions (one attempt per click; never a register loop)

    func activate() {
        guard case .trusted = policy, let registrar else { refresh(); return }
        if registrar.status == .enabled { refresh(); return }
        // Same label installed the legacy way would conflict; never touch someone else's file.
        let legacy = "/Library/LaunchDaemons/\(HelperConstants.plistName)"
        if FileManager.default.fileExists(atPath: legacy) {
            message = "Já existe \(legacy) com o mesmo identificador. Remova esse item manualmente antes de ativar; o app não altera arquivos que não registrou."
            refresh()
            return
        }
        do {
            try registrar.register()
            message = registrar.status == .requiresApproval
                ? "Serviço registrado. Aprove OpenFortiDesk em Ajustes do Sistema › Geral › Itens de Início e volte ao app."
                : "Serviço registrado."
        } catch {
            let code = (error as NSError).code
            if code == kSMErrorAlreadyRegistered { message = nil }
            else if code == kSMErrorLaunchDeniedByUser { message = "O macOS aguarda sua aprovação em Ajustes do Sistema › Itens de Início." }
            else if code == kSMErrorInvalidSignature { message = "O macOS recusou a assinatura do app. Daemons exigem app assinado com Team ID e notarizado; veja o guia de ativação." }
            else { message = "Não foi possível registrar o serviço: \(error.localizedDescription)" }
        }
        refresh()
    }

    func openSettings() { registrar?.openSystemSettings() }

    func inspect(candidate: String) {
        guard let client, health != .checking else { return }
        busy = true
        inspection = nil
        client.request(.inspectRuntime(path: candidate), timeout: 60) { [weak self] result in
            guard let self else { return }
            self.busy = false
            switch result {
            case .success(.inspection(let inspection)): self.inspection = inspection
            case .success(.failure(let failure)), .failure(let failure): self.message = failure.message
            case .success: self.message = "Resposta inesperada do serviço."
            }
        }
    }

    /// The administrator prompt is shown by macOS in this session; nothing is automated.
    func approve() {
        guard let client, let inspection else { return }
        guard let authorization = AdminAuthorizationHandle() else { message = "Não foi possível preparar a autorização do macOS."; return }
        busy = true
        client.request(.approveRuntime(path: inspection.candidatePath, digest: inspection.digest,
                                       authorization: authorization.externalForm), timeout: 600) { [weak self] result in
            withExtendedLifetime(authorization) {}
            guard let self else { return }
            self.busy = false
            switch result {
            case .success(.status(let status)):
                self.inspection = nil
                self.apply(status)
                self.message = "openfortivpn \(status.runtime?.version ?? "") aprovado e protegido."
            case .success(.failure(let failure)), .failure(let failure): self.message = failure.message
            case .success: self.message = "Resposta inesperada do serviço."
            }
        }
    }

    /// Remove (or update) order: block new sessions → disconnect and wait for cleanup →
    /// confirm with the helper → optionally remove managed files → unregister.
    /// Unregister can kill the helper, so it is never used as a disconnect.
    func remove(includeManagedFiles: Bool, reRegister: Bool = false, completion: (() -> Void)? = nil) {
        guard let registrar else { completion?(); return }
        busy = true
        blockNewSessions = true
        manager?.disconnectAll()
        waitForCleanup(deadline: Date().addingTimeInterval(cleanupLimit)) { [weak self] cleaned in
            guard let self else { return }
            guard cleaned else {
                self.finishAction("As conexões ainda não confirmaram a limpeza; o serviço não foi removido.", completion)
                return
            }
            self.confirmHelperIdle { idle in
                guard idle else {
                    self.finishAction("A limpeza global não foi confirmada; o serviço não foi removido. Se o helper for antigo, remova o serviço pelo app anterior antes de atualizar.", completion)
                    return
                }
                self.removeFiles(includeManagedFiles) { note in
                    registrar.unregister { error in
                        if error != nil { self.client?.request(.cancelMaintenance) { _ in } }
                        else { self.client?.invalidate() }
                        var text = error.map { "Falha ao remover o registro: \($0.localizedDescription)" } ?? "Serviço removido. Cadastros e senhas foram preservados."
                        if let note { text += " " + note }
                        if reRegister && error == nil {
                            do { try registrar.register(); text = "Serviço atualizado. Se o macOS pedir, aprove novamente em Ajustes." }
                            catch { text = "Registro removido, mas o novo registro falhou: \(error.localizedDescription)" }
                        }
                        self.finishAction(text, completion)
                    }
                }
            }
        }
    }

    func update(completion: (() -> Void)? = nil) { remove(includeManagedFiles: false, reRegister: true, completion: completion) }

    private func finishAction(_ text: String, _ completion: (() -> Void)?) {
        busy = false
        blockNewSessions = false
        message = text
        refresh()
        completion?()
    }

    private func waitForCleanup(deadline: Date, _ done: @escaping (Bool) -> Void) {
        guard let manager, manager.anyActive else { done(true); return }
        guard Date() < deadline else { done(false); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + cleanupPoll) { [weak self] in
            self?.waitForCleanup(deadline: deadline, done)
        }
    }

    private func confirmHelperIdle(_ done: @escaping (Bool) -> Void) {
        guard registrar?.status == .enabled else {
            done(registrar?.status == .notRegistered || registrar?.status == .requiresApproval); return
        }
        guard let client else { done(false); return }
        client.request(.prepareForMaintenance, timeout: 15) { result in
            switch result {
            case .success(.done): done(true)
            default: done(false) // Missing replies and other users' sessions fail closed.
            }
        }
    }

    private func removeFiles(_ include: Bool, _ done: @escaping (String?) -> Void) {
        guard include, let client, registrar?.status == .enabled else {
            done(include ? "Arquivos gerenciados em \(HelperConstants.stateDirectory) não foram alterados (serviço inacessível)." : nil)
            return
        }
        guard let authorization = AdminAuthorizationHandle() else { done("Arquivos gerenciados preservados (autorização indisponível)."); return }
        client.request(.removeManagedFiles(authorization: authorization.externalForm), timeout: 600) { result in
            withExtendedLifetime(authorization) {}
            switch result {
            case .success(.done): done("Arquivos gerenciados do serviço removidos.")
            case .success(.failure(let failure)), .failure(let failure):
                done("Arquivos gerenciados preservados em \(HelperConstants.stateDirectory): \(failure.message)")
            default: done("Arquivos gerenciados preservados.")
            }
        }
    }

    // MARK: SessionTransport

    func start(_ request: ConnectionRequest, completion: @escaping (Result<(String, LaunchPlan), HelperFailure>) -> Void) {
        guard unavailableReason == nil, let client else {
            completion(.failure(HelperFailure(.unavailable, unavailableReason ?? "Serviço indisponível."))); return
        }
        client.request(.start(request), timeout: 30) { result in
            switch result {
            case .success(.started(let token, let plan)): completion(.success((token, plan)))
            case .success(.failure(let failure)), .failure(let failure): completion(.failure(failure))
            case .success: completion(.failure(HelperFailure(.invalidRequest, "Resposta inesperada do serviço.")))
            }
        }
    }

    func stop(_ token: String, completion: @escaping (HelperFailure?) -> Void) {
        guard let client else { completion(HelperFailure(.unavailable, "Serviço indisponível.")); return }
        client.request(.stop(token: token), timeout: 15) { result in
            switch result {
            case .success(.stopped): completion(nil)
            case .success(.failure(let failure)), .failure(let failure): completion(failure)
            case .success: completion(HelperFailure(.invalidRequest, "Resposta inesperada do serviço."))
            }
        }
    }

    // MARK: Local checks

    /// Used only by the local checks to emulate a healthy service around a fixture helper.
    func useForLocalChecks(status: HelperStatus) { apply(status) }
}
