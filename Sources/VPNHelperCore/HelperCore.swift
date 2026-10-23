import Foundation
import Darwin
import ProcessBridge
import VPNHelperShared

/// Policy and state of the privileged helper, independent of the XPC transport so that
/// local checks can drive it through anonymous listeners with harmless children.
public final class HelperCore {
    public typealias EventSink = (EventBatch, @escaping () -> Void) -> Void
    public struct Configuration {
        public var stateDirectory: String
        public var ownership: TrustedOwnership
        public var supervisorSource: String
        /// Requirement for the supervisor copy. nil only in local checks (no signature to check).
        public var supervisorRequirement: String?
        public var helperVersion: String
        /// Identity used to run --help/--version of a staged runtime (production: nobody).
        public var probeIdentity: (uid_t, gid_t)?
        public var authorizer: AdminAuthorizing
        public var idleTimeout: TimeInterval
        public var onIdle: (() -> Void)?
        public init(stateDirectory: String, ownership: TrustedOwnership, supervisorSource: String,
                    supervisorRequirement: String?, helperVersion: String, probeIdentity: (uid_t, gid_t)?,
                    authorizer: AdminAuthorizing, idleTimeout: TimeInterval = 30, onIdle: (() -> Void)? = nil) {
            self.stateDirectory = stateDirectory; self.ownership = ownership; self.supervisorSource = supervisorSource
            self.supervisorRequirement = supervisorRequirement; self.helperVersion = helperVersion
            self.probeIdentity = probeIdentity; self.authorizer = authorizer
            self.idleTimeout = idleTimeout; self.onIdle = onIdle
        }
    }

    /// One authenticated XPC connection. Sessions belong to exactly one client.
    public final class Client {
        public let id = UUID()
        public let uid: uid_t
        public let auditSession: Int32
        var handshaken = false
        var sink: EventPump.Sink?
        var alive = true
        init(uid: uid_t, auditSession: Int32, sink: EventPump.Sink?) { self.uid = uid; self.auditSession = auditSession; self.sink = sink }
    }

    public let configuration: Configuration
    let queue = DispatchQueue(label: "com.luiz.vpngui.helper.core")
    private let work = DispatchQueue(label: "com.luiz.vpngui.helper.approval")
    let store: RuntimeStore
    let registry: SessionRegistry
    private var clients: [UUID: Client] = [:]
    private(set) var sessions: [String: SessionRunner] = [:]
    private var maintenanceOwner: UUID?
    private var idleTask: DispatchWorkItem?

    public init(_ configuration: Configuration) {
        self.configuration = configuration
        store = RuntimeStore(root: configuration.stateDirectory, ownership: configuration.ownership,
                             probeIdentity: configuration.probeIdentity)
        try? store.prepareDirectories()
        registry = SessionRegistry(path: (try? configuration.ownership.verifyChain(configuration.stateDirectory)) != nil ? store.registryPath : nil)
        queue.async { self.scheduleIdleCheck() }
    }

    // MARK: Clients

    public func connect(uid: uid_t, auditSession: Int32, sink: @escaping EventSink) -> Client {
        // Acknowledgements arrive on an XPC queue; the pump state lives on `queue`.
        let serialized: EventPump.Sink = { [queue] batch, acknowledged in
            sink(batch) { queue.async(execute: acknowledged) }
        }
        return queue.sync {
            let client = Client(uid: uid, auditSession: auditSession, sink: serialized)
            clients[client.id] = client
            idleTask?.cancel(); idleTask = nil
            return client
        }
    }

    /// XPC invalidation/interruption: stop and clean every session of this client only.
    public func disconnect(_ client: Client) {
        queue.async {
            client.alive = false
            client.sink = nil
            self.clients.removeValue(forKey: client.id)
            if self.maintenanceOwner == client.id { self.maintenanceOwner = nil }
            for session in self.sessions.values where session.ownerID == client.id { session.abandon() }
            self.scheduleIdleCheck()
        }
    }

    /// Helper exit (SIGTERM from launchd, unregister): stop everything and wait, bounded.
    public func shutdown(timeout: TimeInterval) {
        let group = DispatchGroup()
        queue.sync {
            for session in sessions.values where !session.finished {
                group.enter()
                let previous = session.onFinish
                session.onFinish = { runner in previous?(runner); group.leave() }
                session.abandon()
            }
        }
        _ = group.wait(timeout: .now() + timeout)
    }

    private func scheduleIdleCheck() {
        guard let onIdle = configuration.onIdle, clients.isEmpty, sessions.isEmpty else { return }
        idleTask?.cancel()
        let task = DispatchWorkItem { [weak self] in
            guard let self, self.clients.isEmpty, self.sessions.isEmpty else { return }
            onIdle()
        }
        idleTask = task
        queue.asyncAfter(deadline: .now() + configuration.idleTimeout, execute: task)
    }

    // MARK: Requests

    public func handle(_ data: Data, from client: Client, reply: @escaping (Data) -> Void) {
        let respond: (HelperResponse) -> Void = { reply(MessageCodec.encode($0)) }
        let request: HelperRequest
        do { request = try MessageCodec.decode(HelperRequest.self, from: data, limit: HelperConstants.maximumRequestSize) }
        catch { respond(.failure(error as? HelperFailure ?? HelperFailure(.invalidRequest, "Mensagem malformada."))); return }
        queue.async {
            guard client.alive else { respond(.failure(HelperFailure(.transport, "Conexão encerrada."))); return }
            if case .hello(let hello) = request {
                guard hello.protocolVersion == HelperConstants.protocolVersion else {
                    client.handshaken = false
                    respond(.failure(HelperFailure(.incompatibleProtocol,
                        "Protocolo do app (\(hello.protocolVersion)) diferente do serviço (\(HelperConstants.protocolVersion), versão \(self.configuration.helperVersion)). Atualize o serviço pelo app.")))
                    return
                }
                client.handshaken = true
                respond(.status(self.status(for: client)))
                return
            }
            guard client.handshaken else {
                respond(.failure(HelperFailure(.handshakeRequired, "Handshake obrigatório antes de qualquer operação."))); return
            }
            switch request {
            case .hello: break
            case .status: respond(.status(self.status(for: client)))
            case .start(let connection): respond(self.start(connection, for: client))
            case .stop(let token): respond(self.stop(token, for: client))
            case .stopAll:
                for session in self.sessions.values where session.ownerID == client.id { session.stop() }
                respond(.stopped(remaining: self.sessions.values.filter { $0.ownerID == client.id }.count))
            case .prepareForMaintenance:
                guard client.uid != 0, self.maintenanceOwner == nil || self.maintenanceOwner == client.id,
                      self.sessions.isEmpty, self.registry.stale(excluding: []).isEmpty else {
                    respond(.failure(HelperFailure(.busy, "Há sessões ou supervisores pendentes; manutenção cancelada.")))
                    return
                }
                self.maintenanceOwner = client.id
                respond(.done)
            case .cancelMaintenance:
                if self.maintenanceOwner == client.id { self.maintenanceOwner = nil }
                respond(.done)
            case .inspectRuntime(let path):
                let uid = client.uid
                self.work.async {
                    do { respond(.inspection(try RuntimeInspector.inspect(candidate: path, requester: uid).report)) }
                    catch { respond(.failure(Self.wrap(error))) }
                }
            case .approveRuntime(let path, let digest, let authorization):
                self.approve(path: path, digest: digest, authorization: authorization, client: client, respond: respond)
            case .removeManagedFiles(let authorization):
                self.removeManagedFiles(authorization: authorization, client: client, respond: respond)
            }
        }
    }

    static func wrap(_ error: Error) -> HelperFailure {
        if let failure = error as? HelperFailure { return failure }
        if let violation = error as? RuleViolation { return HelperFailure(.invalidRequest, violation.message) }
        return HelperFailure(.internalError, error.localizedDescription)
    }

    func status(for client: Client) -> HelperStatus {
        var runtime: RuntimeSummary?
        var problem: String?
        do { runtime = try store.loadActive().summary } catch { problem = Self.wrap(error).message }
        let authorized = (try? store.loadState().authorizedUsers.contains(client.uid)) ?? false
        let stale = registry.stale(excluding: Set(sessions.keys)).filter { $0.uid == client.uid }.map(\.connectionID)
        return HelperStatus(protocolVersion: HelperConstants.protocolVersion, helperVersion: configuration.helperVersion,
                            runtime: runtime, runtimeProblem: problem, userAuthorized: authorized,
                            activeSessions: sessions.values.filter { $0.ownerID == client.id }.count,
                            stoppingConnections: Array(Set(stale)))
    }

    private func start(_ request: ConnectionRequest, for client: Client) -> HelperResponse {
        guard maintenanceOwner == nil else { return .failure(HelperFailure(.busy, "Serviço em manutenção.")) }
        guard client.uid != 0 else { return .failure(HelperFailure(.userNotAuthorized, "O app não deve rodar como root.")) }
        guard (try? store.loadState().authorizedUsers.contains(client.uid)) == true else {
            return .failure(HelperFailure(.userNotAuthorized, "Este usuário do macOS ainda não foi autorizado por um administrador para usar o serviço."))
        }
        let runtime: ActiveRuntime
        do { runtime = try store.loadActive() } catch { return .failure(Self.wrap(error)) }
        let plan: LaunchPlan
        do { plan = try request.validatedPlan(capabilities: runtime.manifest.capabilities) }
        catch { return .failure(Self.wrap(error)) }
        // A finished runner (supervisor reaped and cleaned up) only waits for the delivery of its
        // final events; it must not block the next start, e.g. the SAML fallback after a cookie.
        if sessions.values.contains(where: { !$0.finished && $0.uid == client.uid && $0.connectionID == request.connectionID }) {
            return .failure(HelperFailure(.duplicateSession, "Esta conexão já tem uma sessão ativa ou encerrando."))
        }
        if registry.stale(excluding: Set(sessions.keys)).contains(where: { $0.uid == client.uid && $0.connectionID == request.connectionID }) {
            return .failure(HelperFailure(.busy, "A sessão anterior desta conexão ainda está encerrando. Aguarde a limpeza e tente novamente."))
        }
        guard sessions.values.filter({ !$0.finished && $0.ownerID == client.id }).count < HelperConstants.maximumSessionsPerClient else {
            return .failure(HelperFailure(.limitReached, "Limite de conexões simultâneas atingido."))
        }
        let supervisor: String
        do { supervisor = try store.preparedSupervisor(source: configuration.supervisorSource, requirement: configuration.supervisorRequirement) }
        catch { return .failure(Self.wrap(error)) }
        var configFD: Int32 = -1, cookieFD: Int32 = -1
        defer { if configFD >= 0 { close(configFD) }; if cookieFD >= 0 { close(cookieFD) } }
        do {
            try store.ownership.verifyChain(store.work)
            var content = Data(try ConfigRenderer.render(host: request.host, port: request.port, username: request.username,
                                                         password: request.authentication == .password ? request.password : nil,
                                                         trustedCertificate: request.trustedCertificate).utf8)
            defer { content.resetBytes(in: 0..<content.count) }
            configFD = try ProtectedDescriptor.anonymousFile(content, directory: store.work)
            if plan.usesCookie, let cookie = request.cookie { cookieFD = try ProtectedDescriptor.pipe(Data(cookie.utf8)) }
        } catch { return .failure(Self.wrap(error)) }
        let argv = [supervisor] + plan.supervisorArguments(binary: runtime.executable)
        let environment = RuntimeEnvironment.list(runtime.environment)
        var pid: pid_t = 0
        var cArguments: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
        var cEnvironment: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        defer { cArguments.forEach { free($0) }; cEnvironment.forEach { free($0) } }
        let control = cArguments.withUnsafeMutableBufferPointer { a in
            cEnvironment.withUnsafeMutableBufferPointer { e in
                vpn_spawn_supervisor(supervisor, a.baseAddress, e.baseAddress, configFD, cookieFD, &pid)
            }
        }
        guard control >= 0 else {
            return .failure(HelperFailure(.internalError, "Não foi possível iniciar o supervisor (\(String(cString: strerror(errno))))."))
        }
        let token = UUID().uuidString
        let pump = EventPump(token: token, sink: client.sink)
        let runner = SessionRunner(token: token, ownerID: client.id, uid: client.uid, connectionID: request.connectionID,
                                   supervisorPID: pid, control: control, queue: queue, pump: pump)
        runner.onFinish = { [weak self] runner in
            guard let self else { return }
            self.registry.remove(token: runner.token)
            // Keep the session (and its duplicate guard) until the terminal event was handed over.
            let finish = { [weak self] in
                guard let self, self.sessions[runner.token] === runner else { return }
                self.sessions.removeValue(forKey: runner.token)
                self.scheduleIdleCheck()
            }
            if runner.pump.sink == nil || runner.pump.isDrained { finish() } else { runner.pump.onIdle = finish }
        }
        sessions[token] = runner
        registry.add(token: token, uid: client.uid, connectionID: request.connectionID, pid: pid)
        runner.startReading(captureCookie: plan.mode == .capture, secrets: plan.usesCookie ? [request.cookie ?? ""] : [])
        return .started(token: token, plan: plan)
    }

    private func stop(_ token: String, for client: Client) -> HelperResponse {
        // A token of another client is indistinguishable from an unknown one.
        guard let session = sessions[token], session.ownerID == client.id else {
            return .failure(HelperFailure(.unknownSession, "Sessão desconhecida."))
        }
        session.stop()
        return .stopped(remaining: sessions.values.filter { $0.ownerID == client.id }.count)
    }

    private func approve(path: String, digest: String, authorization: Data, client: Client, respond: @escaping (HelperResponse) -> Void) {
        guard client.uid != 0 else { respond(.failure(HelperFailure(.userNotAuthorized, "O app não deve rodar como root."))); return }
        let uid = client.uid
        work.async {
            do {
                let inventory = try RuntimeInspector.inspect(candidate: path, requester: uid)
                guard inventory.digest == digest else {
                    throw HelperFailure(.runtimeRejected, "A instalação mudou desde a inspeção. Revise o inventário novamente antes de aprovar.")
                }
                guard self.configuration.authorizer.authorize(authorization) else {
                    throw HelperFailure(.authorizationDenied, "Aprovação de administrador cancelada ou recusada.")
                }
                // Serialized with start/status on the core queue. Installing never replaces a
                // runtime in use: a new directory is created and the previous one is kept.
                var outcome: Result<Void, Error> = .success(())
                self.queue.sync {
                    do { try self.store.install(inventory, approvedBy: uid) } catch { outcome = .failure(error) }
                }
                try outcome.get()
                self.queue.async { respond(.status(self.status(for: client))) }
            } catch { respond(.failure(Self.wrap(error))) }
        }
    }

    private func removeManagedFiles(authorization: Data, client: Client, respond: @escaping (HelperResponse) -> Void) {
        guard sessions.isEmpty, registry.stale(excluding: []).isEmpty else {
            respond(.failure(HelperFailure(.busy, "Há sessões ativas ou encerrando; desconecte antes de remover os arquivos do serviço."))); return
        }
        work.async {
            guard self.configuration.authorizer.authorize(authorization) else {
                respond(.failure(HelperFailure(.authorizationDenied, "Aprovação de administrador cancelada ou recusada."))); return
            }
            self.queue.async {
                guard self.sessions.isEmpty else {
                    respond(.failure(HelperFailure(.busy, "Uma sessão começou durante a remoção; nada foi apagado."))); return
                }
                self.store.removeAll()
                respond(.done)
            }
        }
    }

    // MARK: Local checks

    public var sessionCount: Int { queue.sync { sessions.count } }
    public var stateStore: RuntimeStore { store }
}
