import SwiftUI
import AppKit
import VPNHelperShared

@MainActor
final class AppModel: ObservableObject {
    @Published var data = SavedData()
    @Published var error: String?
    @Published var ready = false
    let manager = VPNManager()
    /// Display order for the window and the menu bar: by name as Finder sorts it
    /// (case, accents and numbers), then by server for equal names. Storage keeps its order.
    var sortedConnections: [Connection] {
        data.connections.sorted {
            switch $0.name.localizedStandardCompare($1.name) {
            case .orderedAscending: return true
            case .orderedDescending: return false
            case .orderedSame: return $0.endpoint.localizedStandardCompare($1.endpoint) == .orderedAscending
            }
        }
    }
    let passwords: PasswordStore
    let cookies: SAMLCookieStore
    /// Privileged service (SMAppService + authenticated XPC); the manager's transport.
    let service: ServiceController
    /// Called on a user Conectar (not on automatic reconnects). Must return at once:
    /// the update check it triggers never delays or changes the connection.
    var onUserConnect: (() -> Void)?
    private var store: JSONStore?
    /// Imported OpenVPN profiles, next to connections.json.
    private(set) var profiles: ProfileStore?
    /// Imported WireGuard profiles (with their private keys), next to connections.json.
    private(set) var wireGuardProfiles: ProfileStore?
    init(store suppliedStore: JSONStore? = nil, passwords: PasswordStore = PasswordStore(),
         cookies: SAMLCookieStore = SAMLCookieStore(), service: ServiceController? = nil) {
        self.passwords = passwords
        self.cookies = cookies
        self.service = service ?? .production()
        manager.cookies = cookies
        manager.transport = self.service
        self.service.manager = manager
        do {
            let store = try suppliedStore ?? JSONStore()
            self.store = store
            profiles = .openVPN(store)
            wireGuardProfiles = .wireGuard(store)
            data = try store.load()
            for connection in data.connections { _ = manager.session(connection.id) }
            ready = true
        } catch { self.error = "Falha ao ler os dados. O arquivo existente foi preservado. \(error.localizedDescription)" }
        manager.retry = { [weak self] id in
            guard let self, let connection = self.data.connections.first(where: { $0.id == id }) else { return }
            self.connect(connection, retrying: true)
        }
    }
    /// `openVPNProfile` is the normalized profile of a new import (or a replacement);
    /// nil keeps the profile already saved for this connection. `wireGuardProfile` likewise.
    func save(_ connection: Connection, password: String, openVPNProfile: String? = nil, wireGuardProfile: String? = nil) throws {
        guard ready, let store else { throw AppFailure("Os dados não foram carregados; o arquivo foi preservado.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de editar.") }
        let c = try connection.validated()
        if c.usesPassword {
            guard !password.isEmpty else { throw AppFailure("Informe a senha da VPN.") }
            if c.isOpenVPN {
                do { try OpenVPNRules.checkCredential(password, label: "Senha") }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { try Connection.checkConfigValue(password, label: "Senha") }
        }
        if c.isOpenVPN {
            guard let profiles else { throw AppFailure("Pasta de perfis indisponível.") }
            if let openVPNProfile {
                // The helper applies exactly this check again before root reads it.
                do { _ = try OpenVPNProfile.validated(openVPNProfile) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { _ = try profiles.read(c.id) }
        }
        if c.isWireGuard {
            guard let wireGuardProfiles else { throw AppFailure("Pasta de perfis indisponível.") }
            if let wireGuardProfile {
                do { _ = try WireGuardProfile.validated(wireGuardProfile) }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { _ = try wireGuardProfiles.read(c.id) }
        }
        let previousProfile = c.isOpenVPN && openVPNProfile != nil ? try? profiles?.read(c.id) : nil
        let previousWireGuard = c.isWireGuard && wireGuardProfile != nil ? try? wireGuardProfiles?.read(c.id) : nil
        let previous = try passwords.read(c.id)
        // Any change to gateway, port, user, authentication or certificate drops the saved
        // SAML session. Renaming keeps it; the identity check on read is a second barrier.
        if let old = data.connections.first(where: { $0.id == c.id }),
           SAMLCookieIdentity(old) != SAMLCookieIdentity(c) {
            try? cookies.delete(c.id)
        }
        var updated = data
        if let index = updated.connections.firstIndex(where: { $0.id == c.id }) { updated.connections[index] = c }
        else { updated.connections.append(c) }
        do {
            if let openVPNProfile { try profiles?.write(openVPNProfile, id: c.id) }
            if let wireGuardProfile { try wireGuardProfiles?.write(wireGuardProfile, id: c.id) }
            if c.usesPassword { try passwords.write(password, id: c.id) }
            else { try passwords.delete(c.id) }
            try store.save(updated)
        } catch {
            if let previous { try? passwords.write(previous, id: c.id) }
            else { try? passwords.delete(c.id) }
            if openVPNProfile != nil {
                if let previousProfile { try? profiles?.write(previousProfile, id: c.id) } else { try? profiles?.delete(c.id) }
            }
            if wireGuardProfile != nil {
                if let previousWireGuard { try? wireGuardProfiles?.write(previousWireGuard, id: c.id) } else { try? wireGuardProfiles?.delete(c.id) }
            }
            throw error
        }
        data = updated
        manager.session(c.id).authenticationRejected = false
        manager.session(c.id).digestFix = nil
    }
    func delete(_ connection: Connection) throws {
        guard ready, let store else { throw AppFailure("Os dados não foram carregados.") }
        guard manager.sessions[connection.id]?.state.active != true else { throw AppFailure("Desconecte antes de excluir.") }
        var updated = data
        updated.connections.removeAll { $0.id == connection.id }
        let previous = try passwords.read(connection.id)
        do {
            try passwords.delete(connection.id)
            try store.save(updated)
        } catch {
            if let previous { try? passwords.write(previous, id: connection.id) }
            throw error
        }
        try? cookies.delete(connection.id)
        try? profiles?.delete(connection.id)
        try? wireGuardProfiles?.delete(connection.id)
        data = updated
        manager.sessions.removeValue(forKey: connection.id)
    }
    func trustCertificate(_ connection: Connection, digest: String) throws {
        let session = manager.session(connection.id)
        guard ready, let store, !session.state.active, session.certificateValidationFailed,
              session.suggestedCertificate == digest else { throw AppFailure("O certificado sugerido não está mais disponível.") }
        guard let index = data.connections.firstIndex(where: { $0.id == connection.id }) else { throw AppFailure("Conexão não encontrada.") }
        var updated = data
        updated.connections[index].trustedCertificate = digest
        _ = try updated.connections[index].validated()
        try store.save(updated) // Password stays in Keychain, untouched by certificate approval.
        try? cookies.delete(connection.id) // A new trusted certificate is a new gateway identity.
        data = updated
        session.suggestedCertificate = nil
        connect(updated.connections[index])
    }
    /// Rewrites only `auth RSA-SHAx` → `auth SHAx` in the app's copy of the profile, after the
    /// user confirmed it in the interface, then connects again. The original file is untouched.
    func applyDigestFix(_ connection: Connection, _ fix: OpenVPNCompatibility.DigestFix) throws {
        guard connection.isOpenVPN, let profiles, !manager.session(connection.id).state.active else {
            throw AppFailure("Desconecte antes de corrigir o perfil.")
        }
        let profile: OpenVPNProfile
        do { profile = try OpenVPNProfile.validated(try profiles.read(connection.id)) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
        guard OpenVPNCompatibility.digestFix(for: profile) == fix else { throw AppFailure("A correção sugerida não se aplica mais a este perfil.") }
        try profiles.write(OpenVPNCompatibility.apply(fix, to: profile).text, id: connection.id)
        manager.session(connection.id).digestFix = nil
        connect(connection)
    }
    func connect(_ connection: Connection, retrying: Bool = false) {
        if !retrying { onUserConnect?() }
        do {
            guard !manager.session(connection.id).authenticationRejected else {
                throw AppFailure("A última autenticação foi recusada. Edite a conexão e confirme as credenciais antes de tentar novamente, para evitar bloquear o usuário.")
            }
            let password = connection.usesPassword ? try passwords.read(connection.id) : nil
            if connection.usesPassword && (password?.isEmpty ?? true) {
                throw AppFailure("Senha não encontrada no Keychain. Edite a conexão e salve a senha novamente.")
            }
            var profile: String?
            if connection.isOpenVPN {
                guard let profiles else { throw AppFailure("Pasta de perfis indisponível.") }
                profile = try profiles.read(connection.id)
            }
            if connection.isWireGuard {
                guard let wireGuardProfiles else { throw AppFailure("Pasta de perfis indisponível.") }
                profile = try wireGuardProfiles.read(connection.id)
            }
            // Fail locally instead of looping on a service that cannot run the session.
            if service.blockNewSessions { throw AppFailure("O serviço está sendo removido ou atualizado; novas conexões aguardam.") }
            if manager.harness == nil, let reason = service.unavailableReason(for: connection.kind.runtime) { throw AppFailure(reason) }
            manager.connect(connection, password: password, retrying: retrying, profile: profile)
        } catch {
            if retrying { manager.retryFailed(connection.id, message: error.localizedDescription) }
            self.error = error.localizedDescription
        }
    }
}

/// Who asked AppKit to quit, read from the quit Apple event being handled. Sair and ⌘Q
/// call terminate directly and carry no event.
struct QuitRequest: Equatable {
    /// Bundle id of the sending app; nil for command-line tools (osascript, brew).
    var senderBundleID: String?
    /// Logout, restart or shutdown.
    var hasSystemReason: Bool

    /// Apps whose quit is always a user's or the system's request.
    static let trustedSenders: Set<String> = ["com.apple.dock", "com.apple.loginwindow", "com.apple.ActivityMonitor",
                                              "com.apple.systemevents", "com.apple.ScriptEditor2", "com.apple.Terminal"]

    /// A quit sent by another app while only the menu bar icon is left: that is a
    /// window-based auto quit, not the user leaving TunnelMac.
    func isAutomaticQuit(menuBarIcon: Bool, windowVisible: Bool) -> Bool {
        guard menuBarIcon, !windowVisible, !hasSystemReason, let senderBundleID else { return false }
        return !Self.trustedSenders.contains(senderBundleID)
    }

    @MainActor static func current() -> QuitRequest? {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventClass == AEEventClass(kCoreEventClass), event.eventID == AEEventID(kAEQuitApplication),
              let pid = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))?.int32Value,
              pid != ProcessInfo.processInfo.processIdentifier else { return nil }
        return QuitRequest(senderBundleID: NSRunningApplication(processIdentifier: pid)?.bundleIdentifier,
                           hasSystemReason: event.paramDescriptor(forKeyword: AEKeyword(kAEQuitReason)) != nil)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var model: AppModel?
    var menuBar: MenuBarCoordinator?
    // Injectable for local checks; production asks with an alert and replies to AppKit.
    var confirmTermination: () -> Bool = AppDelegate.askToDisconnect
    var replyToTermination: (Bool) -> Void = { ok in
        DispatchQueue.main.async { NSApp.reply(toApplicationShouldTerminate: ok) }
    }
    private var awaitingTermination = false
    static weak var current: AppDelegate? // NSApp.delegate is SwiftUI's own adaptor.
    func attach(model: AppModel, menuBar: MenuBarCoordinator) {
        AppDelegate.current = self
        self.model = model
        self.menuBar = menuBar
    }
    // The red button only hides the main window: the app, the menu bar and the tunnels
    // stay as they are. Quitting is done by Sair, ⌘Q or the system.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if let menuBar { menuBar.hideMainWindow(sender) }
        else { sender.orderOut(nil) }
        return false
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        terminationReply(request: QuitRequest.current())
    }
    func terminationReply(request: QuitRequest? = nil) -> NSApplication.TerminateReply {
        // Utilities that quit apps without windows (e.g. Vorssaint's auto quit) would take
        // the menu bar icon with them; the user quits with Sair, ⌘Q, the Dock or a script.
        if let request, let menuBar, request.isAutomaticQuit(menuBarIcon: menuBar.preferences.showMenuBarIcon,
                                                              windowVisible: menuBar.mainWindow?.isVisible == true) {
            return .terminateCancel
        }
        guard let model, model.manager.anyActive else { return .terminateNow }
        if awaitingTermination { return .terminateLater }
        guard confirmTermination() else { return .terminateCancel }
        awaitingTermination = true
        model.manager.changed = { [weak self] in
            guard let self, self.awaitingTermination, !model.manager.anyActive else { return }
            self.awaitingTermination = false
            self.replyToTermination(true)
        }
        model.manager.disconnectAll()
        return .terminateLater
    }
    private static func askToDisconnect() -> Bool {
        NSApp.activate(ignoringOtherApps: true) // The window may be hidden; keep the alert visible.
        let alert = NSAlert()
        alert.messageText = "Desconectar e sair?"
        alert.informativeText = "Há conexões ativas, em andamento ou com reconexão agendada. O app aguardará o encerramento e a limpeza das VPNs antes de sair."
        alert.addButton(withTitle: "Desconectar e sair")
        alert.addButton(withTitle: "Cancelar")
        return alert.runModal() == .alertFirstButtonReturn
    }
    // Only the local checks runner quits with its window; the app stays in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { MenuBarCoordinator.isLocalChecks }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard let menuBar, menuBar.mainWindow != nil else { return true } // SwiftUI recreates the window.
        menuBar.showMainWindow()
        return false
    }
}

@main
struct VPNGUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model: AppModel
    @StateObject private var menuBar: MenuBarCoordinator
    @StateObject private var preferences: AppPreferences
    init() {
        if CommandLine.arguments.contains("--release-checks") { exit(ReleaseTests.run()) }
        if CommandLine.arguments.contains(where: [Maintenance.argument, Maintenance.legacyMigrationArgument].contains) {
            exit(Maintenance.run())
        }
        signal(SIGPIPE, SIG_IGN) // A closed control socket returns EPIPE instead of terminating the app.
        if CommandLine.arguments.contains("--self-test") { exit(SelfTests.run()) }
        // One AppModel (and VPNManager) shared by the window and the menu bar.
        let model = UIReviewFixture.enabled ? UIReviewFixture.makeModel() : AppModel()
        model.service.refresh() // Read-only: registration status and authenticated handshake.
        let preferences = AppPreferences.forCurrentProcess()
        let updates = UpdateChecker.production(preferences: preferences)
        let menuBar = MenuBarCoordinator(model: model, preferences: preferences, updates: updates,
                                         loginItem: .production())
        // NSApp does not exist yet inside App.init; with the menu bar icon off, applying the
        // Dock policy here crashed at launch (0.3.0-rc.4 to 0.5.0). Apply it once AppKit runs.
        DispatchQueue.main.async { menuBar.enforceVisibility() }
        if !MenuBarCoordinator.isLocalChecks && !UIReviewFixture.enabled {
            model.onUserConnect = { [weak updates] in updates?.checkIfDue() }
            // After the interface is ready; the request runs in the background.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak updates] in
                updates?.checkOnLaunch()
                updates?.startTimer()
            }
        }
        _model = StateObject(wrappedValue: model)
        _menuBar = StateObject(wrappedValue: menuBar)
        _preferences = StateObject(wrappedValue: preferences)
    }
    var body: some Scene {
        WindowGroup("TunnelMac · \(HelperConstants.version)", id: MenuBarCoordinator.sceneID) {
            if MenuBarCoordinator.isLocalChecks {
                LocalTestsView()
            } else {
                UIReviewContent(model: model, menuBar: menuBar)
                    .frame(minWidth: 850, minHeight: 550)
                    .onAppear { delegate.attach(model: model, menuBar: menuBar) }
                    .background(WindowCloseGuard(delegate: delegate, menuBar: menuBar))
            }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            AppCommands(menuBar: menuBar)
        }
        Window("Configurações", id: MenuBarCoordinator.settingsSceneID) {
            SettingsView(menuBar: menuBar)
                .background(SettingsWindowBinding(menuBar: menuBar))
        }
        .defaultSize(width: 760, height: 540)
        // Not inserted in the local checks runner, so it still quits on its own.
        MenuBarExtra(isInserted: preferences.menuBarIconBinding(enabled: !MenuBarCoordinator.isLocalChecks)) {
            MenuBarView(menuBar: menuBar)
        } label: {
            MenuBarLabel(menuBar: menuBar)
                .onAppear { delegate.attach(model: model, menuBar: menuBar) }
        }
        .menuBarExtraStyle(.window)
    }
}

/// App menu: Sobre, Verificar atualizações…, separator, Configurações… ⌘,
struct AppCommands: Commands {
    let menuBar: MenuBarCoordinator
    @Environment(\.openWindow) private var openWindow
    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button("Verificar atualizações…") {
                register()
                menuBar.checkForUpdates()
            }
        }
        CommandGroup(replacing: .appSettings) {
            Button("Configurações…") {
                register()
                menuBar.showSettings()
            }
            .keyboardShortcut(",", modifiers: .command)
        }
    }
    private func register() {
        let open = openWindow
        if menuBar.openSettingsFallback == nil {
            menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
        }
    }
}

/// Registers the Configurações window (single instance) so reopening brings it forward
/// and closing applies the Dock rule.
struct SettingsWindowBinding: NSViewRepresentable {
    let menuBar: MenuBarCoordinator
    func makeNSView(context: Context) -> SettingsWindowView { SettingsWindowView(menuBar: menuBar) }
    func updateNSView(_ view: SettingsWindowView, context: Context) { view.bind() }
}

final class SettingsWindowView: NSView {
    private let menuBar: MenuBarCoordinator
    init(menuBar: MenuBarCoordinator) {
        self.menuBar = menuBar
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { nil }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        bind()
    }
    func bind() {
        guard let window, menuBar.settingsWindow !== window else { return }
        window.identifier = MenuBarCoordinator.settingsWindowIdentifier
        window.tabbingMode = .disallowed
        window.minSize = NSSize(width: 640, height: 440)
        menuBar.settingsWindow = window
    }
}

// Closing hides the main window; registers it (by reference, not title) for reopening.
struct WindowCloseGuard: NSViewRepresentable {
    let delegate: AppDelegate
    let menuBar: MenuBarCoordinator
    func makeNSView(context: Context) -> MainWindowBinding {
        MainWindowBinding(delegate: delegate, menuBar: menuBar)
    }
    func updateNSView(_ view: MainWindowBinding, context: Context) {
        view.bindWindow()
    }
}

/// SwiftUI can attach a representable to its window after updateNSView has run,
/// and may replace the window delegate. Bind at attachment and give the red
/// button its own hide action so it never depends on SwiftUI's close handling.
final class MainWindowBinding: NSView {
    private let appDelegate: AppDelegate
    private let menuBar: MenuBarCoordinator
    private var closeDelegate: MainWindowCloseDelegate?

    init(delegate: AppDelegate, menuBar: MenuBarCoordinator) {
        self.appDelegate = delegate
        self.menuBar = menuBar
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { nil }


    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        bindWindow()
    }

    func bindWindow() {
        guard let window else { return }
        appDelegate.attach(model: menuBar.model, menuBar: menuBar)
        // Keep SwiftUI's own delegate for layout, toolbar and resizing callbacks.
        if window.delegate !== closeDelegate || closeDelegate == nil {
            let proxy = MainWindowCloseDelegate(appDelegate: appDelegate, original: window.delegate)
            closeDelegate = proxy
            window.delegate = proxy
        }
        window.identifier = MenuBarCoordinator.windowIdentifier
        menuBar.mainWindow = window
        if let closeButton = window.standardWindowButton(.closeButton) {
            closeButton.target = self
            closeButton.action = #selector(hideWindow(_:))
        }
    }

    @objc private func hideWindow(_ sender: Any?) {
        guard let window else { return }
        menuBar.hideMainWindow(window)
    }
}

/// Intercept only close, forwarding all other optional NSWindowDelegate methods
/// to the delegate installed by SwiftUI.
final class MainWindowCloseDelegate: NSObject, NSWindowDelegate {
    private weak var appDelegate: AppDelegate?
    private weak var original: NSWindowDelegate?
    init(appDelegate: AppDelegate, original: NSWindowDelegate?) {
        self.appDelegate = appDelegate
        self.original = original
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        appDelegate?.windowShouldClose(sender) ?? false
    }
    override func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || original?.responds(to: selector) == true
    }
    override func forwardingTarget(for selector: Selector!) -> Any? {
        if original?.responds(to: selector) == true { return original }
        return super.forwardingTarget(for: selector)
    }
}

struct LocalTestsView: View {
    @State private var result: Int32?
    @State private var started = false
    var body: some View {
        VStack(spacing: 16) {
            Text(result == nil ? "Executando verificações locais…" : result == 0 ? "Verificações locais concluídas: 0 falhas" : "As verificações locais encontraram falhas")
                .font(.headline)
            Text("Resultado em TestResults.txt, ao lado deste executor. Nenhuma VPN é acessada.")
            Button("Fechar") { NSApp.terminate(nil) }.disabled(result == nil)
        }.padding(30).frame(width: 550)
            .onAppear {
                guard !started else { return }
                started = true
                // A run-loop block, not a main-queue block: the checks spin the run loop to
                // receive XPC replies, and GCD does not drain the main queue re-entrantly.
                RunLoop.main.perform(inModes: [.default]) {
                    let report = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("TestResults.txt")
                    freopen(report.path, "w", stdout)
                    freopen(report.path + ".stderr", "w", stderr)
                    MainActor.assumeIsolated {
                        result = SelfTests.run()
                        fflush(stdout)
                        if CommandLine.arguments.contains("--headless") { NSApp.terminate(nil) }
                    }
                }
            }
    }
}
