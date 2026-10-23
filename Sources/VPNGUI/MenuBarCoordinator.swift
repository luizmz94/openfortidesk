import SwiftUI
import AppKit
import Combine

/// Aggregated state shown by the menu bar icon. An intermediate state never
/// counts as an established tunnel.
enum MenuBarSummary: Equatable {
    case idle, attention, transitioning, connected
    var symbol: String {
        switch self {
        case .idle: return "shield"
        case .attention: return "exclamationmark.shield"
        case .transitioning: return "shield.lefthalf.filled"
        case .connected: return "checkmark.shield.fill"
        }
    }
}

/// What the row button does for a session, using the same criteria as the window.
enum MenuBarRowAction: Equatable {
    case connect, disconnect, disconnecting, review, unavailable
    var title: String {
        switch self {
        case .connect, .unavailable: return "Conectar"
        case .disconnect: return "Desconectar"
        case .disconnecting: return "Desconectando…"
        case .review: return "Revisar acesso…"
        }
    }
    var enabled: Bool { ![.disconnecting, .unavailable].contains(self) }
    @MainActor static func of(_ session: Session, ready: Bool, serviceReady: Bool = true) -> MenuBarRowAction {
        guard ready else { return .unavailable }
        if session.state.active {
            return session.state == .disconnecting && session.wantsDisconnect ? .disconnecting : .disconnect
        }
        if session.authenticationRejected { return .review }
        return serviceReady ? .connect : .unavailable
    }
}

/// Observes the shared AppModel for the menu bar and routes actions to the model
/// or to the main window. It keeps no connection state of its own.
@MainActor
final class MenuBarCoordinator: ObservableObject {
    static let sceneID = "main"
    static let windowIdentifier = NSUserInterfaceItemIdentifier("com.luiz.vpngui.main-window")
    static var isLocalChecks: Bool { Bundle.main.bundleIdentifier?.hasPrefix("com.luiz.vpngui.local-checks") == true }

    let model: AppModel
    @Published var pendingSelection: UUID?
    /// Opens the service sheet once the main window is visible.
    @Published var pendingServiceSheet = false
    weak var mainWindow: NSWindow?
    var connectAction: (Connection) -> Void
    var disconnectAction: (UUID) -> Void
    var openWindowFallback: (() -> Void)?
    var activateApp: () -> Void = { NSApplication.shared.activate(ignoringOtherApps: true) }
    var setActivationPolicy: (NSApplication.ActivationPolicy) -> Void = { _ = NSApp.setActivationPolicy($0) }
    private var observers = Set<AnyCancellable>()
    private var sessionObservers: [AnyCancellable] = []

    init(model: AppModel) {
        self.model = model
        connectAction = { [unowned model] in model.connect($0) }
        disconnectAction = { [unowned model] in model.manager.disconnect($0) }
        model.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        model.service.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &observers)
        // A @Published change inside a Session does not publish the manager's dictionary,
        // so each session is observed individually. manager.changed stays untouched.
        model.manager.$sessions.sink { [weak self] sessions in
            self?.objectWillChange.send()
            self?.observe(Array(sessions.values))
        }.store(in: &observers)
    }

    private func observe(_ sessions: [Session]) {
        sessionObservers = sessions.map { session in
            Publishers.Merge4(session.$state.dropFirst().map { _ in () },
                              session.$connectedAt.dropFirst().map { _ in () },
                              session.$authenticationRejected.dropFirst().map { _ in () },
                              session.$suggestedCertificate.dropFirst().map { _ in () })
                .sink { [weak self] in self?.objectWillChange.send() }
        }
    }

    private var states: [ConnectionState] { model.manager.sessions.values.map(\.state) }
    var connectedCount: Int { states.filter { $0 == .connected }.count }
    var pendingCount: Int { states.filter { $0.active && $0 != .connected }.count }
    var summary: MenuBarSummary {
        if connectedCount > 0 { return .connected }
        if pendingCount > 0 { return .transitioning }
        if !model.ready || model.error != nil || states.contains(.failed) { return .attention }
        return .idle
    }
    var summaryText: String {
        guard model.ready else { return "Dados não carregados" }
        var parts: [String] = []
        let connected = connectedCount, pending = pendingCount
        if connected > 0 { parts.append(connected == 1 ? "1 conectada" : "\(connected) conectadas") }
        if pending > 0 { parts.append("\(pending) em andamento") }
        if parts.isEmpty { return states.contains(.failed) ? "Nenhuma conexão ativa · falha recente" : "Nenhuma conexão ativa" }
        return parts.joined(separator: " · ")
    }
    var accessibilityDescription: String {
        "OpenFortiDesk: \(summaryText)\(model.error != nil ? ", com erro pendente" : "")"
    }

    /// Names repeated in the list; only these rows show the server to tell them apart.
    var duplicatedNames: Set<String> {
        var seen = Set<String>(), repeated = Set<String>()
        for name in model.data.connections.map({ $0.name.lowercased() }) where !seen.insert(name).inserted { repeated.insert(name) }
        return repeated
    }

    func action(for connection: Connection) -> MenuBarRowAction {
        MenuBarRowAction.of(model.manager.session(connection.id), ready: model.ready, serviceReady: model.service.canConnect)
    }
    func showServiceManagement() {
        showMainWindow()
        pendingServiceSheet = true
    }

    /// Forwards exactly one action to the model. Review goes to the window.
    func perform(_ connection: Connection) {
        guard model.ready, let current = model.data.connections.first(where: { $0.id == connection.id }) else { return }
        switch action(for: current) {
        case .connect: connectAction(current)
        case .disconnect: disconnectAction(current.id)
        case .review: showMainWindow(selecting: current.id)
        case .disconnecting, .unavailable: break
        }
    }

    /// Shows the single main window, recreating it only if SwiftUI released it.
    func showMainWindow(selecting id: UUID? = nil) {
        if let id { pendingSelection = id }
        setActivationPolicy(.regular)
        activateApp()
        if let window = mainWindow {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        } else {
            openWindowFallback?()
        }
    }
    func hideMainWindow(_ window: NSWindow) {
        window.orderOut(nil)
        setActivationPolicy(.accessory)
    }
}
