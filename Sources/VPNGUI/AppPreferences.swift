import Foundation
import SwiftUI
import AppKit
import ServiceManagement
import VPNHelperShared

/// App preferences in the app's own UserDefaults. Nothing sensitive is stored here:
/// passwords and SAML cookies stay in the Keychain. Defaults keep the previous behavior.
@MainActor
final class AppPreferences: ObservableObject {
    enum Key {
        static let showMenuBarIcon = "showMenuBarIcon"
        static let hideDockOnClose = "hideDockOnClose"
        static let checkForUpdates = "checkForUpdatesAutomatically"
        static let includePrereleases = "includePrereleaseUpdates"
        static let skippedVersion = "skippedUpdateVersion"
        static let lastUpdateAttempt = "lastUpdateCheckAttempt"
        static let lastUpdateSuccess = "lastUpdateCheckSuccess"
        static let cachedOffer = "pendingUpdateOffer"
    }

    let defaults: UserDefaults
    /// Suite removed when this object goes away (local checks only).
    private let disposableSuite: String?

    @Published var showMenuBarIcon: Bool { didSet { defaults.set(showMenuBarIcon, forKey: Key.showMenuBarIcon) } }
    /// Stored choice; `hidesDockOnClose` is what the app applies.
    @Published var hideDockOnClose: Bool { didSet { defaults.set(hideDockOnClose, forKey: Key.hideDockOnClose) } }
    @Published var checkForUpdates: Bool { didSet { defaults.set(checkForUpdates, forKey: Key.checkForUpdates) } }
    @Published var includePrereleases: Bool { didSet { defaults.set(includePrereleases, forKey: Key.includePrereleases) } }
    @Published var skippedVersion: String? { didSet { store(skippedVersion, Key.skippedVersion) } }
    @Published var lastUpdateAttempt: Date? { didSet { store(lastUpdateAttempt, Key.lastUpdateAttempt) } }
    @Published var lastUpdateSuccess: Date? { didSet { store(lastUpdateSuccess, Key.lastUpdateSuccess) } }

    init(defaults: UserDefaults, disposableSuite: String? = nil,
         currentVersion: String = HelperConstants.releaseVersion) {
        self.defaults = defaults
        self.disposableSuite = disposableSuite
        showMenuBarIcon = defaults.object(forKey: Key.showMenuBarIcon) as? Bool ?? true
        hideDockOnClose = defaults.object(forKey: Key.hideDockOnClose) as? Bool ?? true
        checkForUpdates = defaults.object(forKey: Key.checkForUpdates) as? Bool ?? true
        // Testers of a release candidate keep receiving candidates; stable users do not.
        includePrereleases = defaults.object(forKey: Key.includePrereleases) as? Bool
            ?? (ReleaseVersion(currentVersion)?.isPrerelease ?? false)
        skippedVersion = defaults.string(forKey: Key.skippedVersion)
        lastUpdateAttempt = defaults.object(forKey: Key.lastUpdateAttempt) as? Date
        lastUpdateSuccess = defaults.object(forKey: Key.lastUpdateSuccess) as? Date
    }

    deinit {
        if let disposableSuite { UserDefaults.standard.removePersistentDomain(forName: disposableSuite) }
    }

    /// Real preferences in the app; an isolated, disposable suite in the local checks runner.
    static func forCurrentProcess() -> AppPreferences {
        if MenuBarCoordinator.isLocalChecks || UIReviewFixture.enabled { return disposable() }
        return AppPreferences(defaults: .standard)
    }

    /// Isolated suite that never touches the user's preferences and is deleted afterwards.
    static func disposable(currentVersion: String = HelperConstants.releaseVersion) -> AppPreferences {
        let name = "com.luiz.vpngui.tests.preferences.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        return AppPreferences(defaults: defaults, disposableSuite: name, currentVersion: currentVersion)
    }

    /// Binding for MenuBarExtra(isInserted:). SwiftUI writes the current value back while
    /// it builds the scenes; publishing that echo re-evaluated the App body, which wrote
    /// again, recursing until the stack overflowed (0.3.0-rc.4). Only real changes publish.
    func menuBarIconBinding(enabled: Bool = true) -> Binding<Bool> {
        Binding(get: { [weak self] in enabled && (self?.showMenuBarIcon ?? true) },
                set: { [weak self] value in
                    guard enabled, let self, self.showMenuBarIcon != value else { return }
                    self.showMenuBarIcon = value
                })
    }

    /// The app must never become invisible: without the menu bar icon it stays in the Dock.
    var hidesDockOnClose: Bool { showMenuBarIcon && hideDockOnClose }

    /// Last offer found, so the pending state survives a relaunch without a new request.
    var cachedOffer: UpdateOffer? {
        get { defaults.data(forKey: Key.cachedOffer).flatMap { try? JSONDecoder().decode(UpdateOffer.self, from: $0) } }
        set { store(newValue.flatMap { try? JSONEncoder().encode($0) }, Key.cachedOffer) }
    }

    private func store(_ value: Any?, _ key: String) {
        if let value { defaults.set(value, forKey: key) } else { defaults.removeObject(forKey: key) }
    }
}

// MARK: - Open at login

/// Login item API used by the controller. Production: SMAppService.mainApp.
@MainActor
protocol LoginItemService: AnyObject {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() throws
    func openSystemSettings()
}

@MainActor
final class MainAppLoginItem: LoginItemService {
    var status: SMAppService.Status { SMAppService.mainApp.status }
    func register() throws { try SMAppService.mainApp.register() }
    func unregister() throws { try SMAppService.mainApp.unregister() }
    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// "Abrir ao iniciar sessão". Reads the real registration state; never registers
/// anything in the local checks runner or in ad hoc builds.
@MainActor
final class LoginItemController: ObservableObject {
    @Published private(set) var status: SMAppService.Status = .notRegistered
    @Published var message: String?
    let unavailableReason: String?
    private let service: LoginItemService?

    init(service: LoginItemService?, unavailableReason: String? = nil) {
        self.service = service
        self.unavailableReason = service == nil ? (unavailableReason ?? "Indisponível neste build.") : unavailableReason
        refresh()
    }

    static func production() -> LoginItemController {
        if MenuBarCoordinator.isLocalChecks || UIReviewFixture.enabled {
            return LoginItemController(service: nil, unavailableReason: "Desativado no executor de verificações e na revisão visual.")
        }
        if case .unavailable = CodeTrust.localPolicy() {
            return LoginItemController(service: nil, unavailableReason: "Build sem assinatura Apple (ad hoc): use o app instalado pelo Homebrew.")
        }
        return LoginItemController(service: MainAppLoginItem())
    }

    var available: Bool { service != nil && unavailableReason == nil }
    var enabled: Bool { status == .enabled || status == .requiresApproval }

    func refresh() {
        guard available, let service else { return }
        status = service.status
    }

    func setEnabled(_ enable: Bool) {
        guard available, let service else { return }
        message = nil
        do {
            if enable { try service.register() } else { try service.unregister() }
        } catch {
            message = (enable ? "Não foi possível ativar: " : "Não foi possível desativar: ") + error.localizedDescription
        }
        status = service.status
    }

    func openSystemSettings() { service?.openSystemSettings() }

    var detail: String {
        if let unavailableReason { return unavailableReason }
        if let message { return message }
        switch status {
        case .enabled: return "Abre o TunnelMac quando você entra no Mac."
        case .requiresApproval: return "Aguardando aprovação em Ajustes do Sistema › Geral › Itens de Início."
        case .notFound: return "O macOS não encontrou o app para abrir ao iniciar. Instale-o em /Applications."
        default: return "Abre o TunnelMac quando você entra no Mac."
        }
    }
}
