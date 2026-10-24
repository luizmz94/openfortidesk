import SwiftUI
import AppKit
import VPNHelperShared

struct MainView: View {
    @ObservedObject var model: AppModel
    let menuBar: MenuBarCoordinator
    @ObservedObject private var updates: UpdateChecker
    @State private var selected: UUID?
    @State private var editing: Connection?
    @State private var pendingImport: OpenVPNImport?
    @State private var deleting: Connection?
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(model: AppModel, menuBar: MenuBarCoordinator) {
        _model = ObservedObject(wrappedValue: model)
        self.menuBar = menuBar
        _updates = ObservedObject(wrappedValue: menuBar.updates)
    }

    var body: some View {
        HSplitView {
            sidebar
                .frame(minWidth: 260, idealWidth: 300, maxWidth: 400, maxHeight: .infinity)
                .background(.regularMaterial)
                .navigationTitle("Conexões")
                .toolbar {
                    ToolbarItem {
                        Button { importOpenVPN() } label: { Label("Importar perfil OpenVPN", systemImage: "square.and.arrow.down") }
                            .help("Importar perfil OpenVPN: .ovpn, .conf ou pasta .visc (⌘I)")
                            .keyboardShortcut("i")
                            .disabled(!model.ready)
                    }
                    ToolbarItem {
                        Button { editing = Connection() } label: { Label("Nova conexão Fortinet", systemImage: "plus") }
                            .help("Nova conexão Fortinet SSL VPN (⌘N)")
                            .keyboardShortcut("n")
                            .disabled(!model.ready)
                    }
                }

            VStack(spacing: 0) {
                if updates.showsCard, let offer = updates.offer {
                    UpdateCard(offer: offer, update: { menuBar.showSettings(.updates) },
                               later: { updates.postpone() })
                        .padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 2)
                        .transition(reduceMotion ? .opacity : .move(edge: .top).combined(with: .opacity))
                }
                detail
            }
            .animation(Motion.state(reduceMotion), value: updates.showsCard)
            .frame(minWidth: 530, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            let open = openWindow
            if menuBar.openSettingsFallback == nil {
                menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            // Back from System Settings: read the real status again (approval or revocation).
            if !model.service.busy { model.service.refresh() }
        }
        .sheet(item: $editing, onDismiss: { pendingImport = nil }) { connection in
            ConnectionEditor(model: model, connection: connection, pendingImport: pendingImport) { selected = connection.id }
        }
        .alert("Erro", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .alert(deleting.map { "Excluir “\($0.name)”?" } ?? "Excluir conexão?",
               isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("Cancelar", role: .cancel) { deleting = nil }
            Button("Excluir", role: .destructive) {
                if let deleting {
                    do { try model.delete(deleting); if selected == deleting.id { selected = nil } }
                    catch { model.error = error.localizedDescription }
                }
                deleting = nil
            }
        } message: {
            Text(deleting?.isOpenVPN == true
                 ? "O cadastro, a senha salva e a cópia privada do perfil OpenVPN serão removidos. O arquivo original não é alterado."
                 : "O cadastro, a senha salva e a sessão SAML guardada serão removidos.")
        }
        .onReceive(menuBar.$pendingSelection) { id in
            // Selection requested by the menu bar (review access or certificate).
            guard let id else { return }
            DispatchQueue.main.async {
                if model.data.connections.contains(where: { $0.id == id }) { selected = id }
                menuBar.pendingSelection = nil
            }
        }
    }

    /// Reads the chosen profile; the editor shows what was found and saves only on Adicionar.
    private func importOpenVPN() {
        guard let url = OpenVPNImportPanel.choose() else { return }
        do {
            let imported = try OpenVPNImporter.load(url)
            pendingImport = imported
            editing = Connection(name: imported.name, server: "", port: imported.profile.remotes.first?.port ?? 1194,
                                 username: imported.username, kind: .openvpn, openVPN: imported.summary)
        } catch { model.error = error.localizedDescription }
    }

    // MARK: Sidebar

    private var sidebar: some View {
        List(selection: $selected) {
            ForEach(model.data.connections) { connection in
                let session = model.manager.session(connection.id)
                ConnectionRow(connection: connection, session: session, model: model,
                              showsServer: true, edit: { editing = connection })
                    .tag(connection.id)
                    .contextMenu { contextMenu(for: connection, session: session) }
            }
        }
        .listStyle(.sidebar)
        .onDeleteCommand {
            guard let connection = model.data.connections.first(where: { $0.id == selected }),
                  !model.manager.session(connection.id).state.active else { return }
            deleting = connection
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            ServiceStatusRow(service: model.service) { menuBar.showServiceManagement() }
                .padding(.horizontal, 10).padding(.bottom, 10).padding(.top, 4)
        }
    }

    @ViewBuilder private func contextMenu(for connection: Connection, session: Session) -> some View {
        let action = MenuBarRowAction.of(session, ready: model.ready, serviceReady: model.service.canConnect)
        Button(action.title) { primaryAction(action, connection) }.disabled(!action.enabled)
        if !session.state.active, session.suggestedCertificate != nil {
            Button("Conferir certificado…") { selected = connection.id }
        }
        Divider()
        Button("Editar…") { editing = connection }.disabled(session.state.active)
        Button("Limpar logs") { session.clearLogs() }.disabled(session.logs.isEmpty)
        Divider()
        Button("Excluir…", role: .destructive) { deleting = connection }.disabled(session.state.active)
    }

    private func primaryAction(_ action: MenuBarRowAction, _ connection: Connection) {
        switch action {
        case .connect: model.connect(connection)
        case .disconnect: model.manager.disconnect(connection.id)
        case .review: editing = connection
        case .disconnecting, .unavailable: break
        }
    }

    // MARK: Detail

    @ViewBuilder private var detail: some View {
        if let connection = model.data.connections.first(where: { $0.id == selected }) {
            ConnectionDetail(connection: connection, session: model.manager.session(connection.id), model: model,
                             edit: { editing = connection }, delete: { deleting = connection },
                             manageService: { menuBar.showServiceManagement() })
                .id(connection.id)
        } else if !model.ready {
            EmptyStateView(symbol: "exclamationmark.triangle", title: "Não foi possível carregar as conexões",
                           message: (model.error ?? "O arquivo existente foi preservado.") + " As ações de conexão ficam indisponíveis até o problema ser resolvido.",
                           tone: .warning)
        } else if model.data.connections.isEmpty {
            EmptyStateView(symbol: "network.badge.shield.half.filled", title: "Nenhuma conexão cadastrada",
                           message: "Cadastre um gateway Fortinet ou importe um perfil OpenVPN para conectar por aqui ou pela barra de menus.") {
                HStack(spacing: 10) {
                    Button { editing = Connection() } label: { Label("Nova conexão Fortinet", systemImage: "plus") }
                        .adaptiveButtonStyle(prominent: true)
                    Button { importOpenVPN() } label: { Label("Importar perfil OpenVPN…", systemImage: "square.and.arrow.down") }
                        .adaptiveButtonStyle()
                }
                .controlSize(.large)
            }
        } else {
            EmptyStateView(symbol: "sidebar.left", title: "Selecione uma conexão",
                           message: "Os detalhes, as ações e os logs aparecem aqui.")
        }
    }
}

// MARK: - Sidebar row

struct ConnectionRow: View {
    let connection: Connection
    @ObservedObject var session: Session
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    let showsServer: Bool
    let edit: () -> Void
    @State private var hovering = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(connection: Connection, session: Session, model: AppModel, showsServer: Bool = true, edit: @escaping () -> Void) {
        self.connection = connection; self.edit = edit; self.showsServer = showsServer
        _session = ObservedObject(wrappedValue: session); _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
    }

    private var action: MenuBarRowAction {
        MenuBarRowAction.of(session, ready: model.ready, serviceReady: service.canConnect)
    }

    var body: some View {
        HStack(spacing: 10) {
            StatusSymbol(symbol: session.state.symbol, tone: session.state.tone,
                         pulsing: session.state.inProgress, size: 14)
            VStack(alignment: .leading, spacing: 2) {
                Text(connection.name).font(.body.weight(.medium)).lineLimit(1).truncationMode(.tail)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .help("\(connection.name) — \(connection.kind.title) · \(connection.endpoint)")
            Spacer(minLength: 4)
            trailing
        }
        .padding(.vertical, 5)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(Motion.state(reduceMotion), value: session.state)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(connection.name), \(session.state.rawValue)")
        .accessibilityAction(named: Text(action.title)) { perform() }
    }

    private var subtitle: String {
        if session.state.active && session.state != .connected { return session.state.rawValue }
        if session.authenticationRejected { return "Autenticação recusada" }
        if session.state == .failed { return "Falha · \(connection.endpoint)" }
        return showsServer ? connection.endpoint : session.state.rawValue
    }

    @ViewBuilder private var trailing: some View {
        if hovering && action.enabled {
            Button(action: perform) {
                Image(systemName: action == .disconnect ? "stop.fill" : action == .review ? "person.crop.circle.badge.exclamationmark" : "play.fill")
                    .font(.system(size: 10, weight: .bold))
                    .frame(width: 22, height: 22)
            }
            .buttonStyle(.borderless)
            .background(Circle().fill(Color.primary.opacity(0.08)))
            .help(action.title)
            .accessibilityLabel("\(action.title) \(connection.name)")
            .transition(.opacity)
        } else if let start = session.connectedAt, session.state == .connected {
            ElapsedTime(start: start).font(.caption).foregroundStyle(.secondary)
        } else if session.state.inProgress {
            ProgressView().controlSize(.small).scaleEffect(0.7).frame(width: 16, height: 16)
                .accessibilityHidden(true)
        }
    }

    private func perform() {
        switch action {
        case .connect: model.connect(connection)
        case .disconnect: model.manager.disconnect(connection.id)
        case .review: edit()
        case .disconnecting, .unavailable: break
        }
    }
}

// MARK: - Detail

struct ConnectionDetail: View {
    let connection: Connection
    @ObservedObject var session: Session
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    let edit: () -> Void
    let delete: () -> Void
    let manageService: () -> Void
    @State private var certificateToTrust: String?
    @State private var confirmingDigestFix: OpenVPNCompatibility.DigestFix?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(connection: Connection, session: Session, model: AppModel, edit: @escaping () -> Void,
         delete: @escaping () -> Void, manageService: @escaping () -> Void = {}) {
        self.connection = connection; self.edit = edit; self.delete = delete; self.manageService = manageService
        _session = ObservedObject(wrappedValue: session); _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
    }

    private var action: MenuBarRowAction {
        MenuBarRowAction.of(session, ready: model.ready, serviceReady: service.canConnect)
    }

    var body: some View {
        GeometryReader { geometry in
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 18) {
                    header
                    actions
                    notices
                    facts
                    logs
                }
                .padding(.horizontal, 28).padding(.top, 22).padding(.bottom, 24)
                .frame(maxWidth: .infinity, minHeight: geometry.size.height, alignment: .topLeading)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .animation(Motion.state(reduceMotion), value: session.state)
        .animation(Motion.state(reduceMotion), value: session.suggestedCertificate)
        .sheet(item: Binding(get: { certificateToTrust.map(CertificateDigest.init) },
                             set: { certificateToTrust = $0?.value })) { digest in
            CertificateTrustSheet(connection: connection, digest: digest.value) {
                do { try model.trustCertificate(connection, digest: digest.value) }
                catch { model.error = error.localizedDescription }
            }
        }
        .confirmationDialog(confirmingDigestFix.map { "Trocar auth \($0.from) por \($0.to)?" } ?? "",
                            isPresented: Binding(get: { confirmingDigestFix != nil }, set: { if !$0 { confirmingDigestFix = nil } })) {
            Button("Corrigir e reconectar") {
                if let fix = confirmingDigestFix {
                    do { try model.applyDigestFix(connection, fix) } catch { model.error = error.localizedDescription }
                }
                confirmingDigestFix = nil
            }
            Button("Cancelar", role: .cancel) { confirmingDigestFix = nil }
        } message: {
            Text("auth define o HMAC dos pacotes e precisa coincidir com o servidor. \(confirmingDigestFix?.from ?? "") é um nome de assinatura que o OpenVPN 2.7 não aceita nessa diretiva; \(confirmingDigestFix?.to ?? "") é o equivalente usual. Só a cópia do perfil no app muda.")
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text(connection.name).font(.title2.weight(.semibold)).lineLimit(2).truncationMode(.tail)
                    .textSelection(.enabled)
                    .accessibilityAddTraits(.isHeader)
                StatePill(state: session.state, connectedAt: session.connectedAt)
            }
            Spacer(minLength: 0)
        }
    }

    private var actions: some View {
        GlassGroup(spacing: 10) {
            HStack(spacing: 10) {
                primaryButton
                Button(action: edit) { Label("Editar…", systemImage: "pencil") }
                    .adaptiveButtonStyle()
                    .disabled(session.state.active)
                    .help(session.state.active ? "Desconecte antes de editar" : "Editar esta conexão")
                Button(role: .destructive, action: delete) { Label("Excluir…", systemImage: "trash") }
                    .adaptiveButtonStyle()
                    .disabled(session.state.active)
                    .help(session.state.active ? "Desconecte antes de excluir" : "Excluir esta conexão")
            }
            .controlSize(.large)
        }
    }

    @ViewBuilder private var primaryButton: some View {
        let button = Button {
            switch action {
            case .connect: model.connect(connection)
            case .disconnect: model.manager.disconnect(connection.id)
            case .review: edit()
            case .disconnecting, .unavailable: break
            }
        } label: {
            Label(action.title, systemImage: primarySymbol).frame(minWidth: 112)
        }
        .disabled(!action.enabled)
        switch action {
        case .disconnect, .disconnecting: button.adaptiveButtonStyle()
        case .review: button.adaptiveButtonStyle(prominent: true).tint(.orange)
        case .connect, .unavailable: button.adaptiveButtonStyle(prominent: true)
        }
    }

    private var primarySymbol: String {
        switch action {
        case .connect, .unavailable: return "bolt.fill"
        case .disconnect: return "stop.fill"
        case .disconnecting: return "hourglass"
        case .review: return "person.crop.circle.badge.exclamationmark"
        }
    }

    @ViewBuilder private var notices: some View {
        if !session.state.active, let fix = session.digestFix {
            InlineNotice(tone: .warning, symbol: "wrench.and.screwdriver",
                         title: "O OpenVPN recusou auth \(fix.from)",
                         message: "Nada foi alterado. O app pode trocar para auth \(fix.to) na cópia do perfil, se o servidor usar esse algoritmo.") {
                Button("Corrigir perfil…") { confirmingDigestFix = fix }
            }
            .transition(.opacity)
        }
        if !session.state.active, let digest = session.suggestedCertificate {
            InlineNotice(tone: .warning, symbol: "lock.trianglebadge.exclamationmark",
                         title: "O certificado do servidor precisa ser conferido",
                         message: "Nada é aceito automaticamente. Compare o SHA-256 com o administrador antes de confiar.") {
                Button("Conferir certificado…") { certificateToTrust = digest }
            }
            .transition(.opacity)
        }
        if session.authenticationRejected, !session.state.active {
            InlineNotice(tone: .danger, symbol: "person.crop.circle.badge.xmark",
                         title: "A última autenticação foi recusada",
                         message: "Confira o usuário e a senha antes de tentar de novo, para evitar o bloqueio da conta.")
                .transition(.opacity)
        } else if session.state == .failed, session.suggestedCertificate == nil {
            InlineNotice(tone: .danger, symbol: "xmark.octagon", title: "A última tentativa falhou",
                         message: "Os detalhes estão nos logs abaixo.")
                .transition(.opacity)
        }
        if !session.state.active && !service.canConnect {
            InlineNotice(tone: service.health.tone == .danger ? .danger : .warning, symbol: service.health.symbol,
                         title: "Conectar fica disponível quando o serviço privilegiado estiver pronto",
                         message: service.health.title) {
                Button("Gerenciar…", action: manageService)
            }
            .transition(.opacity)
        }
    }

    @ViewBuilder private var facts: some View {
        if connection.isOpenVPN { openVPNFacts } else { fortinetFacts }
    }

    private var openVPNFacts: some View {
        VStack(alignment: .leading, spacing: 10) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 7) {
                fact("Protocolo", "OpenVPN")
                fact("Servidores", (connection.openVPN?.remotes ?? []).map(\.display).joined(separator: ", "))
                fact("Usuário", connection.username.isEmpty ? "—" : connection.username)
                fact("Autenticação", connection.usesPassword ? "Certificado + usuário e senha" : "Certificado")
                if let source = connection.openVPN?.source, !source.isEmpty { fact("Importado de", source) }
            }
            .font(.callout)
            if let warnings = connection.openVPN?.warnings, !warnings.isEmpty {
                DisclosureGroup("Avisos da importação (\(warnings.count))") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(warnings, id: \.self) { Text("• " + $0).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
                }
                .font(.callout)
            }
        }
    }

    private var fortinetFacts: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 7) {
            fact("Servidor", "\(connection.server):\(String(connection.port))")
            fact("Usuário", connection.username.isEmpty ? "—" : connection.username)
            fact("Autenticação", connection.authentication.title)
            fact("Certificado", connection.trustedCertificate.isEmpty
                 ? "Validação padrão do sistema"
                 : "SHA-256 fixado · …\(connection.trustedCertificate.suffix(12))")
        }
        .font(.callout)
    }

    private func fact(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }

    private var logs: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text("Logs").font(.headline).accessibilityAddTraits(.isHeader)
                if !session.logs.isEmpty {
                    Text(session.logs.count == 1 ? "1 linha" : "\(session.logs.count) linhas")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer()
                Button { session.clearLogs() } label: { Label("Limpar", systemImage: "trash") }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .help("Limpar logs desta conexão")
                    .accessibilityLabel("Limpar logs desta conexão")
                    .disabled(session.logs.isEmpty)
            }
            LogConsole(lines: session.logs)
                .frame(minHeight: 120, maxHeight: .infinity)
        }
    }
}

private struct CertificateDigest: Identifiable {
    let value: String
    var id: String { value }
}

/// Explicit review of the digest the server presented. Cancel is the default and the
/// keyboard shortcut; trusting needs a deliberate click.
struct CertificateTrustSheet: View {
    let connection: Connection
    let digest: String
    let trust: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 16) {
                SheetHeader(symbol: "lock.trianglebadge.exclamationmark", tone: .warning,
                            title: "Confiar neste certificado?", subtitle: "\(connection.server):\(String(connection.port))")
                VStack(alignment: .leading, spacing: 6) {
                    Text("SHA-256 apresentado pelo servidor").font(.callout.weight(.medium))
                    Text(Self.grouped(digest))
                        .font(.system(.body, design: .monospaced))
                        .lineSpacing(3)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .contentPanel(cornerRadius: 8)
                        .accessibilityLabel("Digest SHA-256: \(digest)")
                }
                if !connection.trustedCertificate.isEmpty {
                    InlineNotice(tone: .warning, symbol: "arrow.triangle.swap",
                                 title: "Este digest substituirá o certificado confiável já cadastrado.")
                }
                Text("Confira o digest com o administrador por um canal confiável. Ao confirmar, ele será salvo nesta conexão e uma nova tentativa será iniciada.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(22)
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Confiar e reconectar") { trust(); dismiss() }
                    .adaptiveButtonStyle(prominent: true)
            }
        }
        .frame(width: 520)
    }

    /// Groups of 8 hex digits, 4 per line, for comparison by eye. Copying keeps the spaces.
    static func grouped(_ digest: String) -> String {
        let chars = Array(digest)
        let groups = stride(from: 0, to: chars.count, by: 8).map { String(chars[$0..<min($0 + 8, chars.count)]) }
        return stride(from: 0, to: groups.count, by: 4)
            .map { groups[$0..<min($0 + 4, groups.count)].joined(separator: " ") }
            .joined(separator: "\n")
    }
}
