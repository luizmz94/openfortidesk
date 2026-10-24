import SwiftUI
import AppKit
import VPNHelperShared

/// Open panel for OpenVPN profiles: a .ovpn/.conf file or a Viscosity .visc folder.
enum OpenVPNImportPanel {
    @MainActor static func choose() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Importar perfil OpenVPN"
        panel.message = "Escolha um arquivo .ovpn ou .conf, ou uma pasta .visc do Viscosity. Os arquivos originais não são alterados."
        panel.prompt = "Importar"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        return panel.runModal() == .OK ? panel.url : nil
    }
}

struct ConnectionEditor: View {
    @ObservedObject var model: AppModel
    @State var connection: Connection
    /// A profile just read from disk (new import or replacement); saved only on Adicionar/Salvar.
    @State var pendingImport: OpenVPNImport?
    var saved: () -> Void
    @State private var password = ""
    @State private var portText = ""
    @State private var error: String?
    @State private var loaded = false
    @State private var applyDigestFix = false
    @FocusState private var focus: Field?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(model: AppModel, connection: Connection, pendingImport: OpenVPNImport? = nil, saved: @escaping () -> Void) {
        _model = ObservedObject(wrappedValue: model)
        _connection = State(initialValue: connection)
        _pendingImport = State(initialValue: pendingImport)
        self.saved = saved
    }

    private enum Field: Hashable { case name, server, port, username, password, certificate }

    private var isNew: Bool { !model.data.connections.contains { $0.id == connection.id } }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: connection.isOpenVPN ? "doc.badge.gearshape" : "network.badge.shield.half.filled", tone: .neutral,
                        title: isNew ? (connection.isOpenVPN ? "Importar perfil OpenVPN" : "Nova conexão") : "Editar conexão",
                        subtitle: isNew ? connection.kind.title : "\(connection.name) · \(connection.kind.title)")
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            Form {
                if connection.isOpenVPN { openVPNSections } else { fortinetSections }
            }
            .formStyle(.grouped)
            .animation(Motion.state(reduceMotion), value: connection.authentication)
            if let error {
                InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error)
                    .padding(.horizontal, 20).padding(.bottom, 12)
                    .transition(.opacity)
            }
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(isNew ? "Adicionar" : "Salvar") { save() }
                    .keyboardShortcut(.defaultAction)
                    .adaptiveButtonStyle(prominent: true)
                    .disabled(!loaded)
            }
        }
        .frame(width: 560, height: connection.isOpenVPN ? 640 : 600)
        .animation(Motion.state(reduceMotion), value: error)
        .onChange(of: focus) { field in if field != .server && !connection.isOpenVPN { splitServerPort() } }
        .onAppear {
            portText = String(connection.port)
            if model.manager.session(connection.id).authenticationRejected {
                password = ""
                error = "A última autenticação foi recusada. Confira o usuário e digite a senha novamente para evitar um bloqueio."
                loaded = true
            } else if let pendingImport, isNew {
                password = pendingImport.password
                loaded = true
            } else {
                do { password = try model.passwords.read(connection.id) ?? ""; loaded = true }
                catch { self.error = error.localizedDescription }
            }
            if isNew { focus = .name }
        }
        .onChange(of: connection.username) { _ in
            // A password belongs to an account; never reuse it silently for a different user.
            if loaded { password = "" }
        }
    }

    // MARK: Fortinet

    @ViewBuilder private var fortinetSections: some View {
        Section("Gateway") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            TextField("Servidor", text: $connection.server, prompt: Text("vpn.exemplo.com"))
                .focused($focus, equals: .server)
            TextField("Porta", text: $portText, prompt: Text("443"))
                .focused($focus, equals: .port)
                .monospacedDigit()
        }
        Section {
            Picker("Método", selection: $connection.authentication) {
                ForEach(Authentication.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            TextField("Usuário", text: $connection.username,
                      prompt: Text(connection.authentication == .password ? "nome.sobrenome" : "Opcional"))
                .focused($focus, equals: .username)
            if connection.authentication == .password {
                SecureField("Senha", text: $password)
                    .focused($focus, equals: .password)
            }
        } header: {
            Text("Autenticação")
        }
        Section {
            TextField("SHA-256 confiável", text: $connection.trustedCertificate, prompt: Text("Opcional"))
                .focused($focus, equals: .certificate)
        } header: {
            Text("Certificado")
        }
    }

    // MARK: OpenVPN

    private var summary: OpenVPNSummary? { pendingImport?.summary ?? connection.openVPN }

    @ViewBuilder private var openVPNSections: some View {
        Section("Perfil") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            if let summary {
                LabeledContent("Servidores") {
                    VStack(alignment: .trailing, spacing: 2) {
                        ForEach(Array(summary.remotes.enumerated()), id: \.offset) { _, remote in
                            Text(remote.display).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
                if !summary.source.isEmpty {
                    LabeledContent("Origem") {
                        Text(summary.source).lineLimit(1).truncationMode(.middle).help(summary.source).textSelection(.enabled)
                    }
                }
            }
            HStack {
                Text(pendingImport != nil && !isNew ? "O novo perfil substituirá o atual ao salvar." : "Certificados e chaves ficam numa cópia privada do app.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Substituir perfil…") { replaceProfile() }.controlSize(.small)
            }
        }
        if summary?.requiresCredentials == true {
            Section {
                TextField("Usuário", text: $connection.username, prompt: Text("nome.sobrenome"))
                    .focused($focus, equals: .username)
                SecureField("Senha", text: $password)
                    .focused($focus, equals: .password)
            } header: {
                Text("Autenticação")
            } footer: {
                Text("A senha fica no Keychain e chega ao OpenVPN só pelo canal protegido do serviço, nunca em arquivo ou argumento.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        if let fix = pendingImport?.digestFix {
            Section {
                Toggle(isOn: $applyDigestFix) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Usar auth \(fix.to) em vez de \(fix.from)")
                        Text("O perfil declara auth \(fix.from), um nome de assinatura que o OpenVPN 2.7 recusa (“Message hash algorithm not found”). \(fix.to) é o algoritmo HMAC equivalente e precisa ser o mesmo configurado no servidor. A troca vale só para a cópia do app; o arquivo original não muda.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            } header: {
                Text("Compatibilidade")
            }
        }
        if let warnings = summary?.warnings, !warnings.isEmpty {
            Section("Avisos da importação") {
                ForEach(warnings, id: \.self) { warning in
                    Label { Text(warning).font(.callout).fixedSize(horizontal: false, vertical: true) }
                        icon: { Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange) }
                }
            }
        }
    }

    private func replaceProfile() {
        guard let url = OpenVPNImportPanel.choose() else { return }
        do {
            let imported = try OpenVPNImporter.load(url)
            pendingImport = imported
            applyDigestFix = false
            connection.openVPN = imported.summary
            if connection.username.isEmpty { connection.username = imported.username }
            // After the username change has reset the field (see onChange below).
            if !imported.password.isEmpty { DispatchQueue.main.async { password = imported.password } }
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    private func save() {
        do {
            if connection.isOpenVPN {
                if let pendingImport { connection.openVPN = pendingImport.summary }
                try model.save(connection, password: summary?.requiresCredentials == true ? password : "",
                               openVPNProfile: pendingImport?.profileText(applyingFix: applyDigestFix))
            } else {
                splitServerPort()
                guard let port = Int(portText) else { throw AppFailure("Informe uma porta numérica.") }
                connection.port = port
                try model.save(connection, password: password)
            }
            saved(); dismiss()
        } catch { self.error = error.localizedDescription }
    }

    private func splitServerPort() {
        if let value = HostPortInput.split(connection.server) {
            connection.server = value.host
            portText = String(value.port)
        }
    }
}
