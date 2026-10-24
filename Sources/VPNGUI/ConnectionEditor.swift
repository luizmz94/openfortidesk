import SwiftUI
import AppKit
import UniformTypeIdentifiers
import VPNHelperShared

/// Open panel for OpenVPN profiles: a .ovpn/.conf file or a Viscosity .visc folder.
enum OpenVPNImportPanel {
    @MainActor static func choose() -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = "Importar perfil OpenVPN"
        panel.message = "Escolha o .ovpn (ou .conf), uma pasta .visc, ou o .ovpn junto com os certificados (⌘-clique para selecionar vários). Os originais não são alterados."
        panel.prompt = "Importar"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.treatsFilePackagesAsDirectories = false
        return panel.runModal() == .OK && !panel.urls.isEmpty ? panel.urls : nil
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
    @State private var step: Step
    /// Saved profile of an existing OpenVPN connection, for the compatibility option.
    @State private var savedProfile: OpenVPNProfile?
    @State private var dropTargeted = false
    /// Saved import whose originals may now go to the Trash (asked once, after saving).
    @State private var cleanup: OpenVPNImport?
    @FocusState private var focus: Field?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(model: AppModel, connection: Connection, pendingImport: OpenVPNImport? = nil, saved: @escaping () -> Void) {
        _model = ObservedObject(wrappedValue: model)
        _connection = State(initialValue: connection)
        _pendingImport = State(initialValue: pendingImport)
        // A blank new cadastro starts by choosing the VPN type.
        let blank = connection.name.isEmpty && pendingImport == nil && !model.data.connections.contains { $0.id == connection.id }
        _step = State(initialValue: blank ? .chooseKind : .form)
        self.saved = saved
    }

    private enum Field: Hashable { case name, server, port, username, password, certificate }
    private enum Step { case chooseKind, chooseFiles, form }

    private var isNew: Bool { !model.data.connections.contains { $0.id == connection.id } }

    var body: some View {
        switch step {
        case .chooseKind: kindChooser
        case .chooseFiles: fileChooser
        case .form: form
        }
    }

    // MARK: Step 1 — type

    private var kindChooser: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "plus.circle", tone: .neutral, title: "Nova conexão", subtitle: "Escolha o tipo de VPN")
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            VStack(spacing: 12) {
                ProtocolCard(kind: .fortinet, title: "Fortinet SSL VPN",
                             subtitle: "Gateway FortiGate, o mesmo usado pelo FortiClient. Usuário e senha ou login SAML no navegador.",
                             status: clientStatus(.fortinet)) { choose(.fortinet) }
                ProtocolCard(kind: .openvpn, title: "OpenVPN",
                             subtitle: "Perfil .ovpn ou pasta .visc do Viscosity. Certificados e chaves ficam guardados junto com a conexão.",
                             status: clientStatus(.openvpn)) { choose(.openvpn) }
            }
            .padding(.horizontal, 22).padding(.vertical, 16)
            Spacer(minLength: 0)
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .frame(width: 560, height: 420)
    }

    private func clientStatus(_ kind: VPNProtocol) -> String {
        guard let status = model.service.status else { return "Usa o \(kind.runtime.title)" }
        if let runtime = status.runtime(kind.runtime) { return "\(kind.runtime.title) \(runtime.version) aprovado" }
        return "\(kind.runtime.title) ainda não aprovado no serviço"
    }

    private func choose(_ kind: VPNProtocol) {
        connection.kind = kind
        error = nil
        if kind == .openvpn { step = .chooseFiles } else { step = .form; loaded = true; focus = .name }
    }

    // MARK: Step 2 — OpenVPN files

    private var fileChooser: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "doc.badge.gearshape", tone: .neutral, title: "Importar perfil OpenVPN", subtitle: "OpenVPN")
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            VStack(alignment: .leading, spacing: 16) {
                VStack(spacing: 10) {
                    ProtocolIcon(kind: .openvpn, size: 40)
                    Text("Arraste o perfil e os certificados para cá").font(.headline)
                    Button("Escolher arquivos…") { if let urls = OpenVPNImportPanel.choose() { importFiles(urls) } }
                        .adaptiveButtonStyle(prominent: true)
                        .keyboardShortcut(.defaultAction)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 22)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(VPNProtocol.openvpn.brandColor.opacity(dropTargeted ? 0.14 : 0.05)))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [6, 4]))
                    .foregroundStyle(dropTargeted ? VPNProtocol.openvpn.brandColor : Color.secondary.opacity(0.5)))
                .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
                    receive(providers); return true
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Aceita").font(.callout.weight(.semibold))
                    Label("Um .ovpn ou .conf com os certificados embutidos", systemImage: "doc.text")
                    Label("Uma pasta .visc do Viscosity", systemImage: "folder")
                    Label("O .ovpn junto com ca, cert, key e ta, selecionados de uma vez", systemImage: "doc.on.doc")
                }
                .font(.callout)
                Text("Certificados e chaves são copiados para um perfil privado do app, que só o seu usuário do macOS lê. Os arquivos originais não são alterados e podem ser apagados depois.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 22).padding(.vertical, 14)
            if let error {
                InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error)
                    .padding(.horizontal, 20).padding(.bottom, 12)
            }
            Spacer(minLength: 0)
            SheetFooter {
                Button("Voltar") { error = nil; step = .chooseKind }
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .frame(width: 560, height: 560)
    }

    private func receive(_ providers: [NSItemProvider]) {
        var urls: [URL] = []
        let group = DispatchGroup()
        let lock = NSLock()
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url { lock.withLock { urls.append(url) } }
                group.leave()
            }
        }
        group.notify(queue: .main) { if !urls.isEmpty { importFiles(urls) } }
    }

    private func importFiles(_ urls: [URL]) {
        do {
            let imported = try OpenVPNImporter.load(urls)
            pendingImport = imported
            applyDigestFix = false
            connection.kind = .openvpn
            connection.openVPN = imported.summary
            connection.port = imported.profile.remotes.first?.port ?? 1194
            if connection.name.isEmpty { connection.name = imported.name }
            if connection.username.isEmpty { connection.username = imported.username }
            // After the username change has reset the field (see onChange below).
            if !imported.password.isEmpty { DispatchQueue.main.async { password = imported.password } }
            error = nil
            loaded = true
            step = .form
        } catch { self.error = error.localizedDescription }
    }

    // MARK: Step 3 — details

    private var form: some View {
        formContent
            .alert("Apagar os arquivos originais?", isPresented: Binding(get: { cleanup != nil }, set: { if !$0 { finishCleanup(trash: false) } })) {
                Button("Mover para a Lixeira", role: .destructive) { finishCleanup(trash: true) }
                Button("Manter", role: .cancel) { finishCleanup(trash: false) }
            } message: {
                Text(cleanupMessage)
            }
    }

    private var cleanupMessage: String {
        guard let cleanup else { return "" }
        let names = cleanup.sourceFolder.map { [$0.lastPathComponent + " (pasta inteira)"] } ?? cleanup.sourceFiles.map(\.lastPathComponent)
        return "O perfil, os certificados e as chaves já estão guardados na pasta privada do app, que só o seu usuário lê. Os originais não são mais necessários:\n\n"
            + names.joined(separator: "\n")
            + "\n\nEles vão para a Lixeira; esvazie-a para apagá-los de vez."
    }

    private func finishCleanup(trash: Bool) {
        guard let pending = cleanup else { return }
        cleanup = nil
        if trash {
            let failed = OpenVPNImporter.trashSources(of: pending)
            if !failed.isEmpty { model.error = "Não foi possível mover para a Lixeira: \(failed.joined(separator: ", ")). A conexão foi salva normalmente." }
        }
        saved(); dismiss()
    }

    private var formContent: some View {
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
            if !isNew, connection.isOpenVPN, pendingImport == nil,
               let text = try? model.profiles?.read(connection.id), let profile = try? OpenVPNProfile.validated(text) {
                savedProfile = profile
                if let fix = editFix { applyDigestFix = OpenVPNCompatibility.isApplied(fix, in: profile) }
            }
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
        if let fix = currentFix {
            Section {
                Toggle(isOn: $applyDigestFix) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Usar auth \(fix.to) em vez de \(fix.from)")
                        Text("O perfil original declara auth \(fix.from), um nome de assinatura que o OpenVPN 2.7 recusa (“Message hash algorithm not found”). \(fix.to) é o algoritmo HMAC equivalente e precisa ser o mesmo configurado no servidor. A troca vale só para a cópia do app; o arquivo original não muda. Desligue para voltar ao valor original.")
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

    /// The compatibility option of the import being made, or of the saved profile.
    private var currentFix: OpenVPNCompatibility.DigestFix? { pendingImport != nil ? pendingImport?.digestFix : editFix }
    private var editFix: OpenVPNCompatibility.DigestFix? {
        connection.openVPN?.compatibility ?? savedProfile.flatMap { OpenVPNCompatibility.digestFix(for: $0) }
    }

    private func replaceProfile() {
        guard let urls = OpenVPNImportPanel.choose() else { return }
        do {
            let imported = try OpenVPNImporter.load(urls)
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
                var profileText = pendingImport?.profileText(applyingFix: applyDigestFix)
                if let pendingImport { connection.openVPN = pendingImport.summary }
                if pendingImport == nil, let fix = editFix, let savedProfile,
                   applyDigestFix != OpenVPNCompatibility.isApplied(fix, in: savedProfile) {
                    let changed = applyDigestFix ? OpenVPNCompatibility.apply(fix, to: savedProfile)
                                                 : OpenVPNCompatibility.revert(fix, in: savedProfile)
                    profileText = changed.text
                }
                connection.openVPN?.compatibility = currentFix
                try model.save(connection, password: summary?.requiresCredentials == true ? password : "",
                               openVPNProfile: profileText)
                if let pendingImport, !pendingImport.sourceFiles.isEmpty {
                    cleanup = pendingImport // The sheet closes after the answer.
                    return
                }
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

/// One VPN type in the Nova conexão chooser.
struct ProtocolCard: View {
    let kind: VPNProtocol
    let title: String
    let subtitle: String
    let status: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 16) {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(kind.brandColor.opacity(0.12))
                    .frame(width: 56, height: 56)
                    .overlay(ProtocolIcon(kind: kind, size: 30))
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.title3.weight(.semibold))
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(status).font(.caption).foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: "chevron.right").font(.body.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .padding(16)
            .contentShape(Rectangle())
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color.primary.opacity(hovering ? 0.07 : 0.035)))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(hovering ? kind.brandColor.opacity(0.7) : Color(nsColor: .separatorColor), lineWidth: hovering ? 1.5 : 0.5))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel("\(title). \(subtitle)")
    }
}
