import SwiftUI
import AppKit
import VPNHelperShared

struct ConnectionEditor: View {
    @ObservedObject var model: AppModel
    @State var connection: Connection
    var saved: () -> Void
    @State private var password = ""
    @State private var portText = ""
    @State private var error: String?
    @State private var loaded = false
    @FocusState private var focus: Field?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private enum Field: Hashable { case name, server, port, username, password, certificate }

    private var isNew: Bool { !model.data.connections.contains { $0.id == connection.id } }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "network.badge.shield.half.filled", tone: .neutral,
                        title: isNew ? "Nova conexão" : "Editar conexão",
                        subtitle: isNew ? nil : connection.name)
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            Form {
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
        .frame(width: 560, height: 600)
        .animation(Motion.state(reduceMotion), value: error)
        .onChange(of: focus) { field in if field != .server { splitServerPort() } }
        .onAppear {
            portText = String(connection.port)
            if model.manager.session(connection.id).authenticationRejected {
                password = ""
                error = "A última autenticação foi recusada. Confira o usuário e digite a senha novamente para evitar um bloqueio."
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

    private func save() {
        do {
            splitServerPort()
            guard let port = Int(portText) else { throw AppFailure("Informe uma porta numérica.") }
            connection.port = port
            try model.save(connection, password: password)
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
