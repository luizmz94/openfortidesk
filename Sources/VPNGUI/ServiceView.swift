import SwiftUI
import AppKit
import VPNHelperShared

/// Compact service state at the bottom of the native material sidebar. The row
/// uses a quiet fill instead of a second material layer.
struct ServiceStatusRow: View {
    @ObservedObject var service: ServiceController
    let manage: () -> Void
    var body: some View {
        HStack(spacing: 9) {
            StatusSymbol(symbol: service.health.symbol, tone: service.health.tone,
                         pulsing: service.health == .checking || service.busy, size: 13)
            VStack(alignment: .leading, spacing: 1) {
                Text("Serviço privilegiado").font(.caption2).foregroundStyle(.secondary)
                Text(service.health.title).font(.caption.weight(.medium)).lineLimit(1).truncationMode(.tail)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 4)
            Button("Gerenciar…", action: manage)
                .controlSize(.small)
                .adaptiveButtonStyle()
                .help("Estado, aprovação e remoção do serviço privilegiado")
        }
        .padding(.leading, 10).padding(.trailing, 6).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }
}

/// Management sheet: status, actionable guidance and the explicit actions.
struct ServiceSheet: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var confirmingRemoval = false
    init(model: AppModel) {
        _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 14) {
                    SheetHeader(symbol: service.health.symbol, tone: service.health.tone,
                                title: service.health.title, subtitle: "Serviço privilegiado · OpenFortiDesk \(HelperConstants.fullVersion)")
                    Text(service.health.detail).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                    if let runtime = service.status?.runtime {
                        runtimeSummary(runtime)
                    }
                    if let warning = service.bundleLocationWarning {
                        InlineNotice(tone: .warning, symbol: "folder.badge.questionmark", title: warning)
                    }
                    if let drift = service.sourceDrift {
                        InlineNotice(tone: .warning, symbol: "arrow.triangle.2.circlepath", title: drift)
                    }
                    if let message = service.message {
                        InlineNotice(tone: .neutral, symbol: "info.circle", title: message)
                    }
                    if let inspection = service.inspection { inventory(inspection).transition(.opacity) }
                }
                .padding(22)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            SheetFooter {
                GlassGroup(spacing: 8) {
                    HStack(spacing: 8) { actions }
                }
                Spacer(minLength: 8)
                if service.busy {
                    ProgressView().controlSize(.small).accessibilityLabel("Em andamento")
                }
                Button("Fechar") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .frame(width: 620)
        .frame(minHeight: service.inspection == nil ? 330 : 560)
        .animation(Motion.state(reduceMotion), value: service.inspection == nil)
        .confirmationDialog("Remover o serviço privilegiado?", isPresented: $confirmingRemoval) {
            Button("Remover serviço", role: .destructive) { service.remove(includeManagedFiles: false) }
            Button("Remover serviço e arquivos gerenciados", role: .destructive) { service.remove(includeManagedFiles: true) }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("As conexões ativas serão desconectadas e o app aguardará a limpeza antes de remover o registro. Cadastros e senhas são preservados. Remover os arquivos gerenciados (\(HelperConstants.stateDirectory)) exige administrador.")
        }
    }

    @ViewBuilder private var actions: some View {
        switch service.health {
        case .notRegistered, .notFound:
            Button("Ativar serviço") { service.activate() }.adaptiveButtonStyle(prominent: true).disabled(service.busy)
        case .requiresApproval:
            Button("Abrir Ajustes") { service.openSettings() }.adaptiveButtonStyle(prominent: true)
        case .outdated:
            Button("Atualizar serviço") { service.update() }.adaptiveButtonStyle(prominent: true).disabled(service.busy)
        case .runtimeMissing, .userNotAuthorized, .ready:
            Button(service.health == .ready ? "Reaprovar openfortivpn…" : "Aprovar openfortivpn…") {
                service.inspect(candidate: BinaryLocator.defaultPath)
            }
            .adaptiveButtonStyle(prominent: service.health != .ready)
            .disabled(service.busy || service.inspection != nil)
        default:
            EmptyView()
        }
        Button("Verificar novamente") { service.refresh() }.adaptiveButtonStyle().disabled(service.busy)
        if service.isRegistered {
            Button("Remover serviço…", role: .destructive) { confirmingRemoval = true }
                .adaptiveButtonStyle().disabled(service.busy)
        }
    }

    private func runtimeSummary(_ runtime: RuntimeSummary) -> some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 5) {
            GridRow {
                Text("openfortivpn").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                Text(runtime.version).textSelection(.enabled)
            }
            GridRow {
                Text("Aprovado em").foregroundStyle(.secondary)
                Text(runtime.approvedAt.formatted(date: .abbreviated, time: .shortened))
            }
            GridRow {
                Text("Origem").foregroundStyle(.secondary)
                Text(runtime.sourcePath).font(.system(.callout, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(runtime.sourcePath)
            }
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }

    private func inventory(_ inspection: RuntimeInspection) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Inventário a aprovar").font(.headline).accessibilityAddTraits(.isHeader)
                if let version = inspection.packageVersion {
                    Text(version).font(.callout).foregroundStyle(.secondary)
                }
            }
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(inspection.items, id: \.sourcePath) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Image(systemName: item.role == .executable ? "terminal" : "shippingbox")
                                    .foregroundStyle(.secondary).accessibilityHidden(true)
                                Text(item.role == .executable ? "executável" : "biblioteca").font(.caption.weight(.semibold))
                                if item.mutableLocation {
                                    Text("local alterável sem administrador").font(.caption).foregroundStyle(.orange)
                                }
                            }
                            Text(item.sourcePath).font(.system(.caption, design: .monospaced))
                            Text("SHA-256 \(item.sha256)").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                        }
                        .textSelection(.enabled)
                        .accessibilityElement(children: .combine)
                    }
                    Divider()
                    Text("Bibliotecas do sistema (protegidas pelo macOS): \(inspection.systemLibraries.joined(separator: ", "))")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
            }
            .frame(maxHeight: 200)
            .contentPanel()
            ForEach(inspection.warnings, id: \.self) {
                InlineNotice(tone: .warning, symbol: "exclamationmark.triangle", title: $0)
            }
            Text("A aprovação copia exatamente estes arquivos para \(HelperConstants.stateDirectory) (root, somente leitura), reescreve só os caminhos das bibliotecas para a própria cópia e preserva licenças. Conectar nunca atualiza essa cópia.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancelar") { service.inspection = nil }
                Button("Aprovar com senha de administrador…") { service.approve() }
                    .adaptiveButtonStyle(prominent: true).disabled(service.busy)
            }
        }
    }
}
