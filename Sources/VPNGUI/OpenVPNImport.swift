import Foundation
import Darwin
import VPNHelperShared

/// Result of reading an OpenVPN profile chosen by the user. Nothing is saved yet and the
/// original files are never modified.
struct OpenVPNImport: Equatable {
    var profile: OpenVPNProfile
    var name: String
    var username: String
    var password: String
    var warnings: [String]
    /// `auth RSA-SHA256`-style value found; applied only if the user accepts.
    var digestFix: OpenVPNCompatibility.DigestFix?
    var source: String

    var summary: OpenVPNSummary {
        OpenVPNSummary(remotes: profile.remotes, requiresCredentials: profile.requiresCredentials,
                       warnings: warnings, source: source)
    }
    func profileText(applyingFix: Bool) -> String {
        guard applyingFix, let digestFix else { return profile.text }
        return OpenVPNCompatibility.apply(digestFix, to: profile).text
    }
}

/// Reads a single .ovpn/.conf file or a Viscosity .visc folder. Referenced certificates and
/// keys are read only from inside the profile's own folder and become inline blocks.
enum OpenVPNImporter {
    static let maximumReferencedFile = 64 * 1024

    static func load(_ url: URL) throws -> OpenVPNImport {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            throw AppFailure("Arquivo não encontrado: \(url.path)")
        }
        let file = isDirectory.boolValue ? try configuration(inFolder: url) : url
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard (attributes[.type] as? FileAttributeType) == .typeRegular,
              (attributes[.size] as? Int ?? .max) <= OpenVPNConfigText.maximumSize else {
            throw AppFailure("O perfil precisa ser um arquivo de texto de até 256 KB.")
        }
        let data = try Data(contentsOf: file)
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw AppFailure("O perfil não está em texto legível.")
        }
        let base = file.deletingLastPathComponent()
        var stem = file.deletingPathExtension().lastPathComponent
        if stem.lowercased() == "config", isDirectory.boolValue { stem = url.deletingPathExtension().lastPathComponent }
        let source = (isDirectory.boolValue ? url : file).path
            .replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        return try importText(text, baseDirectory: base, suggestedName: stem, source: source)
    }

    /// Viscosity bundles hold one config.conf (or a single .ovpn) next to the key files.
    static func configuration(inFolder folder: URL) throws -> URL {
        let entries = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
            .filter { !$0.lastPathComponent.hasPrefix(".") && ["ovpn", "conf"].contains($0.pathExtension.lowercased()) }
        if entries.count == 1 { return entries[0] }
        if let config = entries.first(where: { $0.lastPathComponent.lowercased() == "config.conf" }) { return config }
        if entries.isEmpty { throw AppFailure("A pasta não contém um perfil .ovpn ou config.conf.") }
        throw AppFailure("A pasta contém mais de um perfil (\(entries.map(\.lastPathComponent).sorted().joined(separator: ", "))). Escolha o arquivo desejado.")
    }

    static func importText(_ text: String, baseDirectory: URL, suggestedName: String, source: String) throws -> OpenVPNImport {
        let parsed: OpenVPNConfigText
        do { parsed = try OpenVPNConfigText.parse(text) } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        var blocks: [String: String] = [:]
        var order: [String] = []
        var username = "", password = ""
        var warnings: [String] = []
        var droppedNames = Set<String>()
        var unsupported: [String] = []
        func addBlock(_ tag: String, _ content: String) throws {
            guard blocks[tag] == nil else { throw AppFailure("O material de <\(tag)> aparece mais de uma vez no perfil.") }
            blocks[tag] = content
            order.append(tag)
        }
        func credentials(from content: String) {
            let lines = content.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            username = lines.first?.trimmingCharacters(in: .whitespaces) ?? ""
            password = lines.count > 1 ? lines[1] : ""
        }
        for block in parsed.blocks {
            switch block.tag {
            case _ where OpenVPNRules.blockTags.contains(block.tag): try addBlock(block.tag, block.content)
            case "auth-user-pass": credentials(from: block.content)
            case "connection": throw AppFailure("Blocos <connection> ainda não são suportados. Use diretivas remote no próprio perfil.")
            case "pkcs12": throw AppFailure("Certificados PKCS#12 ainda não são suportados; exporte o perfil com ca/cert/key em PEM.")
            case "http-proxy-user-pass": throw AppFailure("Conexão por proxy ainda não é suportada.")
            default: unsupported.append("<\(block.tag)>")
            }
        }
        var directives: [OpenVPNDirective] = []
        var keyDirection: String?
        for line in parsed.lines {
            var directive = line.directive
            let name = directive.name
            if OpenVPNRules.blockTags.contains(name) {
                guard let path = directive.arguments.first else { throw AppFailure("Linha \(line.number): \(name) sem arquivo.") }
                if path != "[inline]" {
                    if name == "crl-verify" && directive.arguments.count > 1 {
                        throw AppFailure("crl-verify com diretório não é suportado.")
                    }
                    let (content, exposed) = try readReferenced(path, base: baseDirectory, line: line.number)
                    try addBlock(name, content)
                    if exposed {
                        warnings.append("O arquivo original \(path) pode ser lido por outros usuários do Mac (recomendado: chmod 600). A cópia do app é privada.")
                    }
                }
                if name == "tls-auth", directive.arguments.count > 1 {
                    let direction = directive.arguments[1]
                    guard ["0", "1"].contains(direction) else { throw AppFailure("Linha \(line.number): direção de tls-auth inválida.") }
                    if let keyDirection, keyDirection != direction { throw AppFailure("key-direction diverge da direção de tls-auth.") }
                    keyDirection = direction
                }
                continue
            }
            switch name {
            case "key-direction":
                if let value = directive.arguments.first {
                    if let keyDirection, keyDirection != value { throw AppFailure("key-direction diverge da direção de tls-auth.") }
                    keyDirection = value
                }
                continue
            case "auth-user-pass":
                if let file = directive.arguments.first {
                    guard file != "username-only" else { throw AppFailure("Perfis só com usuário (SSO) ainda não são suportados.") }
                    let (content, _) = try readReferenced(file, base: baseDirectory, line: line.number)
                    credentials(from: content)
                    warnings.append("Usuário e senha lidos de \(file); a senha passa a ficar no Keychain.")
                }
                directive.arguments = []
            case "pkcs12": throw AppFailure("Certificados PKCS#12 ainda não são suportados; exporte o perfil com ca/cert/key em PEM.")
            case "secret": throw AppFailure("Chave estática (secret) não é suportada; ela foi removida do OpenVPN 2.7.")
            case "askpass": throw AppFailure("Chave privada protegida por senha ainda não é suportada.")
            case "config": throw AppFailure("O perfil inclui outro arquivo (config), o que não é suportado.")
            case "http-proxy", "socks-proxy", "http-proxy-option": throw AppFailure("Conexão por proxy ainda não é suportada.")
            case "verb":
                if let value = directive.arguments.first.flatMap(Int.init), value > 3 {
                    directive.arguments = ["3"]
                    warnings.append("verb \(value) reduzido para 3: níveis maiores despejam toda a configuração no log.")
                }
            default: break
            }
            if let reason = OpenVPNRules.dropped[name] {
                if droppedNames.insert(name).inserted { warnings.append("Diretiva \(name) removida: \(reason).") }
                continue
            }
            guard OpenVPNRules.allowed[name] != nil else {
                unsupported.append(name)
                continue
            }
            directives.append(directive)
        }
        if !unsupported.isEmpty {
            throw AppFailure("O perfil usa diretivas que o app ainda não suporta: \(Array(Set(unsupported)).sorted().joined(separator: ", ")). Nada foi importado.")
        }
        if let keyDirection { directives.append(OpenVPNDirective("key-direction", [keyDirection])) }
        if directives.contains(where: { ["comp-lzo", "compress"].contains($0.name) && !($0.arguments.first ?? "").hasPrefix("stub") && $0.arguments.first != "no" }) {
            warnings.append("O perfil ativa compressão (comp-lzo/compress), que tem riscos conhecidos de segurança. Ela foi mantida porque o servidor pode exigi-la; prefira desativá-la no servidor.")
        }
        let profile = OpenVPNProfile(directives: directives, blocks: order.map { OpenVPNBlock(tag: $0, content: blocks[$0]!) })
        do { try profile.check() } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        let name = suggestedName.lowercased() == "config" ? (parsed.viscosity["name"] ?? suggestedName) : suggestedName
        return OpenVPNImport(profile: profile, name: name, username: username, password: password, warnings: warnings,
                             digestFix: OpenVPNCompatibility.digestFix(for: profile), source: source)
    }

    /// Only relative names inside the profile's folder: no absolute paths, no "..", and the
    /// resolved file (after symlinks) must still be inside the folder.
    static func readReferenced(_ path: String, base: URL, line: Int) throws -> (content: String, exposed: Bool) {
        guard !path.hasPrefix("/"), !path.hasPrefix("~"), !path.split(separator: "/").contains(".."), !path.isEmpty else {
            throw AppFailure("Linha \(line): \(path) aponta para fora da pasta do perfil. Coloque os arquivos ao lado do .ovpn e use nomes relativos.")
        }
        guard let baseReal = realpath(base.path, nil) else { throw AppFailure("Pasta do perfil inacessível.") }
        let root = String(cString: baseReal); free(baseReal)
        guard let fileReal = realpath(base.appendingPathComponent(path).path, nil) else {
            throw AppFailure("Linha \(line): arquivo \(path) não encontrado ao lado do perfil.")
        }
        let resolved = String(cString: fileReal); free(fileReal)
        guard resolved.hasPrefix(root + "/") else {
            throw AppFailure("Linha \(line): \(path) aponta para fora da pasta do perfil.")
        }
        let fd = open(resolved, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AppFailure("Linha \(line): não foi possível ler \(path).") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= maximumReferencedFile else {
            throw AppFailure("Linha \(line): \(path) não é um arquivo regular de até 64 KB.")
        }
        let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else { throw AppFailure("Linha \(line): \(path) não está em texto (PEM).") }
        let content = text.replacingOccurrences(of: "\r\n", with: "\n").trimmingCharacters(in: .newlines)
        return (content, info.st_mode & 0o077 != 0 && content.contains("PRIVATE KEY") || (info.st_mode & 0o077 != 0 && content.contains("Static key")))
    }
}
