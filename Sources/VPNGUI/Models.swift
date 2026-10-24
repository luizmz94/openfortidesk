import Foundation
 
enum HostPortInput {
    static func split(_ input: String) -> (host: String, port: Int)? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = #"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
              let hostRange = Range(match.range(at: 1), in: value),
              let portRange = Range(match.range(at: 2), in: value),
              let port = Int(value[portRange]), (1...65535).contains(port) else { return nil }
        return (String(value[hostRange]), port)
    }
}
import Security
import Darwin
import VPNHelperShared

struct AppFailure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

extension Authentication {
    var title: String { self == .password ? "Senha" : "SAML (navegador)" }
}

/// VPN protocol of a saved connection. Existing cadastros (no key) are Fortinet.
enum VPNProtocol: String, Codable, CaseIterable, Identifiable {
    case fortinet, openvpn
    var id: String { rawValue }
    var title: String { self == .fortinet ? "Fortinet SSL VPN" : "OpenVPN" }
    var runtime: RuntimeKind { self == .fortinet ? .openfortivpn : .openvpn }
}

/// What the app shows about an imported OpenVPN profile. The profile itself (with its
/// inline certificates and keys) lives in OpenVPNProfileStore, never in connections.json.
struct OpenVPNSummary: Codable, Equatable {
    var remotes: [OpenVPNRemote]
    var requiresCredentials: Bool
    var warnings: [String] = []
    var source: String = ""
    var importedAt = Date()
    /// Compatibility option this profile offers (auth RSA-SHAx → SHAx), applied or not.
    var compatibility: OpenVPNCompatibility.DigestFix?
    /// Original key files that other macOS users could read at import time (full paths).
    var exposedOriginals: [String]?

    /// Those originals that still exist and are still readable by others.
    var stillExposed: [String] {
        (exposedOriginals ?? []).filter { path in
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue else { return false }
            return mode & 0o077 != 0
        }
    }
}

struct Connection: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    /// Fortinet gateway. Empty for OpenVPN (servers come from the profile), so an older
    /// app version reading this file can never try such a cadastro with openfortivpn.
    var server = ""
    var port = 443
    var username = ""
    var authentication: Authentication = .password
    var trustedCertificate = ""
    var kind: VPNProtocol = .fortinet
    var openVPN: OpenVPNSummary?

    var isOpenVPN: Bool { kind == .openvpn }
    /// Whether connecting needs the password saved in the Keychain.
    var usesPassword: Bool { isOpenVPN ? (openVPN?.requiresCredentials ?? false) : authentication == .password }
    /// "host:port" for Fortinet, the first remote (and how many more) for OpenVPN.
    var endpoint: String {
        guard isOpenVPN else { return "\(server):\(String(port))" }
        let remotes = openVPN?.remotes ?? []
        guard let first = remotes.first else { return "OpenVPN" }
        return remotes.count > 1 ? "\(first.display) +\(remotes.count - 1)" : first.display
    }

    func validated() throws -> Connection {
        // Same rules the helper applies again to every request.
        var value = self
        value.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.name.isEmpty else { throw AppFailure("Informe um nome.") }
        if isOpenVPN {
            guard let summary = openVPN else { throw AppFailure("Perfil OpenVPN ausente; importe-o novamente.") }
            value.server = ""
            value.trustedCertificate = ""
            value.authentication = .password
            value.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
            if summary.requiresCredentials {
                guard !value.username.isEmpty else { throw AppFailure("Informe o usuário.") }
                do { try OpenVPNRules.checkCredential(value.username, label: "Usuário") }
                catch let violation as RuleViolation { throw AppFailure(violation.message) }
            } else { value.username = "" }
            return value
        }
        do {
            value.server = try ConnectionRules.normalizedHost(server)
            try ConnectionRules.checkPort(port)
            try ConnectionRules.checkConfigValue(username, label: "Usuário")
            value.trustedCertificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        guard authentication != .password || !username.isEmpty else { throw AppFailure("Informe o usuário.") }
        return value
    }

    static func checkConfigValue(_ text: String, label: String) throws {
        do { try ConnectionRules.checkConfigValue(text, label: label) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }
}

extension Connection {
    enum CodingKeys: String, CodingKey {
        case id, name, server, port, username, authentication, trustedCertificate, kind, openVPN
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        server = try values.decode(String.self, forKey: .server)
        port = try values.decode(Int.self, forKey: .port)
        username = try values.decode(String.self, forKey: .username)
        authentication = try values.decode(Authentication.self, forKey: .authentication)
        trustedCertificate = try values.decode(String.self, forKey: .trustedCertificate)
        kind = try values.decodeIfPresent(VPNProtocol.self, forKey: .kind) ?? .fortinet
        openVPN = try values.decodeIfPresent(OpenVPNSummary.self, forKey: .openVPN)
    }
}

struct SavedData: Codable {
    var connections: [Connection] = []
}

enum BinaryLocator {
    /// Apple Silicon Homebrew uses /opt/homebrew, Intel /usr/local; openvpn installs in sbin.
    static func candidates(environment: [String: String] = ProcessInfo.processInfo.environment, name: String = "openfortivpn") -> [String] {
        let standard = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin",
                        "/opt/homebrew/sbin", "/usr/local/sbin", "/opt/pkg/bin"]
        let inherited = (environment["PATH"] ?? "").split(separator: ":").map(String.init).filter { $0.hasPrefix("/") }
        let user = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin").path
        var seen = Set<String>()
        return (standard + inherited + [user]).map {
            URL(fileURLWithPath: $0).appendingPathComponent(name).path
        }.filter { seen.insert($0).inserted }
    }
    static var defaultPath: String { defaultPath(for: .openfortivpn) }
    static func defaultPath(for kind: RuntimeKind) -> String {
        candidates(name: kind.executableName).first {
            FileManager.default.isExecutableFile(atPath: $0)
        } ?? (kind == .openvpn ? "/opt/homebrew/sbin/openvpn" : "/opt/homebrew/bin/openfortivpn")
    }
}

/// Supervisor next to the running executable. Used by the local checks only; the helper
/// executes its own protected, signature-checked copy.
enum SupervisorLocator {
    static var path: String {
        let executable = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        return executable.deletingLastPathComponent().appendingPathComponent("VPNSupervisor").path
    }
}

struct JSONStore {
    let directory: URL
    init(directory: URL? = nil) throws {
        self.directory = try directory ?? FileManager.default.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("VPNGUI", isDirectory: true)
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
    }
    var file: URL { directory.appendingPathComponent("connections.json") }
    func load() throws -> SavedData {
        guard FileManager.default.fileExists(atPath: file.path) else { return SavedData() }
        let saved = try JSONDecoder().decode(SavedData.self, from: Data(contentsOf: file))
        guard Set(saved.connections.map(\.id)).count == saved.connections.count else {
            throw AppFailure("O arquivo de conexões contém identificadores duplicados.")
        }
        return saved
    }
    func save(_ data: SavedData) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(data).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}

/// Imported OpenVPN profiles (normalized, inline material only), one 0600 file per
/// connection inside a 0700 directory of the app's own data folder.
struct OpenVPNProfileStore {
    let directory: URL
    init(directory: URL) { self.directory = directory }
    init(store: JSONStore) { directory = store.directory.appendingPathComponent("OpenVPN", isDirectory: true) }
    func file(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString + ".ovpn") }
    func read(_ id: UUID) throws -> String {
        let url = file(id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw AppFailure("O perfil OpenVPN desta conexão não foi encontrado. Importe-o novamente.")
        }
        let data = try Data(contentsOf: url)
        guard data.count <= OpenVPNProfile.maximumNormalizedSize, let text = String(data: data, encoding: .utf8) else {
            throw AppFailure("Perfil OpenVPN salvo ilegível.")
        }
        return text
    }
    func write(_ text: String, id: UUID) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let url = file(id)
        let temporary = directory.appendingPathComponent(".\(id.uuidString).\(UUID().uuidString).tmp")
        // Created 0600 before any byte is written; then atomically renamed into place.
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw AppFailure("Não foi possível gravar o perfil OpenVPN.")
        }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.write(contentsOf: Data(text.utf8))
            try handle.close()
            guard rename(temporary.path, url.path) == 0 else { throw AppFailure("Não foi possível gravar o perfil OpenVPN.") }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
    func delete(_ id: UUID) throws {
        let url = file(id)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
}

struct PasswordStore {
    let service: String
    init(service: String = "com.luiz.vpngui.password") { self.service = service }
    private func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString]
    }
    func read(_ id: UUID) throws -> String? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data, let text = String(data: data, encoding: .utf8) else {
            throw AppFailure("Senha inválida no Keychain.")
        }
        return text
    }
    func write(_ password: String, id: UUID) throws {
        let q = query(id)
        let values = [kSecValueData as String: Data(password.utf8)]
        let status = SecItemUpdate(q as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            let item = q.merging(values) { _, new in new }
            try check(SecItemAdd(item as CFDictionary, nil))
        } else { try check(status) }
    }
    func delete(_ id: UUID) throws {
        let status = SecItemDelete(query(id) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw AppFailure("Keychain (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? String(status))")
        }
    }
}
