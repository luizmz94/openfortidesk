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

struct Connection: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    var server = ""
    var port = 443
    var username = ""
    var authentication: Authentication = .password
    var trustedCertificate = ""

    func validated() throws -> Connection {
        // Same rules the helper applies again to every request.
        var value = self
        value.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.name.isEmpty else { throw AppFailure("Informe um nome.") }
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

struct SavedData: Codable {
    var connections: [Connection] = []
}

enum BinaryLocator {
    static func candidates(environment: [String: String] = ProcessInfo.processInfo.environment) -> [String] {
        let standard = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin",
                        "/opt/homebrew/sbin", "/usr/local/sbin", "/opt/pkg/bin"]
        let inherited = (environment["PATH"] ?? "").split(separator: ":").map(String.init).filter { $0.hasPrefix("/") }
        let user = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin").path
        var seen = Set<String>()
        return (standard + inherited + [user]).map {
            URL(fileURLWithPath: $0).appendingPathComponent("openfortivpn").path
        }.filter { seen.insert($0).inserted }
    }
    static var defaultPath: String {
        candidates().first {
            FileManager.default.isExecutableFile(atPath: $0)
        } ?? "/opt/homebrew/bin/openfortivpn"
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
