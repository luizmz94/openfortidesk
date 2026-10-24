import Foundation
 
/// The single "Servidor" field of a Fortinet connection, written like FortiClient's
/// remote gateway: host, host:port or host:port/realm (port 443 when omitted).
enum GatewayAddress {
    static let defaultPort = 443

    static func parse(_ input: String) throws -> (host: String, port: Int, realm: String) {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("https://") { value = String(value.dropFirst("https://".count)) }
        var realm = ""
        if let slash = value.firstIndex(of: "/") {
            realm = String(value[value.index(after: slash)...])
            if realm.hasSuffix("/") { realm.removeLast() }
            value = String(value[..<slash])
        }
        var host = value, port = defaultPort
        if let split = HostPortInput.split(value) {
            host = split.host; port = split.port
        } else if value.filter({ $0 == ":" }).count == 1 {
            throw AppFailure("Porta inválida. Use vpn.exemplo.com ou vpn.exemplo.com:10443.")
        }
        do {
            host = try ConnectionRules.normalizedHost(host)
            try ConnectionRules.checkRealm(realm)
        } catch let violation as RuleViolation {
            throw AppFailure(host.isEmpty || violation.message.hasPrefix("Informe")
                             ? "Informe o servidor como vpn.exemplo.com ou vpn.exemplo.com:10443." : violation.message)
        }
        return (host, port, realm)
    }

    /// Text shown in the field and in lists: the port only when it is not 443.
    static func display(host: String, port: Int, realm: String) -> String {
        guard !host.isEmpty else { return "" }
        var text = host
        if port != defaultPort { text += ":\(port)" }
        if !realm.isEmpty { text += (port == defaultPort ? ":\(port)" : "") + "/\(realm)" }
        return text
    }
}

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
    case fortinet, openvpn, wireguard
    var id: String { rawValue }
    var title: String {
        switch self {
        case .fortinet: return "Fortinet SSL VPN"
        case .openvpn: return "OpenVPN"
        case .wireguard: return "WireGuard"
        }
    }
    var runtime: RuntimeKind {
        switch self {
        case .fortinet: return .openfortivpn
        case .openvpn: return .openvpn
        case .wireguard: return .wireguard
        }
    }
}

/// Original files that other macOS users can still read (they may hold private keys).
enum ExposedFiles {
    static func stillExposed(_ paths: [String]?) -> [String] {
        (paths ?? []).filter { path in
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue else { return false }
            return mode & 0o077 != 0
        }
    }
}

/// What the app shows about an imported WireGuard profile. The profile itself (with the
/// private key) lives in the WireGuard profile store, never in connections.json.
struct WireGuardSummary: Codable, Equatable {
    var endpoints: [String]
    var addresses: [String]
    var dns: [String]
    var allowedIPs: [String]
    var fullTunnel: Bool
    /// Derived from the private key; the value the server administrator registers.
    var publicKey: String
    var warnings: [String] = []
    var source: String = ""
    var importedAt = Date()
    var exposedOriginals: [String]?
    var stillExposed: [String] { ExposedFiles.stillExposed(exposedOriginals) }
    /// "Todo o tráfego" or the routed networks.
    var routesDescription: String {
        if fullTunnel { return "Todo o tráfego (\(allowedIPs.filter { $0.hasSuffix("/0") }.joined(separator: ", ")))" }
        return allowedIPs.isEmpty ? "Nenhuma rota" : allowedIPs.joined(separator: ", ")
    }
}

/// What the app shows about an imported OpenVPN profile. The profile itself (with its
/// inline certificates and keys) lives in the OpenVPN ProfileStore, never in connections.json.
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
    var stillExposed: [String] { ExposedFiles.stillExposed(exposedOriginals) }
}

struct Connection: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    /// Fortinet gateway. Empty for OpenVPN (servers come from the profile), so an older
    /// app version reading this file can never try such a cadastro with openfortivpn.
    var server = ""
    var port = 443
    /// FortiGate realm ("/realm" in the gateway address), empty when none.
    var realm = ""
    var username = ""
    var authentication: Authentication = .password
    var trustedCertificate = ""
    /// Fortinet only: Keychain identity sent as the client certificate.
    var clientCertificate: ClientCertificateReference?
    var kind: VPNProtocol = .fortinet
    var openVPN: OpenVPNSummary?
    var wireGuard: WireGuardSummary?

    var isOpenVPN: Bool { kind == .openvpn }
    var isWireGuard: Bool { kind == .wireguard }
    /// OpenVPN and WireGuard connections come from an imported profile file.
    var usesProfile: Bool { kind != .fortinet }
    /// Whether connecting needs the password saved in the Keychain.
    var usesPassword: Bool {
        switch kind {
        case .fortinet: return authentication == .password
        case .openvpn: return openVPN?.requiresCredentials ?? false
        case .wireguard: return false
        }
    }
    /// "host:port" for Fortinet, the first remote/endpoint (and how many more) for the others.
    var endpoint: String {
        let servers: [String]
        switch kind {
        case .fortinet:
            let address = GatewayAddress.display(host: server, port: port, realm: realm)
            return address.isEmpty ? kind.title : address
        case .openvpn: servers = (openVPN?.remotes ?? []).map(\.display)
        case .wireguard: servers = wireGuard?.endpoints ?? []
        }
        guard let first = servers.first else { return kind.title }
        return servers.count > 1 ? "\(first) +\(servers.count - 1)" : first
    }

    func validated() throws -> Connection {
        // Same rules the helper applies again to every request.
        var value = self
        value.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.name.isEmpty else { throw AppFailure("Informe um nome.") }
        if isWireGuard {
            guard wireGuard != nil else { throw AppFailure("Perfil WireGuard ausente; importe-o novamente.") }
            value.server = ""
            value.trustedCertificate = ""
            value.clientCertificate = nil
            value.realm = ""
            value.authentication = .password
            value.username = ""
            value.openVPN = nil
            return value
        }
        if isOpenVPN {
            guard let summary = openVPN else { throw AppFailure("Perfil OpenVPN ausente; importe-o novamente.") }
            value.server = ""
            value.trustedCertificate = ""
            value.clientCertificate = nil
            value.realm = ""
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
            try ConnectionRules.checkRealm(realm)
            try ConnectionRules.checkConfigValue(username, label: "Usuário")
            value.trustedCertificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        } catch let violation as RuleViolation { throw AppFailure(violation.message) }
        guard authentication != .password || !username.isEmpty else { throw AppFailure("Informe o usuário.") }
        if let reference = clientCertificate, !ClientCertificateReference.isValidHash(reference.sha1) {
            throw AppFailure("Certificado do cliente inválido; escolha-o de novo.")
        }
        return value
    }

    static func checkConfigValue(_ text: String, label: String) throws {
        do { try ConnectionRules.checkConfigValue(text, label: label) }
        catch let violation as RuleViolation { throw AppFailure(violation.message) }
    }
}

extension Connection {
    enum CodingKeys: String, CodingKey {
        case id, name, server, port, realm, username, authentication, trustedCertificate, clientCertificate, kind, openVPN, wireGuard
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        server = try values.decode(String.self, forKey: .server)
        port = try values.decode(Int.self, forKey: .port)
        realm = try values.decodeIfPresent(String.self, forKey: .realm) ?? ""
        username = try values.decode(String.self, forKey: .username)
        authentication = try values.decode(Authentication.self, forKey: .authentication)
        trustedCertificate = try values.decode(String.self, forKey: .trustedCertificate)
        clientCertificate = try values.decodeIfPresent(ClientCertificateReference.self, forKey: .clientCertificate)
        kind = try values.decodeIfPresent(VPNProtocol.self, forKey: .kind) ?? .fortinet
        openVPN = try values.decodeIfPresent(OpenVPNSummary.self, forKey: .openVPN)
        wireGuard = try values.decodeIfPresent(WireGuardSummary.self, forKey: .wireGuard)
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
        } ?? {
            switch kind {
            case .openfortivpn: return "/opt/homebrew/bin/openfortivpn"
            case .openvpn: return "/opt/homebrew/sbin/openvpn"
            case .wireguard: return "/opt/homebrew/bin/wireguard-go"
            }
        }()
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

/// Imported profiles (OpenVPN: normalized, inline material only; WireGuard: normalized,
/// with the private key), one 0600 file per connection inside a 0700 directory of the
/// app's own data folder.
struct ProfileStore {
    let directory: URL
    let fileExtension: String
    let label: String
    let maximumSize: Int
    init(directory: URL, fileExtension: String = "ovpn", label: String = "OpenVPN", maximumSize: Int = OpenVPNProfile.maximumNormalizedSize) {
        self.directory = directory; self.fileExtension = fileExtension; self.label = label; self.maximumSize = maximumSize
    }
    static func openVPN(_ store: JSONStore) -> ProfileStore {
        ProfileStore(directory: store.directory.appendingPathComponent("OpenVPN", isDirectory: true))
    }
    static func wireGuard(_ store: JSONStore) -> ProfileStore {
        ProfileStore(directory: store.directory.appendingPathComponent("WireGuard", isDirectory: true), fileExtension: "conf",
                     label: "WireGuard", maximumSize: WireGuardProfile.maximumSize)
    }
    func file(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString + "." + fileExtension) }
    func read(_ id: UUID) throws -> String {
        let url = file(id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw AppFailure("O perfil \(label) desta conexão não foi encontrado. Importe-o novamente.")
        }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumSize, let text = String(data: data, encoding: .utf8) else {
            throw AppFailure("Perfil \(label) salvo ilegível.")
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
            throw AppFailure("Não foi possível gravar o perfil \(label).")
        }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.write(contentsOf: Data(text.utf8))
            try handle.close()
            guard rename(temporary.path, url.path) == 0 else { throw AppFailure("Não foi possível gravar o perfil \(label).") }
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
