import Foundation

public struct RuleViolation: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public enum Authentication: String, Codable, CaseIterable, Identifiable, Sendable {
    case password, saml
    public var id: String { rawValue }
}

/// Field rules shared by the app (form validation) and the helper (request validation).
/// The helper never trusts the app's validation: it runs the same rules again.
public enum ConnectionRules {
    public static let maximumHost = 253 + 2
    public static let maximumField = 512

    public static func normalizedHost(_ server: String) throws -> String {
        let value = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]")
        guard !value.isEmpty, value.count <= maximumHost, value.unicodeScalars.allSatisfy(allowed.contains),
              !value.hasPrefix("-"), !value.contains("/") else {
            throw RuleViolation("Informe somente o hostname ou IP do servidor, sem protocolo ou porta.")
        }
        return value
    }

    public static func checkPort(_ port: Int) throws {
        guard (1...65535).contains(port) else { throw RuleViolation("A porta deve estar entre 1 e 65535.") }
    }

    /// openfortivpn's config is line based and trims surrounding whitespace.
    public static func checkConfigValue(_ text: String, label: String) throws {
        guard text.utf8.count <= maximumField,
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              text == text.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw RuleViolation("\(label): caracteres de controle ou espaços nas extremidades não são suportados.")
        }
    }

    public static func normalizedCertificate(_ value: String) throws -> String {
        let digest = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard digest.isEmpty || (digest.count == 64 && digest.allSatisfy({ $0.isHexDigit && $0.isASCII })) else {
            throw RuleViolation("O certificado confiável deve ter exatamente 64 caracteres hexadecimais (SHA-256).")
        }
        return digest
    }
}

/// openfortivpn configuration rendered by the helper from validated fields only.
/// Options such as pppd-plugin, pppd-call, user-cert, log paths or set-routes are never
/// produced: the client cannot add lines because every value is line-safe.
public enum ConfigRenderer {
    public static func render(host: String, port: Int, username: String, password: String?,
                              trustedCertificate: String) throws -> String {
        let host = try ConnectionRules.normalizedHost(host)
        try ConnectionRules.checkPort(port)
        try ConnectionRules.checkConfigValue(username, label: "Usuário")
        let certificate = try ConnectionRules.normalizedCertificate(trustedCertificate)
        var content = "host = \(host)\nport = \(port)\n"
        if !username.isEmpty { content += "username = \(username)\n" }
        if let password {
            try ConnectionRules.checkConfigValue(password, label: "Senha")
            content += "password = \(password)\n"
        }
        if !certificate.isEmpty { content += "trusted-cert = \(certificate)\n" }
        return content
    }
}
