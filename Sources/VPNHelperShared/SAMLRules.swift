import Foundation

// SAML session reuse. openfortivpn stays responsible for authentication, TLS, tunnel,
// routes, DNS and logout; this file only captures and validates SVPNCOOKIE.
//
// Verified against openfortivpn 1.24.1 (src/tunnel.c run_tunnel, src/http.c auth_set_cookie,
// src/main.c --cookie-on-stdin, src/userinput.c read_from_stdin):
// - with one -v, run_tunnel logs "DEBUG:  Cookie: SVPNCOOKIE=<value>" after "Authenticated.";
// - --cookie-on-stdin performs one read() of at most COOKIE_SIZE (4096) bytes and keeps
//   every byte, so the value is sent without a newline;
// - with a cookie, auth_set_cookie never asks the gateway: a rejected session only shows up
//   later as an HTTP failure in VPN allocation or configuration.
public enum SAMLCookieRules {
    public static let prefix = "SVPNCOOKIE="
    /// COOKIE_SIZE in openfortivpn, including the "SVPNCOOKIE=" prefix.
    public static let maximumLength = 4096
    public static let maximumAge: TimeInterval = 30 * 60

    /// A transport-safe cookie: prefix plus visible ASCII without ';', never empty.
    public static func isValid(_ cookie: String) -> Bool {
        guard cookie.hasPrefix(prefix), cookie.utf8.count > prefix.utf8.count,
              cookie.utf8.count <= maximumLength else { return false }
        return cookie.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7f && $0 != UInt8(ascii: ";") }
    }

    /// Strict match for the single DEBUG message that carries the session cookie.
    public static func capture(_ line: String) -> String? {
        let marker = "Cookie: "
        guard line.hasPrefix("DEBUG:") else { return nil }
        let rest = line.dropFirst("DEBUG:".count)
        let body = rest.drop { $0 == " " }
        guard rest.count - body.count >= 1, body.hasPrefix(marker) else { return nil }
        let cookie = String(body.dropFirst(marker.count))
        return isValid(cookie) ? cookie : nil
    }

    /// Gateway answered the cookie session with an HTTP-level refusal (expired or logged out).
    /// TLS errors, memory errors and network failures are not refusals.
    public static func isRejection(_ line: String) -> Bool {
        line.range(of: #"^ERROR:\s+(?:VPN allocation request failed|Could not get VPN configuration|Could not start tunnel) \((?:HTTP status code|Bad HTTP response code|Permission denied|No cookie given)\)"#,
                   options: .regularExpression) != nil
        || line.range(of: #"^ERROR:\s+Could not authenticate to gateway\."#, options: .regularExpression) != nil
    }

    /// Failures that say nothing about the cookie: network, TLS, certificate, proxy, DNS.
    public static func isTransportFailure(_ line: String) -> Bool {
        line.range(of: #"(?i)^ERROR:.*(?:\bTLS\b|\bSSL\b|certificate|getaddrinfo|connect:|socket|proxy|gateway host|timed out|network)"#,
                   options: .regularExpression) != nil
    }
}

/// How a SAML session uses the cookie cache during one client process.
public enum SAMLCookieMode: String, Codable, Equatable, Sendable {
    case none        // password profile, or capture unavailable in this client version
    case capture     // normal browser login; candidate cookie captured from -v output
    case reuse       // cached cookie on stdin; no browser, no callback port
}

/// What the approved openfortivpn documents in its --help, probed by the helper.
public struct RuntimeCapabilities: Codable, Equatable, Sendable {
    public var cookieOnStdin: Bool
    public var captureCookie: Bool
    public var samlPort: Bool
    public init(cookieOnStdin: Bool, captureCookie: Bool, samlPort: Bool) {
        self.cookieOnStdin = cookieOnStdin; self.captureCookie = captureCookie; self.samlPort = samlPort
    }
    public init(help: String) {
        cookieOnStdin = help.contains("--cookie-on-stdin")
        captureCookie = cookieOnStdin && help.contains("[-v|-q]")
        samlPort = help.contains("--saml-login[=port]")
    }
    /// Minimum surface of the original client that the helper relies on.
    public static func looksLikeOpenFortiVPN(_ help: String) -> Bool {
        help.contains("openfortivpn") && help.contains("--config") && help.contains("--trusted-cert")
    }
}

/// Client arguments built from enumerated choices only; never from client-supplied text.
public struct LaunchPlan: Codable, Equatable, Sendable {
    public var clientArguments: [String]
    public var mode: SAMLCookieMode
    public init(clientArguments: [String], mode: SAMLCookieMode) {
        self.clientArguments = clientArguments; self.mode = mode
    }
    public var usesCookie: Bool { mode == .reuse }
    public static func make(authentication: Authentication, capabilities: RuntimeCapabilities, cookieAvailable: Bool) -> LaunchPlan {
        guard authentication == .saml else { return LaunchPlan(clientArguments: [], mode: .none) }
        if cookieAvailable && capabilities.cookieOnStdin { return LaunchPlan(clientArguments: [], mode: .reuse) }
        var arguments = ["--saml-login=\(HelperConstants.samlPort)"]
        // One -v is the minimum level that prints the cookie; higher levels expose HTTP bodies.
        if capabilities.captureCookie { arguments.append("-v") }
        return LaunchPlan(clientArguments: arguments, mode: capabilities.captureCookie ? .capture : .none)
    }
    public static func make(authentication: Authentication, help: String, cookieAvailable: Bool) -> LaunchPlan {
        make(authentication: authentication, capabilities: RuntimeCapabilities(help: help), cookieAvailable: cookieAvailable)
    }
    /// Full supervisor argv after argv[0]. The supervisor appends --cookie-on-stdin and -c /dev/fd/3.
    public func supervisorArguments(binary: String) -> [String] {
        (usesCookie ? ["--cookie-fd"] : []) + [binary] + clientArguments
    }
}

/// Reassembles client output into lines before anything leaves the helper. Drops every
/// DEBUG message (including unlabelled continuation lines) and any line containing a known
/// session secret. Only the strict cookie message is extracted. wireguard-go sessions keep
/// DEBUG lines (`keepDebug`): its verbose log is how it reports handshakes, and it never
/// writes key material (peers appear as "peer(ZTJk…f2Tw)").
public struct OutputLineFilter {
    public enum Event: Equatable {
        case line(String)
        case cookie(String)
        case overflow
    }
    public static let maximumLine = 65536
    private var pending = Data()
    private var discarding = false
    private var insideDebug = false
    private var secrets: [Data] = []
    public let captureCookie: Bool
    public let keepDebug: Bool
    public init(captureCookie: Bool, secrets: [String] = [], keepDebug: Bool = false) {
        self.captureCookie = captureCookie
        self.keepDebug = keepDebug
        self.secrets = secrets.filter { !$0.isEmpty }.map { Data($0.utf8) }
        // The bare value can appear unlabelled; hide it as well.
        for secret in secrets where secret.hasPrefix(SAMLCookieRules.prefix) {
            self.secrets.append(Data(secret.dropFirst(SAMLCookieRules.prefix.count).utf8))
        }
    }
    public mutating func feed(_ bytes: Data) -> [Event] {
        var events: [Event] = []
        var start = bytes.startIndex
        while start < bytes.endIndex {
            if let newline = bytes[start...].firstIndex(of: 10) {
                append(bytes[start..<newline], to: &events)
                if discarding { discarding = false } else { complete(&events) }
                pending.removeAll(keepingCapacity: true)
                start = bytes.index(after: newline)
            } else {
                append(bytes[start...], to: &events)
                start = bytes.endIndex
            }
        }
        return events
    }
    public mutating func finish() -> [Event] {
        var events: [Event] = []
        if !discarding && !pending.isEmpty { complete(&events) }
        pending.removeAll()
        discarding = false
        return events
    }
    private mutating func append(_ slice: Data, to events: inout [Event]) {
        guard !discarding else { return }
        pending.append(slice)
        if pending.count > Self.maximumLine {
            // The tail of an oversized line must not reappear as a new, unlabelled line.
            pending.removeAll(keepingCapacity: true)
            discarding = true
            events.append(.overflow)
        }
    }
    private mutating func complete(_ events: inout [Event]) {
        let raw = pending
        let line = String(decoding: raw, as: UTF8.self)
        let labelled = ["ERROR:", "WARN:", "INFO:", "__VPNGUI_", "Supervisor:"].contains { line.hasPrefix($0) }
            || (keepDebug && line.hasPrefix("DEBUG:"))
        if line.hasPrefix("DEBUG:") && !keepDebug {
            insideDebug = true
            if captureCookie, let cookie = SAMLCookieRules.capture(line) {
                remember(cookie)
                events.append(.cookie(cookie))
            }
            return
        }
        if labelled { insideDebug = false } else if insideDebug { return }
        if secrets.contains(where: { raw.range(of: $0) != nil }) { return }
        events.append(.line(line))
    }
    private mutating func remember(_ cookie: String) {
        let full = Data(cookie.utf8)
        guard !secrets.contains(full) else { return }
        secrets.append(full)
        secrets.append(Data(cookie.dropFirst(SAMLCookieRules.prefix.count).utf8))
    }
}
