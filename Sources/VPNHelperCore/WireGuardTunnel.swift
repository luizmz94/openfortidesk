import Foundation
import Darwin
import SystemConfiguration
import VPNHelperShared

public struct CommandResult: Equatable {
    public var status: Int32
    public var output: String
    public init(status: Int32, output: String) { self.status = status; self.output = output }
}

/// What a WireGuard session needs from the system. Production: `SystemWireGuardHost`
/// (root, SIP-protected tools, the real UAPI socket and the dynamic store). Local checks
/// supply a recording host so the same orchestration runs unprivileged.
public protocol WireGuardHost: AnyObject {
    /// Runs one of the fixed system tools (absolute path) with literal arguments; no shell.
    func run(_ tool: String, _ arguments: [String]) -> CommandResult
    /// Literal addresses of an endpoint host (UDP), in resolver order.
    func resolve(_ host: String, port: Int) -> [String]
    /// One request on the UAPI socket of `interface`, which must be served by `pid`.
    func uapi(interface: String, pid: pid_t, request: String) throws -> String
    /// Primary network service (State:/Network/Global/IPv4 PrimaryService).
    func primaryService() -> String?
    /// DNS dictionary of Setup:/Network/Service/<service>/DNS; nil when absent.
    func dnsSetup(service: String) -> [String: Any]?
    /// Replaces (or with nil removes) that dictionary. Not persistent across reboots.
    func setDNSSetup(service: String, value: [String: Any]?) -> Bool
}

public enum WireGuardTools {
    public static let ifconfig = "/sbin/ifconfig"
    public static let route = "/sbin/route"
    public static let netstat = "/usr/sbin/netstat"
    public static let dscacheutil = "/usr/bin/dscacheutil"
    static let all: Set<String> = [ifconfig, route, netstat, dscacheutil]

    /// First non-scoped "default" entry of `netstat -nr` with a real gateway (not link#N).
    public static func defaultRoute(_ table: String) -> (gateway: String, interface: String)? {
        for line in table.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard fields.count >= 4, fields[0] == "default", !fields[1].hasPrefix("link#"), !fields[2].contains("I") else { continue }
            let parts = fields[1].split(separator: "%", maxSplits: 1).map(String.init)
            guard let (address, _) = WireGuardAddress.canonical(parts[0]) else { continue }
            if parts.count == 2 {
                guard parts[1].range(of: #"^[a-z]+[0-9]{1,5}$"#, options: .regularExpression) != nil else { continue }
                return (address + "%" + parts[1], fields[3])
            }
            return (address, fields[3])
        }
        return nil
    }
}

public final class SystemWireGuardHost: WireGuardHost {
    /// wireguard-go's fixed socket directory (root-owned; sockets are created 0600).
    public let uapiDirectory: String
    private let lock = NSLock()
    private var store: SCDynamicStore?

    public init(uapiDirectory: String = "/var/run/wireguard") { self.uapiDirectory = uapiDirectory }

    public func run(_ tool: String, _ arguments: [String]) -> CommandResult {
        guard WireGuardTools.all.contains(tool) else { return CommandResult(status: -1, output: "ferramenta não permitida") }
        do {
            let output = try Probe.run(tool, arguments, environment: ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"],
                                       identity: nil, timeout: 15_000)
            return CommandResult(status: output.status, output: output.text)
        } catch { return CommandResult(status: -1, output: error.localizedDescription) }
    }

    public func resolve(_ host: String, port: Int) -> [String] {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = AI_ADDRCONFIG
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { return [] }
        defer { freeaddrinfo(first) }
        var addresses: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if let address = entry.pointee.ai_addr,
               getnameinfo(address, entry.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let text = String(cString: buffer)
                if WireGuardAddress.canonical(text) != nil, !addresses.contains(text) { addresses.append(text) }
            }
            cursor = entry.pointee.ai_next
        }
        return addresses
    }

    public func uapi(interface: String, pid: pid_t, request: String) throws -> String {
        guard WireGuardTunnel.validInterface(interface) else { throw RuleViolation("Interface inválida.") }
        let path = uapiDirectory + "/" + interface + ".sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RuleViolation("Socket UAPI indisponível.") }
        defer { close(fd) }
        var noSignal: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw RuleViolation("Caminho do socket UAPI longo demais.") }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { throw UAPIUnavailable(code: errno) }
        // The socket must belong to this session's own wireguard-go, not to another process.
        var peer: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &length) == 0, peer == pid else {
            throw RuleViolation("O socket UAPI de \(interface) não pertence ao wireguard-go desta sessão.")
        }
        let data = Array(request.utf8)
        var written = 0
        while written < data.count {
            let count = data[written...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RuleViolation("Falha ao escrever no socket UAPI.") }
            written += count
        }
        var response = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while response.count < 1024 * 1024 {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { break }
            response += buffer.prefix(count)
            if response.count >= 2, response.suffix(2) == [10, 10] { break }
        }
        return String(decoding: response, as: UTF8.self)
    }

    private func dynamicStore() -> SCDynamicStore? {
        if store == nil { store = SCDynamicStoreCreate(nil, "com.luiz.vpngui.helper.wireguard" as CFString, nil, nil) }
        return store
    }

    public func primaryService() -> String? {
        lock.withLock {
            guard let store = dynamicStore(),
                  let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any] else { return nil }
            return global["PrimaryService"] as? String
        }
    }

    public func dnsSetup(service: String) -> [String: Any]? {
        lock.withLock {
            guard let store = dynamicStore() else { return nil }
            return SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(service)/DNS" as CFString) as? [String: Any]
        }
    }

    public func setDNSSetup(service: String, value: [String: Any]?) -> Bool {
        lock.withLock {
            guard let store = dynamicStore() else { return false }
            let key = "Setup:/Network/Service/\(service)/DNS" as CFString
            guard let value else {
                return SCDynamicStoreRemoveValue(store, key) || SCDynamicStoreCopyValue(store, key) == nil
            }
            return SCDynamicStoreSetValue(store, key, value as CFDictionary)
        }
    }
}

struct UAPIUnavailable: Error { let code: Int32 }

/// Brings a WireGuard tunnel up around the session's wireguard-go, the way wg-quick does on
/// macOS, without bash or profile hooks: keys over UAPI, addresses and MTU with ifconfig,
/// AllowedIPs as routes (0/1 + 128/1 for a full tunnel), a host route to each endpoint
/// through the physical gateway, and the tunnel's DNS on the primary network service.
///
/// Everything it changes outside the interface (endpoint routes, DNS) is written first to
/// a root-only record, undone when wireguard-go exits, and undone by the next helper start
/// if the helper itself died. Routes through the utun disappear with the interface.
final class WireGuardTunnel: SessionObserver {
    struct Record: Codable, Equatable {
        struct Route: Codable, Equatable {
            var destination: String
            var ipv6: Bool
            var gateway: String?
        }
        struct DNSChange: Codable, Equatable {
            var service: String
            /// Binary property list of the previous Setup: dictionary; nil when there was none.
            var original: Data?
            var servers: [String]
        }
        var token: String
        var interface: String?
        var routes: [Route] = []
        var dns: DNSChange?
    }

    let token: String
    let profile: WireGuardProfile
    let host: WireGuardHost
    let nameFile: String
    let recordPath: String
    /// Adds one line to the session log (the core queue does the enqueue).
    var emit: (String) -> Void = { _ in }
    /// Asks the session to stop after a setup failure.
    var fail: () -> Void = {}
    var interval: TimeInterval = 3
    var handshakeWarning: TimeInterval = 30
    /// Bounded waits for wireguard-go to create the interface and its UAPI socket.
    var startupTimeout: TimeInterval = 10

    private let queue = DispatchQueue(label: "com.luiz.vpngui.helper.wireguard")
    private let state = NSLock()
    private var ended = false
    private var loggedInterface: String?
    private var pid: pid_t = 0
    private var record: Record
    private var timer: DispatchSourceTimer?
    private var configuredAt: Date?
    private var handshakeSeen = false
    private var warnedNoHandshake = false
    private var endpoints: [(ip: String, ipv6: Bool)] = []
    private var lastDesired: [Record.Route]?

    /// One tunnel at a time may own the system DNS.
    private static let dnsLock = NSLock()
    private static var dnsOwner: String?

    init(token: String, profile: WireGuardProfile, host: WireGuardHost, nameFile: String, recordPath: String) {
        self.token = token; self.profile = profile; self.host = host
        self.nameFile = nameFile; self.recordPath = recordPath
        record = Record(token: token)
    }

    static func validInterface(_ name: String) -> Bool { name.range(of: #"^utun[0-9]{1,5}$"#, options: .regularExpression) != nil }

    private var isEnded: Bool { state.withLock { ended } }

    // MARK: SessionObserver

    func clientStarted(pid: pid_t) {
        queue.async { [self] in
            self.pid = pid
            do { try bringUp() }
            catch {
                guard !isEnded else { return }
                let message = (error as? RuleViolation)?.message ?? error.localizedDescription
                emit("\(WireGuardMarkers.failure) \(message)")
                fail()
            }
        }
    }

    /// wireguard-go's log names the interface: "DEBUG: (utun8) 2026/10/24 … Starting wireguard-go".
    func clientOutput(_ line: String) {
        guard let range = line.range(of: #"^(DEBUG|INFO|ERROR): \(utun[0-9]{1,5}\) "#, options: .regularExpression) else { return }
        let text = line[range]
        guard let open = text.firstIndex(of: "("), let close = text.firstIndex(of: ")") else { return }
        let name = String(text[text.index(after: open)..<close])
        state.withLock { if loggedInterface == nil { loggedInterface = name } }
    }

    func clientEnded() {
        state.withLock { ended = true }
        queue.sync { teardown() }
    }

    // MARK: Bring-up

    private func bringUp() throws {
        let interface = try waitForInterface()
        record.interface = interface
        try saveRecord()
        emit("[+] Interface do WireGuard: \(interface)")
        let resolved = try resolveEndpoints()
        let reply = try request(interface, try profile.uapiConfiguration(endpoints: resolved))
        try checkErrno(reply, "configurar as chaves no wireguard-go")
        emit("[#] wg setconf \(interface) (chaves e \(profile.peers.count) peer(s) pelo socket UAPI do wireguard-go)")
        for address in profile.addresses {
            if address.isIPv6 { try command(WireGuardTools.ifconfig, [interface, "inet6", address.text, "alias"]) }
            else { try command(WireGuardTools.ifconfig, [interface, "inet", address.text, address.address, "alias"]) }
        }
        try command(WireGuardTools.ifconfig, [interface, "mtu", String(profile.mtu ?? automaticMTU())])
        try command(WireGuardTools.ifconfig, [interface, "up"])
        if profile.table == .auto {
            for ip in profile.allowedIPs.sorted(by: { $0.prefix > $1.prefix }) { try addRoute(ip, interface) }
            if profile.routesAllIPv4 || profile.routesAllIPv6 { refreshEndpointRoutes() }
        }
        applyDNS()
        guard !isEnded else { return }
        configuredAt = Date()
        emit("\(WireGuardMarkers.ready) em \(interface).")
        startMonitor(interface)
    }

    /// wireguard-go writes the utun name to WG_TUN_NAME_FILE; its log line is a fallback.
    private func waitForInterface() throws -> String {
        let deadline = Date().addingTimeInterval(startupTimeout)
        while Date() < deadline {
            guard !isEnded else { throw RuleViolation("O wireguard-go encerrou antes de criar a interface.") }
            if let name = readNameFile() ?? state.withLock({ loggedInterface }) { return name }
            usleep(50_000)
        }
        throw RuleViolation("O wireguard-go não informou a interface criada em \(Int(startupTimeout)) s.")
    }

    private func readNameFile() -> String? {
        let fd = open(nameFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size < 64 else { return nil }
        var buffer = [UInt8](repeating: 0, count: 64)
        let count = Darwin.read(fd, &buffer, buffer.count)
        guard count > 0 else { return nil }
        let name = String(decoding: buffer.prefix(count), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return Self.validInterface(name) ? name : nil
    }

    /// The socket appears right after the interface; retry while it does not exist yet.
    private func request(_ interface: String, _ text: String) throws -> String {
        let deadline = Date().addingTimeInterval(startupTimeout)
        while true {
            do { return try host.uapi(interface: interface, pid: pid, request: text) }
            catch let unavailable as UAPIUnavailable where [ENOENT, ECONNREFUSED].contains(unavailable.code) {
                guard Date() < deadline, !isEnded else { throw RuleViolation("O socket UAPI do wireguard-go não ficou disponível.") }
                usleep(50_000)
            } catch let unavailable as UAPIUnavailable {
                throw RuleViolation("Socket UAPI do wireguard-go inacessível (\(String(cString: strerror(unavailable.code)))).")
            }
        }
    }

    private func checkErrno(_ reply: String, _ action: String) throws {
        let code = reply.split(separator: "\n").last { $0.hasPrefix("errno=") }.map { String($0.dropFirst(6)) }
        guard code == "0" else { throw RuleViolation("O wireguard-go recusou \(action) (errno=\(code ?? "?")).") }
    }

    /// Like `wg setconf`: host names are resolved by the helper, IPv4 first.
    private func resolveEndpoints() throws -> [String?] {
        endpoints = []
        return try profile.peers.map { peer in
            guard let endpoint = peer.endpoint else { return nil }
            let addresses: [String]
            if let (literal, _) = WireGuardAddress.canonical(endpoint.host) { addresses = [literal] }
            else { addresses = host.resolve(endpoint.host, port: endpoint.port) }
            guard let chosen = addresses.first(where: { !$0.contains(":") }) ?? addresses.first else {
                throw RuleViolation("Não foi possível resolver o servidor \(endpoint.host).")
            }
            let ipv6 = chosen.contains(":")
            if !endpoints.contains(where: { $0.ip == chosen }) { endpoints.append((chosen, ipv6)) }
            if chosen != endpoint.host { emit("[+] \(endpoint.host) resolvido para \(chosen)") }
            return ipv6 ? "[\(chosen)]:\(endpoint.port)" : "\(chosen):\(endpoint.port)"
        }
    }

    @discardableResult
    private func command(_ tool: String, _ arguments: [String], required: Bool = true, quiet: Bool = false) throws -> CommandResult {
        guard !isEnded else { throw RuleViolation("Sessão encerrada.") }
        let name = (tool as NSString).lastPathComponent
        if !quiet { emit("[#] \(name) \(arguments.joined(separator: " "))") }
        let result = host.run(tool, arguments)
        if required && result.status != 0 {
            let detail = result.output.trimmingCharacters(in: .whitespacesAndNewlines).prefix(300)
            throw RuleViolation("\(name) \(arguments.joined(separator: " ")) falhou (código \(result.status))\(detail.isEmpty ? "" : ": \(detail)").")
        }
        return result
    }

    private func addRoute(_ ip: WireGuardCIDR, _ interface: String) throws {
        let family = ip.isIPv6 ? "-inet6" : "-inet"
        if ip.isDefault {
            // Two halves are more specific than the default route, which stays untouched.
            let halves = ip.isIPv6 ? ["::/1", "8000::/1"] : ["0.0.0.0/1", "128.0.0.0/1"]
            for half in halves { try command(WireGuardTools.route, ["-q", "-n", "add", family, half, "-interface", interface]) }
            return
        }
        let current = host.run(WireGuardTools.route, ["-n", "get", family, ip.text])
        if current.status == 0, current.output.contains("interface: \(interface)\n") { return }
        try command(WireGuardTools.route, ["-q", "-n", "add", family, ip.text, "-interface", interface])
    }

    /// MTU of the interface behind the default route minus 80 (wg-quick's rule), else 1420.
    private func automaticMTU() -> Int {
        guard let interface = WireGuardTools.defaultRoute(host.run(WireGuardTools.netstat, ["-nr", "-f", "inet"]).output)?.interface else { return 1420 }
        let details = host.run(WireGuardTools.ifconfig, [interface]).output
        guard let range = details.range(of: #"mtu [0-9]+"#, options: .regularExpression),
              let mtu = Int(details[range].dropFirst(4)), mtu > 656 else { return 1420 }
        return mtu - 80
    }

    // MARK: Endpoint routes

    /// Keeps a host route to every endpoint through the current physical gateway, so the
    /// tunnel's own packets never enter the tunnel (wg-quick's set_endpoint_direct_route).
    private func refreshEndpointRoutes() {
        let gateway4 = profile.routesAllIPv4 ? WireGuardTools.defaultRoute(host.run(WireGuardTools.netstat, ["-nr", "-f", "inet"]).output)?.gateway : nil
        let gateway6 = profile.routesAllIPv6 ? WireGuardTools.defaultRoute(host.run(WireGuardTools.netstat, ["-nr", "-f", "inet6"]).output)?.gateway : nil
        var desired: [Record.Route] = []
        for endpoint in endpoints where endpoint.ipv6 ? profile.routesAllIPv6 : profile.routesAllIPv4 {
            desired.append(Record.Route(destination: endpoint.ip, ipv6: endpoint.ipv6, gateway: endpoint.ipv6 ? gateway6 : gateway4))
        }
        // Only when something changed: a refused route is not retried on every tick.
        guard desired != lastDesired else { return }
        lastDesired = desired
        for route in record.routes where !desired.contains(route) { deleteRoute(route) }
        record.routes.removeAll { !desired.contains($0) }
        for route in desired where !record.routes.contains(route) {
            let family = route.ipv6 ? "-inet6" : "-inet"
            // Without a gateway, a blackhole prevents a routing loop through the tunnel.
            let target = route.gateway.map { ["-gateway", $0] } ?? [route.ipv6 ? "::1" : "127.0.0.1", "-blackhole"]
            let result = try? command(WireGuardTools.route, ["-q", "-n", "add", family, route.destination] + target, required: false)
            if result?.status == 0 {
                record.routes.append(route)
                try? saveRecord()
            }
        }
    }

    private func deleteRoute(_ route: Record.Route) {
        let arguments = ["-q", "-n", "delete", route.ipv6 ? "-inet6" : "-inet", route.destination]
        emit("[#] route \(arguments.joined(separator: " "))")
        _ = host.run(WireGuardTools.route, arguments)
    }

    // MARK: DNS

    private func applyDNS() {
        guard !profile.dnsServers.isEmpty, !isEnded else { return }
        let claimed = Self.dnsLock.withLock { () -> Bool in
            guard Self.dnsOwner == nil || Self.dnsOwner == token else { return false }
            Self.dnsOwner = token
            return true
        }
        guard claimed else {
            emit("[!] Outro túnel WireGuard já controla o DNS do sistema; o DNS deste perfil não foi aplicado.")
            return
        }
        guard let service = host.primaryService(), Self.validService(service) else {
            emit("[!] Nenhum serviço de rede principal; o DNS do perfil não foi aplicado.")
            releaseDNS()
            return
        }
        setDNS(on: service, backup: host.dnsSetup(service: service))
    }

    private func setDNS(on service: String, backup: [String: Any]?) {
        let original = backup.flatMap { try? PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0) }
        record.dns = Record.DNSChange(service: service, original: original, servers: profile.dnsServers)
        // Recorded before the change: a crash right after it is still undone.
        try? saveRecord()
        var value: [String: Any] = ["ServerAddresses": profile.dnsServers]
        if !profile.dnsSearch.isEmpty { value["SearchDomains"] = profile.dnsSearch }
        let search = profile.dnsSearch.isEmpty ? "" : ", busca \(profile.dnsSearch.joined(separator: " "))"
        emit("[#] DNS \(profile.dnsServers.joined(separator: " "))\(search) no serviço de rede principal")
        if host.setDNSSetup(service: service, value: value) {
            flushDNS()
        } else {
            emit("[!] Não foi possível aplicar o DNS do perfil; o túnel segue com o DNS atual.")
            record.dns = nil
            try? saveRecord()
            releaseDNS()
        }
    }

    private func releaseDNS() { Self.dnsLock.withLock { if Self.dnsOwner == token { Self.dnsOwner = nil } } }

    static func validService(_ id: String) -> Bool { id.range(of: #"^[A-Za-z0-9-]{1,64}$"#, options: .regularExpression) != nil }

    static func servers(_ value: [String: Any]?) -> [String] { value?["ServerAddresses"] as? [String] ?? [] }

    /// Restores the backup only while the service still has this tunnel's servers.
    static func restore(_ change: Record.DNSChange, host: WireGuardHost) -> Bool {
        guard servers(host.dnsSetup(service: change.service)) == change.servers else { return false }
        let original = change.original.flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }
        return host.setDNSSetup(service: change.service, value: original)
    }

    private func flushDNS() { _ = host.run(WireGuardTools.dscacheutil, ["-flushcache"]) }

    /// After a network change (other primary service, or configd rewrote its Setup: keys)
    /// the tunnel's DNS is moved or applied again, like wg-quick's route monitor does.
    private func checkDNS() {
        guard let change = record.dns else { return }
        let primary = host.primaryService()
        if let primary, Self.validService(primary), primary != change.service {
            if Self.restore(change, host: host) { emit("[+] Rede principal mudou; DNS restaurado no serviço anterior.") }
            setDNS(on: primary, backup: host.dnsSetup(service: primary))
        } else if primary == change.service {
            let current = host.dnsSetup(service: change.service)
            if Self.servers(current) != change.servers {
                emit("[+] As configurações de rede mudaram; aplicando o DNS do túnel de novo.")
                setDNS(on: change.service, backup: current)
            }
        }
    }

    // MARK: Monitor

    private func startMonitor(_ interface: String) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in self?.tick(interface) }
        self.timer = timer
        timer.resume()
    }

    private func tick(_ interface: String) {
        guard !isEnded else { return }
        if !handshakeSeen, let reply = try? host.uapi(interface: interface, pid: pid, request: "get=1\n\n") {
            let handshakes = reply.split(separator: "\n").compactMap { line -> Int? in
                line.hasPrefix("last_handshake_time_sec=") ? Int(line.dropFirst("last_handshake_time_sec=".count)) : nil
            }
            if handshakes.contains(where: { $0 > 0 }) {
                handshakeSeen = true
                let server = profile.peers.compactMap(\.endpoint).first?.display ?? "o peer"
                emit("\(WireGuardMarkers.handshake) com \(server).")
            } else if !warnedNoHandshake, let configuredAt, Date().timeIntervalSince(configuredAt) >= handshakeWarning {
                warnedNoHandshake = true
                emit("[!] Nenhum handshake com o servidor após \(Int(handshakeWarning)) s. Confira o endpoint e se o servidor conhece a chave pública deste perfil.")
            }
        }
        if profile.table == .auto, profile.routesAllIPv4 || profile.routesAllIPv6 { refreshEndpointRoutes() }
        checkDNS()
    }

    // MARK: Teardown

    private func teardown() {
        timer?.cancel()
        timer = nil
        for route in record.routes { deleteRoute(route) }
        record.routes = []
        if let change = record.dns {
            if Self.restore(change, host: host) { emit("[#] DNS do serviço de rede principal restaurado") }
            else { emit("[!] O DNS do serviço de rede mudou durante o túnel; ele foi mantido como está.") }
            flushDNS()
            record.dns = nil
        }
        releaseDNS()
        unlink(nameFile)
        unlink(recordPath)
    }

    private func saveRecord() throws {
        try SecureFile.replace(recordPath, data: try JSONEncoder().encode(record), mode: 0o600)
    }

    // MARK: Recovery

    /// Undoes what earlier sessions left behind when the helper died before their cleanup.
    /// Records of sessions in `live` (still running or still being stopped) are kept.
    static func recover(directory: String, host: WireGuardHost, live: Set<String>) {
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] where entry.hasSuffix(".json") {
            let token = String(entry.dropLast(5))
            guard !live.contains(token) else { continue }
            let path = directory + "/" + entry
            if let (data, _) = try? SecureFile.read(path, limit: 256 * 1024),
               let record = try? JSONDecoder().decode(Record.self, from: data), record.token == token {
                for route in record.routes {
                    _ = host.run(WireGuardTools.route, ["-q", "-n", "delete", route.ipv6 ? "-inet6" : "-inet", route.destination])
                }
                if let change = record.dns, restore(change, host: host) {
                    _ = host.run(WireGuardTools.dscacheutil, ["-flushcache"])
                }
            }
            unlink(path)
        }
    }
}
