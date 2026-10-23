import Foundation
import VPNHelperShared

/// NSXPCListener delegate of the helper.
///
/// Code identity is enforced by the system on the audit token of each connection:
/// `setConnectionCodeSigningRequirement` on the listener rejects a non-matching peer before
/// this delegate runs, and `setCodeSigningRequirement` on the accepted connection re-checks
/// every message. The delegate adds the user policy (no root client) and binds the
/// connection to a `HelperCore.Client` (uid + audit session from the same connection).
public final class HelperListenerDelegate: NSObject, NSXPCListenerDelegate {
    let core: HelperCore
    /// nil = fail closed: every connection is refused (ad hoc or untrusted helper build).
    let clientRequirement: String?

    public init(core: HelperCore, clientRequirement: String?) {
        self.core = core
        self.clientRequirement = clientRequirement
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let clientRequirement, CodeTrust.compiles(clientRequirement) else { return false }
        guard connection.effectiveUserIdentifier != 0 else { return false }
        connection.setCodeSigningRequirement(clientRequirement)
        connection.exportedInterface = HelperInterfaces.helper()
        connection.remoteObjectInterface = HelperInterfaces.client()
        let peer = ClientSinkProxy(connection: connection)
        let client = core.connect(uid: connection.effectiveUserIdentifier, auditSession: connection.auditSessionIdentifier,
                                  sink: peer.deliver)
        connection.exportedObject = HelperEndpoint(core: core, client: client)
        let core = self.core
        connection.invalidationHandler = { core.disconnect(client) }
        connection.interruptionHandler = { core.disconnect(client) }
        connection.resume()
        return true
    }
}

/// Exported object: forwards the raw request; HelperCore decodes, validates and checks state.
final class HelperEndpoint: NSObject, VPNHelperXPC {
    let core: HelperCore
    let client: HelperCore.Client
    init(core: HelperCore, client: HelperCore.Client) { self.core = core; self.client = client }
    func perform(_ request: Data, reply: @escaping (Data) -> Void) { core.handle(request, from: client, reply: reply) }
}

/// Sends batches to the app; a transport error drops the connection (and its sessions).
final class ClientSinkProxy {
    weak var connection: NSXPCConnection?
    init(connection: NSXPCConnection) { self.connection = connection }
    func deliver(_ batch: EventBatch, acknowledged: @escaping () -> Void) {
        guard let connection else { return }
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in connection.invalidate() } as? VPNHelperClientXPC
        proxy?.deliver(MessageCodec.encode(batch)) { acknowledged() }
    }
}
