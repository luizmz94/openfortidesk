import Foundation
import Security
import VPNHelperShared

/// Consent for the distinct, restricted operations (approve/update/remove the runtime).
public protocol AdminAuthorizing: AnyObject {
    /// Blocks while the system asks for administrator credentials in the requester's session.
    func authorize(_ externalForm: Data) -> Bool
}

/// Authorization Services check on an AuthorizationRef created by the app.
/// The right is (re)defined by the root helper with rule `authenticate-admin`
/// (the system controls credential caching and whether another prompt is needed).
/// Because `config.add.` lets any user create a
/// right, an existing definition is checked and rewritten if it is not exactly that rule.
public final class SystemAdminAuthorizer: AdminAuthorizing {
    public init() {}
    static let rule = "authenticate-admin"

    public static func definitionIsExpected(_ definition: [String: Any]?) -> Bool {
        guard let definition, definition["class"] as? String == "rule" else { return false }
        // A matching rule name does not make an `allow` class safe. Likewise, a
        // zero-of-N threshold must not bypass the authenticate-admin subrule.
        if let threshold = definition["kofn"], (threshold as? NSNumber)?.intValue != 1 { return false }
        if let rule = definition["rule"] as? [String] { return rule == [Self.rule] }
        if let rule = definition["rule"] as? String { return rule == Self.rule }
        return false
    }

    private func ensureRight() -> Bool {
        var current: CFDictionary?
        let status = AuthorizationRightGet(HelperConstants.authorizationRight, &current)
        if status == errAuthorizationSuccess, Self.definitionIsExpected(current as? [String: Any]) { return true }
        var own: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &own) == errAuthorizationSuccess, let own else { return false }
        defer { AuthorizationFree(own, []) }
        let set = AuthorizationRightSet(own, HelperConstants.authorizationRight, Self.rule as CFString,
                                        "TunnelMac quer aprovar ou remover a cópia protegida de um cliente VPN (openfortivpn, OpenVPN ou wireguard-go)." as CFString, nil, nil)
        guard set == errAuthorizationSuccess else { return false }
        var verified: CFDictionary?
        return AuthorizationRightGet(HelperConstants.authorizationRight, &verified) == errAuthorizationSuccess
            && Self.definitionIsExpected(verified as? [String: Any])
    }

    public func authorize(_ externalForm: Data) -> Bool {
        guard externalForm.count == MemoryLayout<AuthorizationExternalForm>.size, ensureRight() else { return false }
        var form = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &form) { _ = externalForm.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess, let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        return HelperConstants.authorizationRight.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(reference, &rights, nil, [.interactionAllowed, .extendRights], nil) == errAuthorizationSuccess
            }
        }
    }
}
