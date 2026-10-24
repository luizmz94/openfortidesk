import SwiftUI
import AppKit

/// Protocol marks used only to tell the two connection types apart. Path data from
/// Simple Icons 13.21.0 (CC0-1.0); the marks themselves belong to Fortinet, Inc. and
/// OpenVPN Inc. This project is independent of both (see THIRD_PARTY_NOTICES.md).
enum ProtocolIcons {
    private static let paths: [VPNProtocol: String] = [
        .fortinet: "M0 9.785h6.788v4.454H0zm8.666-6.33h6.668v4.453H8.666zm0 12.637h6.668v4.454H8.666zm8.522-6.307H24v4.454h-6.812zM2.792 3.455C1.372 3.814.265 5.404 0 7.425v.506h6.788V3.454zM0 16.091v.554c.24 1.926 1.276 3.466 2.624 3.9h4.188v-4.454zm24-8.184v-.506c-.265-1.998-1.372-3.587-2.792-3.972h-4.02v4.454H24zM21.376 20.57c1.324-.458 2.36-1.974 2.624-3.9v-.554h-6.812v4.454Z",
        .openvpn: "M12 .357C5.385.357 0 5.69 0 12.254c0 4.36 2.358 8.153 5.896 10.204l.77-5.076a7.046 7.046 0 01-1.846-4.719c0-3.897 3.18-7.076 7.13-7.076 3.948 0 7.126 3.18 7.126 7.076 0 1.847-.717 3.488-1.846 4.77L18 22.51c3.59-2.05 6-5.899 6-10.258C24 5.69 18.615.357 12 .357zm-.05 8.157a3.786 3.786 0 00-3.796 3.795 3.738 3.738 0 002.461 3.54L9.13 23.643h5.64l-1.435-7.795c1.385-.564 2.41-1.898 2.41-3.54a3.786 3.786 0 00-3.795-3.794z",
    ]

    static func image(_ kind: VPNProtocol) -> NSImage? {
        guard let path = paths[kind] else { return nil }
        let svg = "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"\(path)\"/></svg>"
        guard let image = NSImage(data: Data(svg.utf8)) else { return nil }
        image.isTemplate = true
        return image
    }
}

extension VPNProtocol {
    /// Brand colors published with the marks.
    var brandColor: Color {
        self == .fortinet ? Color(red: 0xEE / 255, green: 0x31 / 255, blue: 0x24 / 255)
                          : Color(red: 0xEA / 255, green: 0x7E / 255, blue: 0x20 / 255)
    }
    var fallbackSymbol: String { self == .fortinet ? "shield.lefthalf.filled" : "lock.shield" }
}

struct ProtocolIcon: View {
    let kind: VPNProtocol
    var size: CGFloat = 28
    var body: some View {
        Group {
            if let image = ProtocolIcons.image(kind) {
                Image(nsImage: image).resizable().renderingMode(.template).interpolation(.high)
            } else {
                Image(systemName: kind.fallbackSymbol).resizable()
            }
        }
        .aspectRatio(contentMode: .fit)
        .foregroundStyle(kind.brandColor)
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
