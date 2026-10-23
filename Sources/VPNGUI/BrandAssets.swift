import SwiftUI
import AppKit

@MainActor
enum BrandAssets {
    static let menuIcon: NSImage? = {
        guard let image = Bundle.main.image(forResource: "MenuBarIconTemplate") else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 18, height: 18)
        return image
    }()
    static let lightSymbol = Bundle.main.image(forResource: "BrandSymbol")
    static let darkSymbol = Bundle.main.image(forResource: "BrandSymbolDark")
}

struct BrandSymbol: View {
    var size: CGFloat = 32
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        Group {
            if let image = scheme == .dark ? BrandAssets.darkSymbol : BrandAssets.lightSymbol {
                Image(nsImage: image).resizable().scaledToFit()
            } else {
                Image(systemName: "network.badge.shield.half.filled").resizable().scaledToFit()
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
