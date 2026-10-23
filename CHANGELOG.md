# Changelog

## 0.3.0-rc.1 — 2026-10-23

- Rename the distributed bundle and visible product to OpenFortiDesk.
- Preserve legacy app/helper identifiers, profiles and Keychain services.
- Add normal-user maintenance with normal quit, global helper idle verification,
  a start gate and successful unregister required before replacing a bundle.
- Preserve backups when migrating VPNGUI.app to OpenFortiDesk.app.
- Package only Developer ID signed, notarized, stapled arm64 releases; generate
  final ZIP checksums and prepare a Homebrew tap from verified release assets.
- Keep the existing Liquid Glass UI, close-window behavior, V/node icon and
  authorization hardening developed before this release preparation.
