# Changelog

## 0.3.0-rc.3 — 2026-10-23

- Fix `brew upgrade`, `reinstall` and `uninstall`, which always failed because
  Homebrew 7 runs cask steps inside a sandbox that blocks the service registration
  and the helper connection. Inside the sandbox the maintenance command now only
  verifies, through libproc, that the app, its supervisors and the managed
  openfortivpn are not running, and keeps the service registered for the upgraded
  bundle.
- The cask's VPNGUI.app migration requires the old service to be removed first, and
  the caveats explain that Remover serviço must be used before `brew uninstall`.
- The local checks run the maintenance command under Homebrew's sandbox profile.
- rc.1 and rc.2 cannot upgrade by themselves; see the release notes for the manual
  steps.

## 0.3.0-rc.2 — 2026-10-23

- Fix the SAML fallback after a refused saved session: the helper no longer rejects
  the browser login as a duplicate while the previous attempt's final events are
  still being acknowledged.
- A refused saved session that the Keychain will not delete (for example one written
  by VPNGUI.app) is no longer retried on every connection, and the failure is logged.

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
