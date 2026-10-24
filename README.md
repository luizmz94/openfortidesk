# OpenFortiDesk

Native macOS GUI for the original [openfortivpn](https://github.com/adrienverge/openfortivpn)
and, since 0.4.0, for [OpenVPN](https://openvpn.net/community/) 2.7+ profiles,
using SwiftUI/AppKit and a bundled SMAppService/XPC privileged helper. Independent
of, and not affiliated with, Fortinet or the openfortivpn project. No VPN executable
or Homebrew libraries are bundled in the distributed app.

**Status:** release candidate
[`v0.3.0-rc.5`](https://github.com/luizmz94/openfortidesk/releases/tag/v0.3.0-rc.5),
signed with Developer ID and notarized. Full Homebrew upgrade/uninstall lifecycle
validation is still pending, so it is not yet declared stable.

## Installation and first use

```sh
brew install --cask luizmz94/openfortidesk/openfortidesk
# Equivalent:
brew tap luizmz94/openfortidesk
brew install --cask openfortidesk
```

The tap lives at [luizmz94/homebrew-openfortidesk](https://github.com/luizmz94/homebrew-openfortidesk).
For a manual install, download `OpenFortiDesk-<version>-arm64.zip` and `SHA256SUMS`
from [Releases](https://github.com/luizmz94/openfortidesk/releases), check the
checksum with `shasum -a 256 -c SHA256SUMS`, unzip and move the app to
`/Applications`, and install openfortivpn with `brew install openfortivpn`.

The initial candidate targets **Apple Silicon (arm64)**. The code targets macOS 13+
with standard material fallbacks before macOS 26; the new Liquid Glass APIs require
macOS 26+. Only the host OS/architecture actually checked appears in the release
report. Intel is not offered until tested; Rosetta cannot run arm64 code on Intel.

Install the signed/notarized app in `/Applications/OpenFortiDesk.app`. Open
**Configurações… → Serviço privilegiado → Ativar serviço** (the **Gerenciar…** button
in the sidebar opens the same tab) and approve the background item in System Settings
→ General → Login Items. Return to the app, review **Aprovar openfortivpn…** and
approve with an administrator account. Each macOS user needs runtime approval.
Root is needed for openfortivpn/pppd to configure tunnels, routes and DNS; the GUI
always runs as a normal user. The runtime is copied to a protected root-owned
location, inventoried and integrity-checked before every connection.

## Usage

Use **+** to save a host, port, username and password or SAML authentication.
Passwords are stored in Keychain. Each profile has its own session, timer and
in-memory log. Multiple sessions may coexist; overlapping routes and DNS are not
resolved automatically. Closing the window (X/⌘W) leaves menu bar and VPNs running.
**Sair/⌘Q** asks to disconnect active sessions and waits for cleanup.

SAML opens the HTTPS gateway URL in your browser. Logins queue on callback port
8020. Cached cookies stay in Keychain for at most 30 minutes and remain valid only
as allowed by the gateway. The app does not inject a username into a signed SAML
URL. A rejected cookie permits one fresh browser login. Reconnect after a previously
established tunnel is limited to delays of 10, 20 and 40 seconds; rejected credentials,
TLS failures and initial connection failures do not loop automatically.

### OpenVPN

Install OpenVPN 2.7 or later (`brew install openvpn`), then use **Aprovar OpenVPN…**
in Configurações → Serviço privilegiado. The approval freezes the executable, its
libraries and the `dns-updown` script that configures the tunnel's DNS.

Use **Importar perfil OpenVPN…** (⌘I) with a single `.ovpn`/`.conf` that carries its
keys inline, or with a Viscosity `.visc` folder whose profile references `ca.crt`,
`cert.crt`, `key.key` and `ta.key`. Referenced files must sit inside the profile's
folder (no absolute paths, `..` or links leaving it); they are copied inline into a
private profile under `~/Library/Application Support/VPNGUI/OpenVPN` (0600). The
originals are not modified; a world-readable original key produces a warning.
Profiles that use `auth-user-pass` ask for a username and password (Keychain).

Only tunnel directives are kept. Scripts, plugins, `setenv`, management interfaces,
log/status files, OpenSSL providers and Windows-only options are removed with a
warning; unknown directives, proxies, PKCS#12, static `secret` keys and
password-protected private keys refuse the import. The helper repeats the check
and adds its own `script-security`, `dns-updown`, `auth-retry none` and inline
credentials. `auth RSA-SHA256` is offered as `auth SHA256` only after confirmation.
OpenVPN reconnects internally; `AUTH_FAILED` blocks retries until the credentials
are reviewed.

No OTP/PIN form or client-certificate UI is implemented for Fortinet. Certificate failures require
explicit review and approval of the profile's trusted digest; TLS is not disabled.

## Settings

**Configurações… (⌘,)** is in the app menu and in the menu bar window. Tabs:

- **Geral:** show the menu bar icon; hide from the Dock when the window is closed
  (always kept in the Dock while the menu bar icon is off, so the app never becomes
  invisible); open at login (`SMAppService.mainApp`, only in signed builds).
- **Atualizações:** update check options and how to update (see below).
- **Serviço privilegiado:** why the service exists, its state, runtime approval and
  **Remover serviço** (formerly the Gerenciar… sheet).
- **Sobre:** version, build, repository, release notes, license and notices.

Preferences live in the app's own `UserDefaults` (`com.luiz.vpngui`); nothing
sensitive is stored there.

## Update check

The app only checks for and announces new versions; it never downloads, opens or
runs anything, and never calls `brew`. It sends one anonymous `GET` to
`https://api.github.com/repos/luizmz94/openfortidesk/releases` (no token, cookies,
machine identifiers or connection data), at launch, on **Conectar** when the last
attempt is more than 4 hours old, from an hourly timer with the same interval, and
when you choose **Verificar atualizações…**. Checking never delays a connection.
Release candidates are offered by default only when the running version is one.
Turn off **Verificar automaticamente** in Configurações → Atualizações to stop
automatic checks; manual checks stay available.

A new version shows a small card in the main window (**Atualizar**, **Depois**,
**Ver novidades**), a line in the menu bar and a dot on the Atualizações tab. You
can skip a version. To install it, quit with **Sair** (this disconnects the VPNs),
then run:

```sh
brew upgrade --cask luizmz94/openfortidesk/openfortidesk
```

## Updates, migration and removal

After publication:

```sh
brew upgrade --cask luizmz94/openfortidesk/openfortidesk
brew uninstall --cask luizmz94/openfortidesk/openfortidesk
```

Upgrade/reinstall/uninstall call the installed app's restricted normal-user
maintenance command **before** bundle removal. Homebrew runs it inside its sandbox,
where the app cannot reach the service registration or the helper. There it only
checks, without contacting anything, that OpenFortiDesk, its supervisors and its
openfortivpn are not running, and keeps the service registered: the upgraded bundle
lands at the same path with the same identifiers and Team, so the registration stays
valid. Before `brew upgrade`, quit the app with **Sair** (this disconnects its VPNs);
otherwise brew stops and nothing is replaced.

Before `brew uninstall`, open the app and use **Configurações… → Serviço privilegiado
→ Remover serviço**, then
quit with **Sair**: the sandbox cannot remove the registration for you. Do not use
`--force` and do not reopen the app during maintenance. Outside the sandbox (for
example `./scripts/install.sh`), the same command requests normal quit, waits for
cleanup, has the authenticated helper prove global idle and unregisters the service.
This lifecycle still requires isolated VM validation before a stable release.

Moving from rc.1 or rc.2: their installed maintenance command always fails inside the
Homebrew sandbox, so `brew upgrade` stops. Use **Remover serviço** and **Sair** in the
app, move `/Applications/OpenFortiDesk.app` to the Trash, then run
`rm -rf "$(brew --caskroom)/openfortidesk"` and
`brew install --cask luizmz94/openfortidesk/openfortidesk`, and activate the service
again from the new app.

When the cask finds `/Applications/VPNGUI.app`, it requires the old service to be
removed first (checked with `launchctl print`): open VPNGUI, use **Remover serviço**,
quit with **Sair** and run brew again. For manual migration, run `./scripts/install.sh`
after building/signing/notarizing. The script stages and verifies the new bundle,
backs up both possible installed names in Application Support/VPNGUI/Backups and
requires cleanup/unregister before replacing either bundle. If an old helper does
not support the maintenance contract, open the old app, use **Remover serviço…**
and quit normally, then retry. Enable the service from the new app afterward.
No installed personal app is modified by build/test commands.

Normal uninstall retains profiles, Keychain entries and the approved root runtime.
To remove the root-managed runtime, first use **Configurações… → Serviço privilegiado
→ Remover serviço… → Remover serviço e arquivos gerenciados** (administrator authorization). To delete profiles afterward,
remove the data directory listed below; delete individual Keychain entries only if
you intend to discard those credentials. There is no destructive zap stanza.

Compatibility deliberately preserves `com.luiz.vpngui`, the helper/supervisor
identifiers, Mach service, authorization right and plist name. The internal GUI
executable remains VPNGUI. Renaming these would require a separate data/service
migration.

| Data | Location |
| --- | --- |
| Profiles (0600) and backups | `~/Library/Application Support/VPNGUI/` |
| Preferences | `UserDefaults` domain `com.luiz.vpngui` |
| Passwords | Keychain service `com.luiz.vpngui.password` |
| SAML cookies | Keychain service `com.luiz.vpngui.saml-cookie` |
| Protected runtime | `/private/var/db/com.luiz.vpngui.helper` |
| Logs | Memory only; bounded to 1,500 lines per session |

## Development and release

Use Xcode with macOS 26 SDK or newer. Preparation used Swift 6.4/macOS 27 SDK.

```sh
brew install openfortivpn
./scripts/build.sh
./scripts/test.sh
./build/0.3.0/OpenFortiDesk.app/Contents/MacOS/VPNGUI --release-checks
```

Build outputs are isolated under `build/<version>`; set OUTPUT_DIR to preserve other
bundles. Use ARCH=arm64 or ARCH=x86_64 to compile explicitly. Compiling a slice is
not proof it runs. Ad hoc builds render and test but fail closed for privileged
operations; they are not functional VPN releases. The full suite needs graphical
login, Keychain and anonymous XPC. Additional `--release-checks` do not replace it.

For your own distribution, provide SIGNING_IDENTITY and optional TEAM_ID to
`build.sh`, then NOTARY_PROFILE to `notarize.sh`. These inputs reference your own
Keychain identity/profile. App, helper and supervisor must share a verified Apple
Team. `package-release.sh` accepts only Developer ID signed, timestamped, hardened,
notarized/stapled arm64 bundles and computes SHA-256 after final ZIP packaging.
`publish-release.sh` gates draft creation on a clean default branch, full test report,
audit and successful CI. `update-tap.py` generates a versioned cask only from a
published, verified release. No private key export or signing secret in CI is needed.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
