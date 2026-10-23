OpenFortiDesk release candidate: macOS 13+, Apple Silicon arm64 only.

Changes in rc.4:
- Configurações window (⌘,): menu bar icon, hide from the Dock on close, open at
  login, and an About tab.
- Update check: the app asks the public GitHub releases API (anonymously, at most
  every 4 hours, or on demand with Verificar atualizações…) and shows a discreet
  notice when a new version exists. It never downloads or runs anything; updating
  stays with Homebrew. Automatic checks can be turned off in Configurações.
- Service management is now the Serviço privilegiado tab of Configurações, with a
  short explanation of why the service exists. Gerenciar… opens it.
See CHANGELOG.md.

Updating from rc.3: quit OpenFortiDesk with Sair (this disconnects its VPNs), then
run `brew upgrade --cask luizmz94/openfortidesk/openfortidesk` and open the app.
Before `brew uninstall`, use Configurações… > Serviço privilegiado > Remover serviço.

Coming from rc.1 or rc.2: their maintenance command always fails in the Homebrew
sandbox, so `brew upgrade` stops without replacing anything. Unblock it once:
1. In the app, use Gerenciar… > Remover serviço, then quit with Sair.
2. Move /Applications/OpenFortiDesk.app to the Trash.
3. rm -rf "$(brew --caskroom)/openfortidesk"
4. brew install --cask luizmz94/openfortidesk/openfortidesk
5. Open the new app and activate the service again.

Developer ID signed, hardened, timestamped, notarized and stapled.
First launch requires macOS background-service approval and administrator approval
of the protected openfortivpn runtime. openfortivpn is an external Homebrew dependency.
Overlapping routes/DNS are not resolved; SAML logins queue on port 8020 and cookie
validity depends on the gateway. SIGKILL of a supervisor can leave an orphaned client.
Root registration and Homebrew lifecycle integration require isolated VM validation;
this candidate is not declared stable. Uninstall preserves profiles and Keychain.
