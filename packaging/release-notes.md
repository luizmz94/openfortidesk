OpenFortiDesk release candidate: macOS 13+, Apple Silicon arm64 only.

Changes: `brew upgrade`, `reinstall` and `uninstall` work again. Homebrew 7 runs
cask steps in a sandbox that blocks the service registration and the helper; there
the maintenance command now only checks that OpenFortiDesk, its supervisors and its
openfortivpn are not running, and keeps the service registered for the upgraded app.
Quit the app with Sair before upgrading. Before `brew uninstall`, use
Gerenciar… > Remover serviço in the app. See CHANGELOG.md.

Coming from rc.1 or rc.2: their maintenance command always fails in the sandbox, so
`brew upgrade` stops without replacing anything. Unblock it once:
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
