TunnelMac release candidate: macOS 13+, Apple Silicon arm64 only.

TunnelMac is the new name of OpenFortiDesk: the app now handles Fortinet SSL VPN
(openfortivpn) and OpenVPN profiles.

Changes in 0.4.0-rc.1:
- OpenVPN 2.7+ support next to Fortinet: import a single `.ovpn`/`.conf` or a
  Viscosity `.visc` folder (Importar perfil OpenVPN…, ⌘I). Profiles are reduced to an
  allowlist of tunnel directives; passwords stay in Keychain.
- The privileged service approves and freezes an OpenVPN installation the same way it
  does openfortivpn.
- New-connection chooser and a reorganized connection detail.
See CHANGELOG.md.

Coming from OpenFortiDesk (the bundle name changed, so the service registration
cannot be kept):
1. In OpenFortiDesk, use Configurações… > Serviço privilegiado > Remover serviço,
   then quit with Sair (this disconnects its VPNs).
2. brew uninstall --cask openfortidesk
3. brew untap luizmz94/openfortidesk
4. brew install --cask luizmz94/tunnelmac/tunnelmac
5. Open TunnelMac and activate the service again. Profiles and Keychain secrets are kept.

Developer ID signed, hardened, timestamped, notarized and stapled.
First launch requires macOS background-service approval and administrator approval
of the protected openfortivpn/OpenVPN runtime. openfortivpn and OpenVPN are external
Homebrew dependencies. Overlapping routes/DNS are not resolved; SAML logins queue on
port 8020 and cookie validity depends on the gateway. SIGKILL of a supervisor can
leave an orphaned client. Root registration and Homebrew lifecycle integration
require isolated VM validation; this candidate is not declared stable. Uninstall
preserves profiles and Keychain.
