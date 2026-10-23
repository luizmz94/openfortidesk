# Security

## Reporting

Do not post exploits, secrets or real VPN details in public issues. GitHub private
vulnerability reporting has **not been enabled or verified by this preparation**.
Until it is enabled, ask the maintainer to establish a private reporting channel
without disclosing sensitive details. No private contact address or response-time
commitment is published. There has been no independent security audit.

Include version/build, macOS, architecture and a reproduction with fictitious
profiles. Remove users, gateways, cookies, passwords, tokens and SAML URLs from
attachments. Never send a private key or Keychain export.

## Trust boundaries

The GUI runs as the logged-in user. A bundled LaunchDaemon runs as root, registered
through SMAppService and approved by macOS. Both XPC peers require an Apple-issued
signature with the expected legacy identifier and the same certificate Team ID.
Ad hoc builds cannot enable privileged operations. No sudo or deprecated privilege
fallback is provided.

The helper accepts typed, bounded operations, not shell commands, writable output
paths, arbitrary PIDs or argument vectors. The protected runtime is copied from the
user's inspected openfortivpn installation after administrator authorization.
The helper verifies its integrity before every start. Initial approval trusts the
inspected local files; hashes alone do not establish upstream provenance.

Passwords and SAML cookies use Keychain and authenticated XPC, then anonymous
file descriptors. They are excluded from argv, environment, JSON and logs. TLS is
not disabled; trusting a certificate digest requires explicit profile approval.
Closing the window preserves sessions; Sair requests normal disconnect and waits
for cleanup. Lost GUI/XPC connections stop their sessions; lost helper channels
ask supervisors to stop normally.

Maintenance runs as a normal user through the same authenticated helper channel.
A global idle check rejects active sessions and surviving supervisors; a helper
start gate remains held during unregister. Refusal, missing proof, protocol mismatch,
timeout or unregister error aborts bundle replacement. No root app scripts are run.
An old helper without this operation must be removed through the old app first.

## Known limitations

A direct SIGKILL of a supervisor can leave an orphaned openfortivpn. Do not use
killall, forced termination or launchctl bootout as a cleanup substitute. Overlapping
routes/DNS are not resolved automatically. Gateway, IdP, openfortivpn and macOS
behavior still affect authentication, TLS and network cleanup. A globally unregistered
service cannot be made transactional with an arbitrary external file manager:
do not reopen the app during package maintenance.

Normal uninstall preserves profiles, Keychain secrets and the root-managed runtime.
Use Gerenciar → Remover serviço e arquivos gerenciados before uninstall to request
administrator-authorized runtime removal. Do not manually delete root state while
it is in use. No broad zap stanza deletes credentials. Forks need their own identity
and notarization. Do not run fork PR workflows with signing/notarization secrets.
