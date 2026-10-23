OpenFortiDesk release candidate: macOS 13+, Apple Silicon arm64 only.

Changes: the SAML browser login after a refused saved session is no longer
rejected as a duplicate session, and a refused saved session that the Keychain
will not delete (written by VPNGUI.app) is not retried on every connection.
See CHANGELOG.md.

Developer ID signed, hardened, timestamped, notarized and stapled.
First launch requires macOS background-service approval and administrator approval
of the protected openfortivpn runtime. openfortivpn is an external Homebrew dependency.
Overlapping routes/DNS are not resolved; SAML logins queue on port 8020 and cookie
validity depends on the gateway. SIGKILL of a supervisor can leave an orphaned client.
Root registration and Homebrew lifecycle integration require isolated VM validation;
this candidate is not declared stable. Uninstall preserves profiles and Keychain.
