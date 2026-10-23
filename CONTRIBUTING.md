# Contributing

OpenFortiDesk uses SwiftUI/AppKit, SMAppService and authenticated XPC. The original
openfortivpn remains an external dependency. Do not implement a VPN protocol or
bundle a fork of its executable.

Use Xcode with the macOS 26 SDK or newer (local preparation used Swift 6.4 and the
macOS 27 SDK). Deployment target: macOS 13; recent APIs require fallbacks.

```sh
brew install openfortivpn
./scripts/build.sh
./scripts/test.sh
```

Set OUTPUT_DIR to preserve builds in use, and ARCH=arm64 or ARCH=x86_64 to
cross-compile. Compilation alone does not validate an architecture. Full checks
require a logged-in graphical session, Keychain, local XPC and loopback access;
a restricted shell or CI runner may block them. Report those failures as blocked,
not successful. The test runner uses separate data, disposable Keychain services,
anonymous XPC listeners and harmless child processes. It never registers a daemon,
connects to a VPN, requests root or changes routes/DNS.

Ad hoc builds compile and render but fail closed for privileged operations.
Fork distributors must use their own Apple identity and notarization profile:

```sh
SIGNING_IDENTITY='Developer ID Application: Your Name (YOURTEAMID)' \
  TEAM_ID=YOURTEAMID ./scripts/build.sh
NOTARY_PROFILE=your-keychain-profile ./scripts/notarize.sh
./scripts/package-release.sh
```

These are contributor inputs, not project credentials. PR checks run on GitHub-hosted
macOS with read permissions and no secrets; they run the real suite, and
graphical-session failures remain failures. Releases are built by the manually
triggered `release` workflow on the maintainer's self-hosted Mac; its signing and
notarization secrets exist only in the protected `release` environment.

Keep PRs focused and describe the trigger, resulting behavior and checks performed.
Changes to helper operations, XPC trust, runtime integrity, maintenance or persistence
require explicit maintainer review. Read SECURITY.md before changing these boundaries.
Preserve the original work when updating specifications or UI assets.

Never commit passwords, tokens, cookies, real VPN profiles, private certificates,
Keychain exports, personal signing profiles or client screenshots. Do not use
personal VPNs or the installed service for automated integration tests. Full
install/upgrade/uninstall validation belongs in an isolated macOS VM, with distinct
service identifiers and root state. Check cancellation, cleanup timeout, unregister
failure, data retention and reinstall there before promoting a candidate to stable.

For future submission to homebrew/cask, satisfy the current official acceptance,
public-interest, platform, security, verifiable-download and livecheck policies.
A private tap does not imply eligibility or Homebrew endorsement. This task does
not submit an official Homebrew PR.
