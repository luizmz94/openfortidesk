# OpenFortiDesk Homebrew tap — pending publication

Planned repository: https://github.com/luizmz94/homebrew-openfortidesk

This directory is a prepared tap source, not a published/installable tap. There is
no cask until an actual signed/notarized release asset exists. The app repository
publication is blocked by private information in its reachable history.

The app's scripts/update-tap.py reads a **published** release and verifies the
actual download digest and stapled bundle before creating Casks/openfortidesk.rb.
It uses the ordinary gh login, never a new cross-repository PAT. Do not commit test
archives, ad hoc builds, fake checksums or draft release URLs.

After publication:

```sh
brew install --cask luizmz94/openfortidesk/openfortidesk
brew upgrade --cask luizmz94/openfortidesk/openfortidesk
brew uninstall --cask luizmz94/openfortidesk/openfortidesk
```

The cask's uninstall_preflight_steps runs the installed app's fixed maintenance command
as the normal user before Homebrew removes the app artifact. A normal quit request
allows the user to cancel; pending cleanup, an unreachable/old helper, another
user's active VPN or unregister failure aborts removal. Never force the uninstall.
The first background-service/runtime approval occurs in the app, not a postflight.
Profiles, Keychain secrets and root-managed runtime survive uninstall. No zap is
provided. See the app README for administrator-authorized runtime removal.

Validate generated changes with brew style, brew audit --cask --online and brew
livecheck. Test installation by the fully qualified token in an isolated macOS VM;
do not alter a personal installation or active VPN to validate this tap.
