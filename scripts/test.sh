#!/bin/bash
# Local checks in an isolated runner bundle. No VPN, privileges, network or service registration.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
out="${OUTPUT_DIR:-$PWD/build/$version}"
SIGNING_IDENTITY=- TEAM_ID= OUTPUT_DIR="$out" ./scripts/build.sh
# Launch the test executable as a normal macOS app, so Keychain, loopback and XPC use the
# same environment as the actual app, rather than a restricted shell. Always ad hoc.
runner="$out/VPNGUILocalChecks-$version.app"
runner_identifier="com.luiz.vpngui.local-checks.v${version//./-}"
if pgrep -f "$runner/Contents/MacOS/VPNGUI" >/dev/null 2>&1; then
    echo "Test runner is already running; use a different OUTPUT_DIR." >&2; exit 1
fi
rm -rf "$runner"
mkdir -p "$runner/Contents/MacOS"
cp "$out/OpenFortiDesk.app/Contents/MacOS/VPNGUI" "$runner/Contents/MacOS/VPNGUI"
cp "$out/OpenFortiDesk.app/Contents/MacOS/VPNSupervisor" "$runner/Contents/MacOS/VPNSupervisor"
cp "$out/OpenFortiDesk.app/Contents/Info.plist" "$runner/Contents/Info.plist"
cp -R "$out/OpenFortiDesk.app/Contents/Resources" "$runner/Contents/Resources"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $runner_identifier" "$runner/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleName OpenFortiDesk Local Checks' "$runner/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleDisplayName OpenFortiDesk Local Checks' "$runner/Contents/Info.plist"
codesign --force --sign - --identifier com.luiz.vpngui.supervisor "$runner/Contents/MacOS/VPNSupervisor"
codesign --force --sign - --identifier "$runner_identifier" "$runner"
if [[ "${1:-}" == "--prepare-only" ]]; then
    printf 'Test runner preparado: %s\n' "$runner"
    exit 0
fi
rm -f "$out/TestResults.txt" "$out/TestResults.txt.stderr" "$out/TestCommit.txt"
open -W -n "$runner" --args --headless
cat "$out/TestResults.txt"
if ! /usr/bin/grep -q '^OK: 0 falha(s)' "$out/TestResults.txt"; then exit 1; fi

# Attestation used by draft publication; dirty development runs still run normally.
rm -f "$out/TestCommit.txt"
if [[ -z $(git status --porcelain) ]]; then git rev-parse HEAD > "$out/TestCommit.txt"; fi
