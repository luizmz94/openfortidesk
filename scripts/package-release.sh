#!/bin/bash
# Package only an already signed, notarized, stapled artifact. No credentials in CI.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
release=$(sed -n 's/.*static let releaseVersion = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
app="${1:-$PWD/build/$version/OpenFortiDesk.app}"
[[ $(basename "$app") == OpenFortiDesk.app ]] || exit 1
./scripts/verify-bundle.sh "$app"
team=''
arch=''
for component in "$app" "$app/Contents/MacOS/VPNHelper" "$app/Contents/MacOS/VPNSupervisor"; do
    details=$(codesign -dvv "$component" 2>&1)
    grep -q 'Authority=Developer ID Application' <<<"$details"
    grep -q 'Timestamp=' <<<"$details"
    grep -q 'flags=.*runtime' <<<"$details"
    current_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$details")
    [[ -n "$current_team" && ( -z "$team" || "$team" == "$current_team" ) ]] || exit 1
    team="$current_team"
    executable="$component"
    [[ ! -d "$component" ]] || executable="$component/Contents/MacOS/VPNGUI"
    current_arch=$(lipo -archs "$executable")
    [[ -z "$arch" || "$arch" == "$current_arch" ]] || { echo 'Architecture mismatch' >&2; exit 1; }
    arch="$current_arch"
done
# Initial release is arm64 only. Cross-compilation is not an Intel execution test.
[[ "$arch" == arm64 ]] || { echo 'Only validated arm64 releases are supported by this packaging script.' >&2; exit 1; }
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist") == "$version" ]]
out="${RELEASE_DIR:-$PWD/build/releases/$release}"
mkdir -p "$out"
zip="$out/OpenFortiDesk-$release-$arch.zip"
[[ ! -e "$zip" ]] || { echo 'Release archive already exists; refusing overwrite.' >&2; exit 1; }
ditto -c -k --keepParent "$app" "$zip"
(cd "$out" && shasum -a 256 "$(basename "$zip")" > SHA256SUMS)
echo "$zip"
