#!/bin/bash
# Notarizes and staples a Developer ID build. Run manually, after scripts/build.sh with
# SIGNING_IDENTITY="Developer ID Application: …" and TEAM_ID set.
#
#   NOTARY_PROFILE=<perfil já salvo com `xcrun notarytool store-credentials`> ./scripts/notarize.sh [OpenFortiDesk.app]
#
# No Apple ID, password or API key is read or stored by this script: the profile lives in
# your Keychain and is created by you beforehand. NOTARY_KEYCHAIN selects another keychain (CI).
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
app="${1:-$PWD/build/$version/OpenFortiDesk.app}"
profile="${NOTARY_PROFILE:?Defina NOTARY_PROFILE com o nome do perfil do notarytool já salvo no Keychain.}"

[[ -d "$app" ]] || { echo "App não encontrado: $app" >&2; exit 1; }
./scripts/verify-bundle.sh "$app"
for component in "$app/Contents/MacOS/VPNSupervisor" "$app/Contents/MacOS/VPNHelper" "$app"; do
    details=$(codesign -dvv "$component" 2>&1)
    grep -q "Authority=Developer ID Application" <<<"$details" || { echo "Não é Developer ID: $component" >&2; exit 1; }
    grep -q "Timestamp=" <<<"$details" || { echo "Sem carimbo de tempo seguro: $component" >&2; exit 1; }
    grep -q "flags=.*runtime" <<<"$details" || { echo "Sem hardened runtime: $component" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ditto -c -k --keepParent "$app" "$work/OpenFortiDesk.zip"
keychain=()
[[ -z "${NOTARY_KEYCHAIN:-}" ]] || keychain=(--keychain "$NOTARY_KEYCHAIN")
xcrun notarytool submit "$work/OpenFortiDesk.zip" --keychain-profile "$profile" ${keychain[@]+"${keychain[@]}"} --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
echo "Notarizado e grampeado: $app"
