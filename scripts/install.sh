#!/bin/bash
# Normal-user installation/migration. Never changes the personal app during tests.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(id -u) != 0 ]] || { echo 'Run as your normal user, not root.' >&2; exit 1; }
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
source_app="${1:-$PWD/build/$version/TunnelMac.app}"
target=/Applications/TunnelMac.app
installed_apps=(/Applications/VPNGUI.app /Applications/OpenFortiDesk.app "$target")
codesign --verify --strict --deep "$source_app"
spctl --assess --type execute "$source_app"
xcrun stapler validate "$source_app"
for installed in "${installed_apps[@]}"; do [[ "$source_app" != "$installed" ]] || exit 1; done
backups="$HOME/Library/Application Support/VPNGUI/Backups/$(date +%Y%m%d%H%M%S)-$$"
mkdir -p "$backups"
for installed in "${installed_apps[@]}"; do
    if [[ -d "$installed" ]]; then
        ditto "$installed" "$backups/$(basename "$installed")"
        codesign --verify --strict --deep "$backups/$(basename "$installed")"
    fi
done
# Stage and verify before requesting any shutdown. Refusal/unregister errors leave
# both installed bundles untouched. This command accepts no caller-supplied operation.
stage=$(mktemp -d /Applications/.TunnelMac-install.XXXXXX)
installed_ok=false
finish_install() {
    if [[ "$installed_ok" != true ]]; then
        for installed in "${installed_apps[@]}"; do
            if [[ -d "$stage/$(basename "$installed").previous" && ! -e "$installed" ]]; then
                mv "$stage/$(basename "$installed").previous" "$installed" || {
                    echo "Rollback needs attention: $stage; backup: $backups" >&2
                    return
                }
            fi
        done
    fi
    rm -rf "$stage"
}
trap finish_install EXIT
ditto "$source_app" "$stage/TunnelMac.app"
codesign --verify --strict --deep "$stage/TunnelMac.app"
"$source_app/Contents/MacOS/VPNGUI" --prepare-for-maintenance
# Only after acknowledged global cleanup AND successful unregister.
for installed in "${installed_apps[@]}"; do
    if [[ -d "$installed" ]]; then mv "$installed" "$stage/$(basename "$installed").previous"; fi
done
if ! mv "$stage/TunnelMac.app" "$target"; then
    for installed in "${installed_apps[@]}"; do
        [[ ! -d "$stage/$(basename "$installed").previous" ]] || mv "$stage/$(basename "$installed").previous" "$installed"
    done
    exit 1
fi
installed_ok=true
echo "Installed: $target. Backup: $backups"
echo 'Open Configurações… → Serviço privilegiado → Ativar serviço; approve in System Settings if requested.'
