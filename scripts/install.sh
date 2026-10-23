#!/bin/bash
# Normal-user installation/migration. Never changes the personal app during tests.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(id -u) != 0 ]] || { echo 'Run as your normal user, not root.' >&2; exit 1; }
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
source_app="${1:-$PWD/build/$version/OpenFortiDesk.app}"
target=/Applications/OpenFortiDesk.app
legacy=/Applications/VPNGUI.app
codesign --verify --strict --deep "$source_app"
spctl --assess --type execute "$source_app"
xcrun stapler validate "$source_app"
[[ "$source_app" != "$target" && "$source_app" != "$legacy" ]] || exit 1
backups="$HOME/Library/Application Support/VPNGUI/Backups/$(date +%Y%m%d%H%M%S)-$$"
mkdir -p "$backups"
for installed in "$legacy" "$target"; do
    if [[ -d "$installed" ]]; then
        ditto "$installed" "$backups/$(basename "$installed")"
        codesign --verify --strict --deep "$backups/$(basename "$installed")"
    fi
done
# Stage and verify before requesting any shutdown. Refusal/unregister errors leave
# both installed bundles untouched. This command accepts no caller-supplied operation.
stage=$(mktemp -d /Applications/.OpenFortiDesk-install.XXXXXX)
installed_ok=false
finish_install() {
    if [[ "$installed_ok" != true ]]; then
        for installed in "$legacy" "$target"; do
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
ditto "$source_app" "$stage/OpenFortiDesk.app"
codesign --verify --strict --deep "$stage/OpenFortiDesk.app"
"$source_app/Contents/MacOS/VPNGUI" --prepare-for-maintenance
# Only after acknowledged global cleanup AND successful unregister.
for installed in "$legacy" "$target"; do
    if [[ -d "$installed" ]]; then mv "$installed" "$stage/$(basename "$installed").previous"; fi
done
if ! mv "$stage/OpenFortiDesk.app" "$target"; then
    for installed in "$legacy" "$target"; do
        [[ ! -d "$stage/$(basename "$installed").previous" ]] || mv "$stage/$(basename "$installed").previous" "$installed"
    done
    exit 1
fi
installed_ok=true
echo "Installed: $target. Backup: $backups"
echo 'Open Gerenciar… → Ativar serviço; approve in System Settings if requested.'
