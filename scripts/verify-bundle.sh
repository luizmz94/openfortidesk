#!/bin/bash
# Verify identity and trust boundaries independently of the build output.
set -euo pipefail
app="${1:?Pass OpenFortiDesk.app}"
[[ $(basename "$app") == OpenFortiDesk.app ]]
codesign --verify --strict --deep "$app"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") == com.luiz.vpngui ]]
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleName' "$app/Contents/Info.plist") == OpenFortiDesk ]]
team=$(codesign -dv "$app" 2>&1 | sed -n 's/^TeamIdentifier=//p')
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || { echo "Release requires a valid Apple signing Team; ad hoc artifacts are rejected." >&2; exit 1; }
for pair in "com.luiz.vpngui:$app" "com.luiz.vpngui.helper:$app/Contents/MacOS/VPNHelper" "com.luiz.vpngui.supervisor:$app/Contents/MacOS/VPNSupervisor"; do
    identifier=${pair%%:*}
    component=${pair#*:}
    details=$(codesign -dvv "$component" 2>&1)
    grep -q 'Authority=Developer ID Application' <<<"$details"
    grep -q 'Timestamp=' <<<"$details"
    grep -q 'flags=.*runtime' <<<"$details"
    codesign --verify --strict -R="identifier \"$identifier\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\"" "$component"
done
plutil -lint "$app/Contents/Info.plist" "$app/Contents/Library/LaunchDaemons/com.luiz.vpngui.helper.plist"
