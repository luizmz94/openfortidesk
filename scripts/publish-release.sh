#!/bin/bash
# Draft only. Publishing is a separate final action after review and validation.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=luizmz94/openfortidesk
[[ $(git remote get-url origin) == "https://github.com/$repo.git" ]] || { echo 'Repository rename/origin update is pending.' >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo 'Commit and validate the complete working tree first.' >&2; exit 1; }
./scripts/audit-publication.py > /dev/null
visibility=$(gh repo view "$repo" --json visibility --jq .visibility)
[[ "$visibility" == PUBLIC ]] || { echo 'Publicity audit/visibility change is pending.' >&2; exit 1; }
default=$(gh repo view "$repo" --json defaultBranchRef --jq .defaultBranchRef.name)
[[ $(git branch --show-current) == "$default" ]]
[[ $(git rev-parse HEAD) == $(git ls-remote origin "refs/heads/$default" | cut -f1) ]]
version=$(sed -n 's/.*static let releaseVersion = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
app="${1:?Pass the signed and stapled OpenFortiDesk.app}"
report="${TEST_REPORT:?Set TEST_REPORT to the full graphical suite output for the validated commit}"
grep -q '^OK: 0 falha(s)' "$report"
# At least one completed successful real CI run for exactly this commit.
sha=$(git rev-parse HEAD)
[[ $(cat "$(dirname "$report")/TestCommit.txt") == "$sha" ]] || { echo 'Full suite must have passed on this exact clean commit.' >&2; exit 1; }
run=$(gh run list --repo "$repo" --commit "$sha" --workflow checks.yml --status success --json databaseId --jq '.[0].databaseId')
[[ -n "$run" ]] || { echo 'Successful CI for this commit is required.' >&2; exit 1; }
if gh release view "v$version" --repo "$repo" >/dev/null 2>&1; then echo 'Release exists; refusing replacement.' >&2; exit 1; fi
if git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null 2>&1; then echo 'Tag exists; refusing reuse.' >&2; exit 1; fi
./scripts/package-release.sh "$app"
out="$PWD/build/releases/$version"
notes=packaging/release-notes.md
gh release create "v$version" --repo "$repo" --target "$sha" --draft --prerelease \
  --title "OpenFortiDesk $version" --notes-file "$notes" \
  "$out/OpenFortiDesk-$version-arm64.zip" "$out/SHA256SUMS"
echo 'Draft uploaded. Verify artifacts and lifecycle checks before publishing the draft.'
