#!/usr/bin/env python3
"""Generate the tap only from a published, signed, stapled arm64 release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

REPO = 'luizmz94/openfortidesk'

def command(*args):
    return subprocess.check_output(args, text=True).strip()

def cask(version, digest):
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\.\d+)?', version):
        raise ValueError('Invalid version')
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('Invalid SHA-256')
    return r'''cask "openfortidesk" do
  version "%s"
  sha256 "%s"

  url "https://github.com/luizmz94/openfortidesk/releases/download/v#{version}/OpenFortiDesk-#{version}-arm64.zip"
  name "OpenFortiDesk"
  desc "Native GUI for the original openfortivpn"
  homepage "https://github.com/luizmz94/openfortidesk"

  livecheck do
    url :url
    strategy :github_releases do |json|
      json.filter_map do |release|
        next if release["draft"]

        release["tag_name"][/\Av?(\d+\.\d+\.\d+(?:-rc\.\d+)?)\z/i, 1]
      end
    end
  end

  depends_on arch: :arm64
  depends_on formula: "openfortivpn"
  depends_on macos: :ventura

  app "OpenFortiDesk.app"

  preflight_steps do
    if_path_exists "VPNGUI.app", base: :appdir do
      run "OpenFortiDesk.app/Contents/MacOS/VPNGUI",
          args:         ["--prepare-for-maintenance"],
          base:         :staged_path,
          sudo:         false,
          must_succeed: true
      move "VPNGUI.app", "~/Library/Application Support/VPNGUI/Backups/VPNGUI-before-OpenFortiDesk.app",
           source_base: :appdir,
           overwrite:   false
    end
  end

  uninstall_preflight_steps do
    run "OpenFortiDesk.app/Contents/MacOS/VPNGUI",
        args:         ["--prepare-for-maintenance"],
        base:         :appdir,
        sudo:         false,
        must_succeed: true
  end

  caveats <<~EOS
    First use: open OpenFortiDesk, activate its service, approve it in System
    Settings and approve the protected openfortivpn runtime. Release candidate:
    isolated root lifecycle integration is not yet validated. Profiles, Keychain
    secrets and the protected runtime survive uninstall. Do not reopen the app
    during an upgrade. See SECURITY.md before removing managed root files.
  EOS
end
''' % (version, digest)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('--tap', type=Path, default=Path(__file__).resolve().parent.parent.parent / 'homebrew-openfortidesk',
                        help='checkout of luizmz94/homebrew-openfortidesk (default: next to this repository)')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-rc\.\d+)?', args.tag):
        parser.error('Invalid release tag')
    release = json.loads(command('gh', 'release', 'view', args.tag, '--repo', REPO,
                                 '--json', 'isDraft,isPrerelease,assets,tagName'))
    if release['isDraft'] or release['tagName'] != args.tag:
        raise SystemExit('Only an existing published release can populate the tap')
    version = args.tag[1:]
    asset = f'OpenFortiDesk-{version}-arm64.zip'
    if asset not in [a['name'] for a in release['assets']]:
        raise SystemExit('The required release asset is absent')
    with tempfile.TemporaryDirectory(prefix='openfortidesk-tap-') as tmp:
        command('gh', 'release', 'download', args.tag, '--repo', REPO, '--pattern', asset,
                '--pattern', 'SHA256SUMS', '--dir', tmp)
        root = Path(tmp)
        digest = hashlib.sha256((root / asset).read_bytes()).hexdigest()
        if f'{digest}  {asset}' not in (root / 'SHA256SUMS').read_text().splitlines():
            raise SystemExit('Published checksum mismatch')
        command('ditto', '-x', '-k', str(root / asset), str(root / 'unpacked'))
        app = root / 'unpacked/OpenFortiDesk.app'
        command(str(Path(__file__).resolve().parent / 'verify-bundle.sh'), str(app))
        if command('/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleShortVersionString', str(app / 'Contents/Info.plist')) != version.split('-')[0]:
            raise SystemExit('Bundle version differs from the release tag')
        command('xcrun', 'stapler', 'validate', str(app))
        command('spctl', '--assess', '--type', 'execute', str(app))
        for binary in ('VPNGUI', 'VPNHelper', 'VPNSupervisor'):
            if command('lipo', '-archs', str(app / 'Contents/MacOS' / binary)) != 'arm64':
                raise SystemExit('Release architectures do not match the cask')
        target = args.tap / 'Casks/openfortidesk.rb'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(cask(version, digest))
        print(target)

if __name__ == '__main__':
    main()
