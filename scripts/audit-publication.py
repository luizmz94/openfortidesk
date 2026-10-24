#!/usr/bin/env python3
"""Local, redacted privacy/secret inventory; not a substitute for a secret scanner.
Scans every reachable blob, current public source files and commit messages. Does
not print matched text or send code to any service. Exit 1 means publication blocked.
"""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
RULES = {
    'private-key': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'github-token': rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})',
    'cloud-key': rb'AKIA[0-9A-Z]{16}',
    'personal-path': rb'/Users/[A-Za-z0-9_-]+/',
    'personal-email': rb'[A-Za-z0-9._+-]+@(?:hotmail|gmail|outlook|icloud)\.com',
    'client-gateway': rb'(?:server:|host:|HostPortInput\.split\()\s*"[^"\n]*[A-Za-z0-9.-]+\.(?:com|com\.br|net|org)(?=[:/"\s])',
    'personal-signing-identity': rb'Developer ID Application: (?!Your Name|Name|<)[A-Za-z ]+\([A-Z0-9]{10}\)',
}

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def scan(data, location, findings):
    for kind, pattern in RULES.items():
        lines = [n for n, line in enumerate(data.splitlines(), 1) if re.search(pattern, line)]
        if lines:
            findings.append({'location': location, 'type': kind, 'lines': lines})

findings = []
objects = git('rev-list', '--objects', '--all').decode().splitlines()
blobs = 0
for obj in objects:
    oid, _, path = obj.partition(' ')
    if git('cat-file', '-t', oid).strip() != b'blob':
        continue
    blobs += 1
    scan(git('cat-file', 'blob', oid), f'history:{oid}:{path}', findings)
for rev in git('rev-list', '--all').decode().splitlines():
    scan(git('show', '-s', '--format=%B%nAuthor: %an <%ae>%nCommitter: %cn <%ce>', rev), f'commit-message:{rev}', findings)
for folder in ('Sources', 'scripts', 'specs', 'Resources', '.github', 'packaging', 'TunnelMac-Brand'):
    for path in sorted((ROOT / folder).rglob('*')):
        if path.is_file() and path.suffix in ('.swift', '.c', '.h', '.md', '.sh', '.py', '.yml', '.rb', '.svg', '.plist'):
            scan(path.read_bytes(), f'working-tree:{path.relative_to(ROOT)}', findings)
for path in ROOT.glob('*.md'):
    scan(path.read_bytes(), f'working-tree:{path.name}', findings)
report = {'reachable_blobs_scanned': blobs, 'findings': findings,
          'remote_releases_assets_and_ci_logs': 'not audited; requires GitHub access',
          'result': 'BLOCKED' if findings else 'local pattern scan clear; remote audit still required'}
print(json.dumps(report, indent=2))
sys.exit(bool(findings))
