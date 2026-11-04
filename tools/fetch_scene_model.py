"""Fetch the exact Seeed B601 model closure without replacing existing files."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'assets/vendor-cache/reBot-Isaacsim/'
BASE = 'https://raw.githubusercontent.com/Seeed-Projects/reBot-Isaacsim/158f87317fcaa35a7d1706ef364e324d3565939e/'


def verify(path, record):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Not an ordinary file: {path}')
    data = path.read_bytes()
    if len(data) != record['size_bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError(f'Model file does not match manifest: {path}')


def main():
    manifest = json.loads((ROOT / 'artifacts/model_manifest.json').read_text())
    for record in manifest['files']:
        relative = record['path']
        path = ROOT / relative
        if path.exists() or path.is_symlink():
            verify(path, record)
            continue
        if not relative.startswith(PREFIX) or '..' in Path(relative).parts:
            raise ValueError(f'Missing tracked file: {relative}')
        suffix = relative[len(PREFIX):]
        with urlopen(BASE + suffix, timeout=60) as response:
            data = response.read(record['size_bytes'] + 1)
        if len(data) != record['size_bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError(f'Download does not match manifest: {relative}')
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation: preserve any pre-existing local cache.
        with path.open('xb') as output:
            output.write(data)
        verify(path, record)
    print('Verified every model manifest file (length and SHA-256).')


if __name__ == '__main__':
    main()
