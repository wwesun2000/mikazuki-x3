"""Package an accepted player's explicit file list, never saves or ISO assets."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, zipfile

ROOT = Path(__file__).resolve().parents[1]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    manifest = args.manifest.resolve()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT):
        raise ValueError('Output must stay within this project')
    receipt = output.with_suffix('.manifest.json')
    if output.exists() or receipt.exists():
        raise FileExistsError('Choose a new candidate path; existing packages are retained')
    authority = json.loads(manifest.read_bytes())
    expected = authority['distribution']
    if len(expected) != 4:
        raise ValueError('Review the changed distribution list before packaging')
    staged = ROOT / 'local/windows-iso-player'
    files = {}
    for name, expected_hash in expected.items():
        rel = PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or ':' in name or '\\' in name:
            raise ValueError(f'Unsafe archive path: {name}')
        data = (staged / name).read_bytes()
        if digest(data) != expected_hash:
            raise ValueError(f'Staged file changed since acceptance: {name}')
        files[name] = data
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 11, 3, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compresslevel=6)
    with zipfile.ZipFile(output) as archive:
        assert sorted(archive.namelist()) == sorted(expected)
        assert archive.testzip() is None
        assert all(digest(archive.read(name)) == h for name, h in expected.items())
    record = dict(status='packaged-verified-candidate', archive=str(output.relative_to(ROOT)),
                  bytes=output.stat().st_size, sha256=digest(output.read_bytes()),
                  authority=str(manifest.relative_to(ROOT)), authority_sha256=digest(manifest.read_bytes()),
                  files=expected, scope='Local playable candidate. Four accepted files only. No ISO, user saves, settings, source, extracted assets or test data.',
                  full_game_release_approved=False)
    receipt.write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(json.dumps(record, ensure_ascii=False))

if __name__ == '__main__':
    main()
