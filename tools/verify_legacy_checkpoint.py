"""Create saves with a preserved Windows build, then migrate and reopen in independent processes."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILDS = ROOT / 'local/pc-core/cold-story'
V3 = 'e5e43f1f2efafdfd44c038de72970bcdde91f1a67a86f7f335aa53ace2157c09'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    latest = json.loads((BUILDS / 'build.json').read_bytes())
    old = BUILDS / 'builds' / V3 / 'cold_story_probe.exe'
    new = Path(latest['snapshot']) / old.name
    old_hash, new_hash = digest(old), digest(new)
    if old_hash != '23af756b803435c63d866578caec1888f83e98798279a25fe2202a3c1431081c' or new_hash != latest['output_sha256'].lower():
        raise ValueError('Unexpected probe build')
    cases = []
    with tempfile.TemporaryDirectory(dir=BUILDS) as temp:
        temp = Path(temp)
        original, migrated, reopened, initial = [temp / name for name in ('v3', 'converted', 'reopened', 'initial')]
        for game, ticks in [('sn2', 450), ('sn4g', 354)]:
            def run(exe, count, source, destination):
                process = subprocess.run([exe, ROOT, game, '--checkpoint', str(count), source, destination],
                                         capture_output=True, text=True, timeout=180)
                if process.returncode:
                    raise RuntimeError(f"{game} checkpoint failed ({process.returncode}): {process.stderr.strip()}")
                return json.loads(process.stdout)

            old_observation = run(old, ticks, '-', original)
            before = run(new, 0, original, initial)
            after = run(new, 3, original, migrated)
            opened = run(new, 0, migrated, reopened)
            if original.read_bytes()[:8] != b'KX3WIN\x03\x00' or migrated.read_bytes()[:8] != b'KX3WIN\x09\x00':
                raise ValueError('Unexpected migration versions')
            if after['tick'] != ticks + 3 or after['tick'] != opened['tick'] or digest(migrated) != digest(reopened):
                raise ValueError('Reopening the migrated session changed persistent state')
            if game == 'sn2' and (not before['music_frame'] or after['music_frame'] != before['music_frame'] + 2400):
                raise ValueError('Restored BGM did not advance by three 800-frame blocks')
            if game == 'sn4g' and (not before['voices'] or after['voices'] != before['voices']):
                raise ValueError('Active original voices lost during migration')
            cases.append(dict(game=game, old_observation=old_observation, before=before, after=after, original_sha256=digest(original),
                              migrated_sha256=digest(migrated), reopened_sha256=digest(reopened)))
    now = datetime.now(timezone.utc)
    report = ROOT / 'analysis/native-core' / f'player-legacy-save-{now:%Y%m%d-%H%M%S}.json'
    report.write_text(json.dumps(dict(status='passed', from_version=3, to_version=9, old_exe=old_hash,
                                      current_exe=new_hash, cases=cases), indent=2)+'\n', encoding='utf-8')
    print(report)


if __name__ == '__main__':
    main()
