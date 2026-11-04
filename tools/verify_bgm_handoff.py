"""Check the original SN2 music replacement using independent cold and restored player processes."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'local/pc-core/cold-story/build.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    build = json.loads(BUILD.read_bytes())
    exe = Path(build['snapshot'])/'cold_story_probe.exe'
    if digest(exe) != build['output_sha256'].lower():
        raise ValueError('Probe differs from build')

    def run(*args):
        child = subprocess.run([exe, ROOT, 'sn2', *map(str,args)], capture_output=True,
                               text=True, timeout=400)
        if child.returncode:
            raise RuntimeError(child.stderr)
        return json.loads(child.stdout.splitlines()[-1])

    def route(tick, dest):
        end = run('--route', tick, '--save', dest, '--accept-default-names','keyboard', *[0]*6)
        if end['tick'] != tick or end['stage'] != 'frame-limit' or end['accepted_choices'] != 6:
            raise ValueError('Route failed to reach the requested frame through all six choices')

    with tempfile.TemporaryDirectory(dir=BUILD.parent) as scratch:
        saved, direct, resumed, reopened = [Path(scratch)/name for name in ('before','cold','resumed','reopened')]
        route(8192, saved)
        start = run('--checkpoint', 0, saved, reopened)
        route(8197, direct)
        crossed = run('--walk-checkpoint', 5, saved, resumed)
        if not (start['music'] and crossed['music'] and start['music'] != crossed['music']):
            raise ValueError(f'Expected a replacement during this interval: {start} -> {crossed}')
        if not 0 < crossed['music_ramp_elapsed'] < crossed['music_ramp_length']:
            raise ValueError('New track has no active fade-in')
        if digest(direct) != digest(resumed):
            raise ValueError('Cold and restored session files differ across music replacement')
        check = run('--checkpoint', 0, resumed, reopened)
        if check != crossed or digest(reopened) != digest(resumed):
            raise ValueError('Reopening mid-envelope changed playback state')
        proof = dict(start=start, crossed=crossed, after_sha256=digest(resumed),
                     inputs='Six first options, accepted at their original presentation times; no save-state input on cold route')
    now = datetime.now(timezone.utc)
    report = ROOT / 'analysis/native-core' / f'bgm-handoff-{now:%Y%m%d-%H%M%S}.json'
    report.write_text(json.dumps(dict(status='passed',exe_sha256=digest(exe),**proof),indent=2)+'\n',encoding='utf-8')
    print(report)


if __name__ == '__main__':
    main()
