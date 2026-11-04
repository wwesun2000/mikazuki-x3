"""Open each player save in a fresh process and compare the continued session with a cold replay."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    build = ROOT / 'local/pc-core/cold-story/build.json'
    manifest=json.loads(build.read_bytes())
    exe=Path(manifest['snapshot'])/'cold_story_probe.exe'
    build=exe.parent/'build.json'
    fingerprint = digest(exe)
    if json.loads(build.read_text())['output_sha256'].lower() != fingerprint:
        raise ValueError('Player probe differs from its build record')
    cases = []
    with tempfile.TemporaryDirectory(dir=exe.parent) as tmp:
        tmp = Path(tmp)
        a, b, c = (tmp / n for n in ('snapshot','fresh','resumed'))

        def launch(ticks, source, dest, game='sn4g', *, success=True, walk=False):
            mode='--walk-checkpoint' if walk else '--checkpoint'
            payload = subprocess.run([exe, ROOT, game, mode, str(ticks), source, dest],
                                     capture_output=True, text=True, timeout=240)
            if success:
                if payload.returncode:
                    raise RuntimeError(payload.stderr)
                return json.loads(payload.stdout)
            if not payload.returncode:
                raise ValueError('Invalid save accepted')

        starts = [('sn2',450,False)]+[('sn4g',t,False) for t in (1,3,4,43,108,354,459,550,620)]
        starts += [('sn4g',t,True) for t in (2115,2300,5460,9000)]
        for game,start,walk in starts:
            before = launch(start, '-', a, game,walk=walk)
            expected = launch(start+5, '-', b, game,walk=walk)
            resumed = launch(5, a, c, game,walk=walk)
            if resumed != expected or c.read_bytes() != b.read_bytes():
                raise ValueError(f'Divergent continuation after original frame {start}')
            cases.append(dict(scenario=game, confirm_original_waits=walk, before=before, continued=resumed, snapshot_sha256=digest(a),
                              continued_file_sha256=digest(c), stored_bytes=a.stat().st_size))
        if not any(row['before']['voices'] for row in cases):
            raise ValueError('No active sound was restored')
        if not any(row['before']['visible_text_events'] for row in cases):
            raise ValueError('No visible source text was restored')
        if not any(row['before']['music_frame'] and row['continued']['music_frame'] != row['before']['music_frame'] for row in cases):
            raise ValueError('No advancing music track was restored')
        if not any(row['before']['frame'] and row['continued']['scene_sha256'] != row['before']['scene_sha256'] for row in cases):
            raise ValueError('No changing original movie frame was restored')
        previous = digest(c)
        launch(1, a, c, 'sn2', success=False)
        data = bytearray(a.read_bytes())
        data[len(data)//2] ^= 0x80
        a.write_bytes(data)
        launch(1, a, c, success=False)
        if digest(c) != previous:
            raise ValueError('An unsuccessful restore overwrote an existing slot')
    if digest(exe) != fingerprint:
        raise ValueError('Build changed during save verification')
    now = datetime.now(timezone.utc)
    result = dict(status='passed', checked_utc=now.isoformat(), build_sha256=digest(build),
                  exe_sha256=fingerprint, cases=cases, rejected=['different-scenario','corrupted-save'],
                  scope='Cold sn2 and sn4g, pending and active scenes, movie frames, BGM clock, glyph reveal, delay and looped SE. '
                        'Two independent processes compare complete session files after five further ticks.')
    path = ROOT / 'analysis/native-core' / f'player-save-{now:%Y%m%d-%H%M%S}.json'
    path.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(status='passed', fresh_process_cases=len(cases), report=str(path))))


if __name__=='__main__':
    main()
