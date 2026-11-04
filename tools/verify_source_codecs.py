"""Compare the player's on-demand media with independently decoded original media."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import wave

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    build = ROOT / 'local/pc-core/cold-story/build.json'
    exe = build.with_name('cold_story_probe.exe')
    identity = sha(exe.read_bytes())
    if json.loads(build.read_bytes())['output_sha256'].lower() != identity:
        raise ValueError('Cold probe identity mismatch')

    def native(mode, names):
        result = subprocess.run([exe, ROOT, mode, *names], capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        return {r['name']: r for line in result.stdout.splitlines() if (r := json.loads(line))}

    archive = json.loads((ROOT / 'analysis/scenario_decode.json').read_bytes())
    stills = {Path(r['source']).name: r for r in archive['results'] if r['source'].lower().endswith('.ipu')
              and r.get('first_frame_sha256') and r['returncode'] == 0}
    images = native('--ipu', ['MOVIE/'+name for name in (*stills, 'mm0010.ipu', 'my0007.ipu')])
    raster = ROOT / 'local/pc-core/raster_probe.exe'
    for name, row in stills.items():
        png = ROOT / row['first_frame']
        image = images['MOVIE/'+name]
        expected = json.loads(subprocess.run([raster, png, row['first_frame_sha256'], str(image['width']),
                                              str(image['height'])], check=True, capture_output=True,
                                             text=True, timeout=30).stdout)
        if expected['rgba_sha256'] != image['sha']:
            raise ValueError('Pixel difference for ' + name)
        image['wic_rgba_sha256'] = expected['rgba_sha256']
    if len(stills) < 16:
        raise ValueError('Missing original PNG comparison cases')

    tracks = native('--music', ['k1a006.ogg', 'k2h012.ogg', 'k1f013.ogg', 'k1a001.ogg'])
    bank = (ROOT / 'local/assets/SOUND/SSDVDAT/bgm.dat').read_bytes()
    for name, result in tracks.items():
        rows = [bank[i:i+56] for i in range(0, 56000, 56)
                if bank[i] & 0x80 and bank[i+40:i+54].split(b'\0')[0] == Path(name).stem.encode()]
        if len(rows) != 1 or tuple(result[s] for s in ('loop_start', 'loop_end')) != struct.unpack_from('<II', rows[0], 4):
            raise ValueError('Music loop markers differ for '+name)
        witness = ROOT / 'captures/derived/opening-audio' / (Path(name).stem+'.bgm.wav')
        if witness.is_file():
            with wave.open(str(witness)) as w:
                digest = sha(w.readframes(w.getnframes()))
                if w.getframerate()!=result['rate'] or w.getnchannels()!=result['channels'] or w.getnframes()!=result['frames'] or digest!=result['sha']:
                    raise ValueError('PCM difference for '+name)
                result['wav_pcm_sha256'] = digest
    if sum('wav_pcm_sha256' in r for r in tracks.values()) < 2 or sha(exe.read_bytes()) != identity:
        raise ValueError('Source media comparison cases or build changed')
    now = datetime.now(timezone.utc)
    path = ROOT / 'analysis/native-core' / f'source-codecs-{now:%Y%m%d-%H%M%S}.json'
    path.write_text(json.dumps(dict(exe=identity, checked_utc=now.isoformat(), images=images, tracks=tracks),
                               indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(compared_ipu=len(stills), decoded_ipu=len(images), checked_bgm=len(tracks), report=str(path))))


if __name__ == '__main__':
    main()
