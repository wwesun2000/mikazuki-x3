"""Compare native channels decoded directly from SE.DAT with independently decoded PCM."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import wave

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report_path = ROOT / 'analysis/se_bank.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    bank = ROOT / 'local/assets/SOUND/SSDVDAT/se.dat'
    if digest(bank) != report['source_sha256']:
        raise ValueError('SE.DAT differs from the original FFmpeg inputs')
    probe = ROOT / 'local/pc-core/cold-story/cold_story_probe.exe'
    run = subprocess.run([probe, ROOT, '--sound', *report['entries']], capture_output=True,
                         text=True, timeout=90, check=True)
    rows = [json.loads(s) for s in run.stdout.splitlines()]
    expected = {(int(name), channel): stream for name, record in report['entries'].items()
                for channel, stream in enumerate(record['streams'])}
    if len(rows) != len(expected):
        raise ValueError('Unexpected number of decoded source channels')
    for row in rows:
        stream = expected.pop((row['id'], row['channel']))
        path = ROOT / stream['wav_path']
        with wave.open(str(path), 'rb') as wav:
            pcm = wav.readframes(wav.getnframes())
        if (digest(path) != stream['wav_sha256'] or hashlib.sha256(pcm).hexdigest() != stream['pcm_sha256']
                or row['pcm_sha256'] != stream['pcm_sha256'] or row['samples'] != stream['sample_count']
                or row['loop_start'] != stream['loop']['start_sample']):
            raise ValueError(f"Decoded PCM or loop mismatch for {row['id']} stream {row['channel']}")
    now = datetime.now(timezone.utc)
    data = dict(status='passed', verified_utc=now.isoformat(), probe_sha256=digest(probe),
                bank_sha256=report['source_sha256'], reference_sha256=digest(report_path),
                channels=rows, sample_count=sum(x['samples'] for x in rows),
                scope='First-pass decoded PCM and loop points; original SPU2 mix and device playback tested separately.')
    dest = ROOT / 'analysis/native-core' / f'sound-pcm-{now:%Y%m%d-%H%M%S}.json'
    dest.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(status='passed', channels=len(rows), samples=data['sample_count'], report=str(dest))))


if __name__ == '__main__':
    main()
