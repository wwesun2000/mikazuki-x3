"""Decode selected original assets locally and retain provenance, not gameplay captures."""
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import time


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def decoder_errors(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if re.search(r'Error submitting|Invalid data found|Error while decoding|corrupt(?:ed)? frame', line, re.I)]


def audit(root: Path):
    path = root / 'analysis/media_decode_report.json'
    report = json.loads(path.read_text(encoding='utf-8'))
    for item in report['results']:
        errors = decoder_errors((root / item['log']).read_text(encoding='utf-8', errors='replace'))
        item['decoder_errors'] = errors
        item['artifact_produced'] = bool(item['output'] and (root / item['output']).is_file())
        item['success'] = item['returncode'] == 0 and not errors and (not item['output'] or item['artifact_produced'])
        item['status'] = 'decoded-sample' if item['success'] else 'needs-decoder-investigation'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


def main():
    root = Path(__file__).resolve().parent.parent
    if sys.argv[1:] == ['--audit-existing']:
        for item in audit(root)['results']:
            print(item['name'], item['status'])
        return
    exe = root / 'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    if not exe.is_file():
        raise SystemExit('Install pinned imageio-ffmpeg==0.7.0 into local/dependencies first.')
    destination = root / 'captures/derived'
    logs = root / 'captures/logs'
    destination.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    tasks = [
        ('ak0000a', 'local/assets/GRA/AK/ak0000a.ipu', ['-frames:v', '1'], 'ak0000a.png'),
        ('ak0074c-frame', 'local/assets/GRA/AK/ak0074c.m2v', ['-frames:v', '1'], 'ak0074c-frame.png'),
        ('ak0074c-video', 'local/assets/GRA/AK/ak0074c.m2v', ['-an', '-c:v', 'libx264', '-crf', '16', '-pix_fmt', 'yuv420p', '-movflags', '+faststart'], 'ak0074c.mp4'),
        ('etc001-audio', 'local/assets/SOUND/SSDVVOR/etc001.ogg', ['-f', 'null'], None),
    ]
    results = []
    for name, relative, options, filename in tasks:
        source = root / relative
        output = destination / filename if filename else None
        if output and output.exists():
            raise SystemExit(f'Refusing to replace existing derived media: {output}')
        command = [str(exe), '-nostdin', '-hide_banner', '-n', '-i', str(source), *options, str(output) if output else '-']
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, timeout=120,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        log = logs / (name + '.log')
        log.write_bytes(result.stderr)
        success = result.returncode == 0 and (output is None or output.is_file() and output.stat().st_size > 0)
        results.append(dict(name=name, source=relative, source_sha256=digest(source),
                            output=output.relative_to(root).as_posix() if output else None,
                            output_sha256=digest(output) if output and output.is_file() else None,
                            success=success, returncode=result.returncode,
                            duration_seconds=round(time.monotonic() - start, 3),
                            command=command, log=log.relative_to(root).as_posix(),
                            origin='extracted-original-asset', is_runtime_capture=False))
        print(name, 'OK' if success else f'FAILED ({result.returncode})')
    version = subprocess.run([str(exe), '-version'], capture_output=True, timeout=10,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout.decode('utf-8', errors='replace')
    report = dict(evidence_id='MEDIA-DECODE-001', tool_path=str(exe), tool_sha256=digest(exe),
                  tool_version=version, package='imageio-ffmpeg==0.7.0',
                  dependency_source='https://pypi.org/project/imageio-ffmpeg/0.7.0/', results=results,
                  limitations=['Selected assets only; this is not PS2 or native-port gameplay execution.',
                               'Decoder success does not establish pixel/color parity with PS2 output.'])
    (root / 'analysis/media_decode_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    audit(root)


if __name__ == '__main__':
    main()
