"""Strict, local-only decoding of the exact opening resource-index dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from scenario_resources import ROOT, SPK_SHA, SN4_SHA, ResourceIndex, sha, require, normalize_single_frame_ipu, extract_mmv_member


def write_identical_or_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), 'Refusing symlink output')
    if path.exists():
        require(path.read_bytes() == data, f'Refusing changed output: {path}')
    else:
        with path.open('xb') as stream:
            stream.write(data)


def decode(root=ROOT, scenes=None):
    root = Path(root).resolve()
    output = root / 'captures/derived/opening-resources'
    output.mkdir(parents=True, exist_ok=True)
    require(output.resolve().is_relative_to(root), 'Output outside project')
    require(not any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in [output, *output.parents]), 'Linked output directory')
    ffmpeg = root / 'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    report = json.loads((root / 'analysis/scenario_resources.json').read_text(encoding='utf-8'))
    require(report['sources'] == dict(spk_sha256=SPK_SHA, sn4_sha256=SN4_SHA), 'Unexpected resource report sources')
    require(sha((root / 'local/assets/SCENARIO/sn4g.spk').read_bytes()) == SPK_SHA and
            sha((root / 'local/assets/SCENARIO/sn4g.sn4').read_bytes()) == SN4_SHA, 'Original scenario changed')
    assets = {}
    resources = report['resources'].values()
    if scenes:
        index = ResourceIndex.from_project(root)
        resources = [index.resolve(0x73, name) for name in scenes]
    for resource in resources:
        for asset in resource['assets']:
            if asset['kind'] == 'file':
                assets[asset['fad_path']] = asset
    result = dict(evidence_id='SCENARIO-DECODE-001', tool=str(ffmpeg),
                  tool_sha256=sha(ffmpeg.read_bytes()), sources=report['sources'],
                  status='offline-source-decoding-not-runtime-capture', results=[])
    if scenes:
        # A bounded extension keeps earlier source evidence, including the header.
        previous = json.loads((root / 'analysis/scenario_decode.json').read_text(encoding='utf-8'))
        require(previous['sources'] == report['sources'] and
                previous['tool_sha256'] == result['tool_sha256'], 'Previous decode provenance changed')
        result['results'] = [row for row in previous['results'] if row['source'] not in assets]
    for fad_path, asset in sorted(assets.items()):
        source = root / 'local/assets' / fad_path
        require(source.resolve().is_relative_to(root / 'local/assets'), 'Source outside asset tree')
        original = source.read_bytes()
        require(sha(original) == asset['sha256'], 'Source asset changed')
        work = []
        if source.suffix == '.mmv':
            for member in asset['members']:
                payload, provenance = extract_mmv_member(original, member['index'])
                target = output / f'{source.name}.member-{member["index"]:02d}.m2v'
                write_identical_or_new(target, payload)
                work.append((target, provenance))
        elif source.suffix == '.ipu':
            payload, provenance = normalize_single_frame_ipu(original)
            target = output / f'{source.name}.ffmpeg.ipu'
            write_identical_or_new(target, payload)
            work.append((target, provenance))
        elif source.suffix in ('.pss', '.m2v', '.ogg'):
            work.append((source, None))
        else:
            result['results'].append(dict(source=fad_path, status='unsupported-no-output'))
        for target, adaptation in work:
            key = target.name
            audio = target.suffix == '.ogg'
            common = [str(ffmpeg), '-hide_banner', '-nostdin', '-xerror', '-err_detect', 'explode', '-i', str(target)]
            cmd = common + (['-map', '0:a:0', '-af', 'volumedetect'] if audio else ['-map', '0:v:0']) + ['-f', 'null', '-']
            process = subprocess.run(cmd, capture_output=True, timeout=120)
            log = process.stderr.decode('utf-8', errors='replace')
            logfile = output / f'{key}.full-decode.log'
            logfile.write_text(log, encoding='utf-8')
            bad = [line for line in log.splitlines() if re.search(r'\b(error|invalid|corrupt|damaged)\b', line, re.I)]
            record = dict(source=fad_path, source_sha256=sha(original), input=str(target),
                          input_sha256=sha(target.read_bytes()), adaptation=adaptation,
                          command=cmd, returncode=process.returncode, error_lines=bad,
                          log=str(logfile), log_sha256=sha(logfile.read_bytes()),
                          status='strict-decode-passed' if process.returncode == 0 and not bad else 'failed')
            result['results'].append(record)
            if record['status'] != 'strict-decode-passed':
                continue
            if audio:
                record['volume_lines'] = [line for line in log.splitlines() if 'mean_volume' in line or 'max_volume' in line]
                continue
            frames = re.findall(r'frame=\s*(\d+)', log)
            record['decoded_frame_count'] = int(frames[-1]) if frames else None
            png = output / f'{key}.first.png'
            with tempfile.TemporaryDirectory(prefix='decode-', dir=output) as scratch:
                scratch_png = Path(scratch) / 'first.png'
                image_cmd = common + ['-map', '0:v:0', '-frames:v', '1', '-update', '1', str(scratch_png)]
                image_process = subprocess.run(image_cmd, capture_output=True, timeout=120)
                image_log = image_process.stderr.decode('utf-8', errors='replace')
                require(image_process.returncode == 0 and not re.search(r'\b(error|invalid|corrupt|damaged)\b', image_log, re.I), 'First-frame strict decoding failed')
                write_identical_or_new(png, scratch_png.read_bytes())
            record.update(first_frame=str(png), first_frame_sha256=sha(png.read_bytes()),
                          first_frame_command=image_cmd, first_frame_status='extracted-not-captured')
    result['summary'] = dict(total=len(result['results']),
                             passed=sum(r['status'] == 'strict-decode-passed' for r in result['results']),
                             failed=sum(r['status'] != 'strict-decode-passed' for r in result['results']))
    report_path = root / 'analysis/scenario_decode.json'
    report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=ROOT)
    ap.add_argument('--scenes', nargs='+', help='Strictly decode named scenes and preserve previous verified evidence')
    args = ap.parse_args()
    result = decode(args.root, args.scenes)
    print(json.dumps(result['summary']))
    raise SystemExit(1 if result['summary']['failed'] else 0)
