"""Bind a real WIC decode to the retained original-asset conversion evidence."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    output = ROOT / 'analysis/native-core/windows-raster-v2.json'
    conversion_path = ROOT / 'analysis/scenario_decode.json'
    conversion = json.loads(conversion_path.read_text())
    entry = next(row for row in conversion['results'] if row['source'] == 'GRA/MY/my0000.ipu')
    assert entry['status'] == 'strict-decode-passed' and entry['decoded_frame_count'] == 1
    original = ROOT / 'local/assets' / entry['source']
    png = ROOT / 'local/port-assets/scenes' / (entry['first_frame_sha256']+'.png')
    derived_png = Path(entry['first_frame'])
    assert sha(original) == entry['source_sha256']
    assert sha(png) == sha(derived_png) == entry['first_frame_sha256']
    expected_width, expected_height = entry['adaptation']['width'], entry['adaptation']['height']
    probe = ROOT / 'local/pc-core/raster_probe.exe'
    command = [str(probe), str(png), sha(png), str(expected_width), str(expected_height)]
    run = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
    observed = json.loads(run.stdout)
    assert observed['status'] == 'passed' and observed['png_sha256'] == sha(png)
    assert observed['width'] == expected_width and observed['height'] == expected_height
    assert all(observed[key] for key in ('wrong_hash_rejected', 'wrong_dimensions_rejected',
                                        'rgba_limit_rejected', 'com_lifecycle_passed'))
    # Existing pinned FFmpeg independently decodes the same extracted PNG to
    # RGBA. This verifies actual pixels and WIC channel/alpha layout, not a screenshot.
    ffmpeg = Path(conversion['tool'])
    assert sha(ffmpeg) == conversion['tool_sha256']
    reference_command = [str(ffmpeg), '-v', 'error', '-nostdin', '-xerror',
                         '-i', str(png), '-frames:v', '1', '-f', 'rawvideo', '-pix_fmt', 'rgba', 'pipe:1']
    reference = subprocess.run(reference_command, capture_output=True, check=True, timeout=30)
    assert not reference.stderr
    assert len(reference.stdout) == observed['rgba_bytes'] == expected_width * expected_height * 4
    reference_hash = hashlib.sha256(reference.stdout).hexdigest()
    assert reference_hash == observed['rgba_sha256']
    assert sha(original) == entry['source_sha256'] and sha(png) == entry['first_frame_sha256']
    build_path = ROOT / 'local/pc-core/raster_probe.build.json'
    build = json.loads(build_path.read_text())
    assert sha(probe) == build['output_sha256']
    for name, digest in build['sources'].items():
        assert sha(Path(name)) == digest
    report = {
        'schema': 1, 'status': 'passed', 'kind': 'actual-Windows-WIC-PNG-to-RGBA-decode',
        'conversion_report': str(conversion_path.relative_to(ROOT)), 'conversion_report_sha256': sha(conversion_path),
        'original_asset': str(original.relative_to(ROOT)), 'original_asset_sha256': sha(original),
        'original_asset_bytes': original.stat().st_size,
        'png': str(png.relative_to(ROOT)), 'png_sha256': sha(png),
        'derived_first_frame_png_equal': True,
        'probe_command': command, 'probe_exit_code': run.returncode, 'probe_sha256': sha(probe),
        'build_record': str(build_path.relative_to(ROOT)), 'build_record_sha256': sha(build_path),
        'observed': observed,
        'independent_decoder': {'command': reference_command, 'ffmpeg_sha256': sha(ffmpeg),
                                'rgba_sha256': reference_hash, 'matches_WIC_RGBA': True},
        'sources': [
            'https://learn.microsoft.com/en-us/windows/win32/api/wincodec/nf-wincodec-iwicbitmapsource-copypixels',
            'https://learn.microsoft.com/en-us/windows/win32/api/wincodec/nf-wincodec-iwicformatconverter-initialize',
            'https://learn.microsoft.com/en-us/windows/win32/api/wincodec/nf-wincodec-iwicstream-initializefrommemory',
            'https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex'],
        'limits': ['The source asset first frame is genuinely solid opaque black; it is not a placeholder',
                   'No UI, GPU upload, movie timing or prepared/current promotion is implemented by the loader',
                   'The existing IPU-to-PNG conversion remains a separate offline container/codec adaptation',
                   'Generic loader has no asset-name special case; the acceptance script deliberately selects one known original asset'],
    }
    try:
        with output.open('x', encoding='utf-8') as record:
            record.write(json.dumps(report, indent=2) + '\n')
    except FileExistsError:
        if json.loads(output.read_text(encoding='utf-8')) != report:
            raise ValueError('Raster evidence changed; retain this record and use a new version')
    print(json.dumps({'status': 'passed', 'rgba_bytes': observed['rgba_bytes'],
                      'rgba_sha256': reference_hash, 'independent_pixels_match': True,
                      'report': str(output.relative_to(ROOT))}))


if __name__ == '__main__':
    main()
