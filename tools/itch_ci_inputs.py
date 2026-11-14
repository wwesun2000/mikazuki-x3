"""Download a protected build bundle and extract only reviewed files after SHA256 checks."""
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile
from package_itch import LEGAL_TEXTS

ROOT = Path(__file__).resolve().parents[1]

def main():
    url = os.environ['ITCH_INPUTS_URL']
    expected = os.environ['ITCH_INPUTS_SHA256'].lower()
    if not url.startswith('https://') or len(expected) != 64:
        raise SystemExit('Configure HTTPS ITCH_INPUTS_URL and SHA256')
    dest = ROOT/'local/itch-inputs'
    dest.mkdir(parents=True, exist_ok=False)
    archive = dest/'inputs.zip'
    # Never print a signed URL or raw HTTP exception containing credentials.
    try:
        with urllib.request.urlopen(url, timeout=120) as response, archive.open('wb') as out:
            if not response.url.startswith('https://'):
                raise ValueError('Insecure redirect')
            while chunk := response.read(1024*1024):
                out.write(chunk)
    except Exception:
        raise SystemExit('Protected input download failed; inspect access/expiry without logging the URL') from None
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise SystemExit('Protected bundle SHA256 mismatch')
    allowed = set(json.loads((ROOT/'local-build-inputs.json').read_bytes())['private_inputs'])
    allowed.update({'runtime/ffmpeg.exe', 'legal/ffmpeg-7.1.tar.xz'})
    allowed.update('legal/'+name for name in LEGAL_TEXTS)
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(names) != len(allowed) or set(names) != allowed:
            raise SystemExit('Bundle contains unreviewed, missing or duplicate files')
        for name in names:
            target = (dest/name).resolve()
            if not target.is_relative_to(dest.resolve()):
                raise SystemExit('Unsafe input path')
            if Path(name).suffix.lower() in {'.iso', '.bin', '.img', '.rom', '.ps2', '.p2s'}:
                raise SystemExit('Disc/BIOS/save input prohibited')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(name))
    archive.unlink()
    print('Protected build inputs extracted; per-file fingerprints are checked by build_public_player.py')

if __name__ == '__main__':
    main()
