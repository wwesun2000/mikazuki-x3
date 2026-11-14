"""Create an isolated, allowlisted Windows itch payload. Never scan/copy a workspace tree."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DECODER = 'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
SOURCE_SHA256 = '40973d44970dbc83ef302b0609f2e74982be2d85916dd2ee7472d30678a7abe6'
DECODER_SHA256 = '797b8ae343e9b2222976e6ac6d71b983e8a04b9036e94f982a233d877071e419'
LEGAL_TEXTS = ('FFmpeg-LICENSE.txt', 'FFmpeg-SOURCE.txt', 'THIRD-PARTY-NOTICES.txt',
               'FFmpeg-config.log', 'FFmpeg-imports.txt', 'build_itch_decoder.sh',
               'MinGW-w64-COPYING.txt', 'GCC-COPYING.txt', 'WINDOWS-RUNTIME-LICENSES.txt')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pe64(data):
    if data[:2] != b'MZ' or len(data) < 64:
        raise ValueError('Expected a Windows executable')
    offset = struct.unpack_from('<I', data, 60)[0]
    if data[offset:offset+4] != b'PE\0\0' or struct.unpack_from('<H', data, offset+4)[0] != 0x8664:
        raise ValueError('Expected an AMD64 PE executable')

def package(player, launcher, decoder, legal, output):
    if output.exists():
        raise FileExistsError('Use a fresh output directory, never a live player installation')
    payload = {
        'MikazukiX3.exe': launcher.read_bytes(),
        'local/pc-core/player/KamaitachiX3.exe': player.read_bytes(),
        DECODER: decoder.read_bytes(),
        '.itch.toml': (ROOT/'distribution/itch/.itch.toml').read_bytes(),
        'README.txt': (ROOT/'docs/itch/GETTING_STARTED.md').read_bytes(),
    }
    for name in ('MikazukiX3.exe', 'local/pc-core/player/KamaitachiX3.exe', DECODER):
        pe64(payload[name])
    if sha(payload[DECODER]) != DECODER_SHA256:
        raise ValueError('Decoder does not match the reviewed source-included build')
    # Explicit legal filenames only: no recursive copying, nested archives or wildcard binaries.
    for name in LEGAL_TEXTS:
        data = (legal/name).read_bytes()
        if len(data) < 40 or b'\0' in data:
            raise ValueError('Missing or invalid legal text: ' + name)
        data.decode('utf-8')
        payload['licenses/'+name] = data
    source = (legal/'ffmpeg-7.1.tar.xz').read_bytes()
    if sha(source) != SOURCE_SHA256:
        raise ValueError('FFmpeg corresponding source hash mismatch')
    payload['licenses/ffmpeg-7.1.tar.xz'] = source
    hashes = {name: sha(data) for name, data in sorted(payload.items())}
    payload['SHA256SUMS.txt'] = ''.join(f'{digest}  {name}\n' for name, digest in hashes.items()).encode()
    output.mkdir(parents=True)
    for name, data in payload.items():
        dest = output/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    archive = output.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(payload.items()):
            z.writestr(name, data)
    with zipfile.ZipFile(archive) as z:
        if set(z.namelist()) != set(payload) or z.testzip() is not None:
            raise ValueError('Archive verification failed')
        for name, data in payload.items():
            if z.read(name) != data:
                raise ValueError('Archive mismatch: '+name)
    report = {'archive': archive.name, 'sha256': sha(archive.read_bytes()),
              'architecture': 'amd64', 'files': hashes,
              'scope': 'Allowlisted payload, not copyright clearance or malware certification'}
    archive.with_suffix('.audit.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    archive.with_suffix('.sha256').write_text(report['sha256']+'  '+archive.name+'\n', encoding='utf-8')
    print(json.dumps(report))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('player', 'launcher', 'decoder', 'legal', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    package(a.player, a.launcher, a.decoder, a.legal, a.output)
