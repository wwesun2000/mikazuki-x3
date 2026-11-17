"""Recreate fingerprinted Windows player inputs from a locally supplied retail ISO."""

import argparse
import hashlib
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from fad import bound_range, parse_index
import generate_cold_manager_bindings as manager
import generate_context_bridges as bridges
import generate_original_media_index as media
from iso9660 import Iso9660, reject_links
import index_original_movies as movies
from vm_handlers import Image

ROOT = Path(__file__).resolve().parents[1]
DISC_SIZE = 3594551296
DISC_SHA = '2a193cdbe97ba96faf0ad4d376a1d45b765aa99625895ff161f5102a5e85c95d'
MOVIE_TYPES = {'.mmv', '.m2v', '.pss'}
# The player requests these original panel families. hrsel.dat is outside
# the Windows panel allowlist. Keep the same accepted names and fingerprints.
PANEL_PATH = re.compile(r'PANEL/(?:hannin|hsil_0[0-9]|hsil_1[0-3]|memory0[1-6])\.dat')


def read_original(iso, movie_sources):
    if iso.size != DISC_SIZE or iso.sha256() != DISC_SHA:
        raise ValueError('Expected the supported Japanese PS2 disc image')
    files = {row['path']: row for row in iso.inventory() if row['kind'] == 'file'}
    cnf = files['SYSTEM.CNF']
    boot = re.search(rb'(?im)^BOOT2\s*=\s*cdrom0:\\([^;\s]+);1', iso.read(cnf['offset'], cnf['size']))
    if not boot or boot[1] != b'SLPM_664.52':
        raise ValueError('Unexpected original boot executable')
    elf = files[boot[1].decode('ascii')]
    image = Image(iso.read(elf['offset'], elf['size']))
    chain = [files[name] for name in ('DISC.FAD', 'DISC1.FAD', 'DISC2.FAD', 'DISC3.FAD')]
    for left, right in zip(chain, chain[1:]):
        if left['offset'] + left['size'] != right['offset']:
            raise ValueError('Original FAD extents must be contiguous')
    base, index_size = chain[0]['offset'], chain[0]['size']
    limit = chain[-1]['offset'] + chain[-1]['size']
    records = []
    panels = []
    for row in parse_index(iso.read(base, index_size)):
        suffix = Path(row['path']).suffix
        is_panel = PANEL_PATH.fullmatch(row['path']) is not None
        if row['kind'] != 'file' or (suffix not in media.TYPES and not is_panel):
            continue
        start, end = bound_range(row, base, limit)
        if start < base + index_size:
            raise ValueError('FAD payload overlaps the original index')
        payload = iso.read(start, end - start)
        row['sha256'] = hashlib.sha256(payload).hexdigest()
        if is_panel:
            panels.append(row)
        else:
            records.append(row)
        if movie_sources and suffix in MOVIE_TYPES:
            path = movie_sources / row['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    return image, records, panels


def render_panels(rows):
    lines = ['#pragma once', '#include <cstdint>', 'namespace kx3::platform {',
             '// DISC.FAD entries verified in analysis/integrity_check.json. Only the requested',
             '// original member is read. No panel image is bundled in the player.',
             'struct PanelMember { const char* path; std::uint32_t size; const char* sha; };',
             'inline constexpr PanelMember panel_members[]{']
    for row in sorted(rows, key=lambda row: row['path']):
        lines.append('    {' + ','.join(json.dumps(row[key]) for key in ('path', 'size', 'sha256')) + '},')
    return '\n'.join(lines + ['};', '}', ''])


def verified_bytes(content, expected, name):
    lf = content.encode('utf-8')
    # Existing fingerprints cover byte identity including the original line endings.
    for candidate in (lf, lf.replace(b'\n', b'\r\n')):
        if hashlib.sha256(candidate).hexdigest() == expected:
            return candidate
    raise ValueError(f'Regenerated input differs from the recorded SHA-256: {name}')


def prepare(iso_path, inputs, decoder):
    manifest = json.loads((ROOT / 'local-build-inputs.json').read_bytes())['private_inputs']
    reject_links(inputs, 'Build input output directory')
    inputs = inputs.resolve()
    inputs.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.disc-build-', dir=inputs) as temp:
        scratch = Path(temp)
        with Iso9660(iso_path) as iso:
            image, records, panels = read_original(iso, scratch / 'source' if decoder else None)
        bindings = manager.render(image)
        outputs = {
            'port/core/manager_handler_bindings.hpp': bindings,
            'port/core/context_bridges.hpp': bridges.render(image.data, bindings),
            'port/platform/original_media_catalog.hpp': media.render(image, records),
            'port/platform/panel_members.hpp': render_panels(panels),
        }
        if decoder:
            header, _ = movies.render(image, records, scratch / 'source', decoder, scratch / 'decode')
            outputs['port/platform/movie_stream_index.hpp'] = header
        pending = []
        for name, content in outputs.items():
            body = verified_bytes(content, manifest[name], name)
            target = inputs / name
            reject_links(target, 'Generated input')
            if target.exists() and target.read_bytes() != body:
                raise ValueError(f'Refusing to replace changed input: {name}')
            pending.append((name, target, body))
        for name, target, body in pending:
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(body)
            print(f'{name}  SHA-256 matched')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True, help='Local output tree for build_public_player.py')
    parser.add_argument('--ffmpeg', type=Path, help='Pinned FFmpeg 7.1 executable to also generate the movie index')
    args = parser.parse_args()
    prepare(args.iso, args.inputs, args.ffmpeg.resolve(strict=True) if args.ffmpeg else None)


if __name__ == '__main__':
    main()
