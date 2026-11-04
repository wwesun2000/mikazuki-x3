"""Read-only, bounded ISO9660 inventory and selective extraction (stdlib only).

No UDF/Joliet interpretation, multi-extent, interleaved or extended-attribute
files are supported. Unsupported features fail explicitly instead of guessing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import struct
import tempfile

SECTOR = 2048


class IsoError(ValueError):
    pass


def both16(data: bytes, offset: int) -> int:
    little, big = struct.unpack_from('<H', data, offset)[0], struct.unpack_from('>H', data, offset + 2)[0]
    if little != big:
        raise IsoError(f'Inconsistent dual-endian uint16 at {offset}')
    return little


def both32(data: bytes, offset: int) -> int:
    little, big = struct.unpack_from('<I', data, offset)[0], struct.unpack_from('>I', data, offset + 4)[0]
    if little != big:
        raise IsoError(f'Inconsistent dual-endian uint32 at {offset}')
    return little


def safe_component(identifier: bytes) -> tuple[str, str]:
    try:
        raw = identifier.decode('ascii')
    except UnicodeDecodeError as exc:
        raise IsoError('Non-ASCII primary-volume identifier') from exc
    name = raw.rsplit(';', 1)[0] if ';' in raw else raw
    if (not name or name in ('.', '..')
            or any(ord(c) < 32 or ord(c) == 127 or c in '/\\:<>"|?*' for c in name)
            or name.rstrip(' .') != name):
        raise IsoError(f'Unsafe ISO name: {raw!r}')
    # Windows device names remain unsafe even with an extension.
    if name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}:
        raise IsoError(f'Reserved filesystem name: {raw!r}')
    return name, raw


def reject_links(path: Path, label: str):
    """Reject links before resolving paths, including a linked output root."""
    for component in (path, *path.parents):
        if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
            raise IsoError(f'{label} uses a symlink or junction: {component}')


def protect_output(output: Path, protected_paths: list[Path]):
    reject_links(output, 'Manifest output')
    resolved = output.resolve()
    for source in protected_paths:
        if resolved == source.resolve() or (output.exists() and source.exists() and os.path.samefile(output, source)):
            raise IsoError(f'Manifest output aliases a source or extracted member: {source}')


def write_manifest(output: Path, result: dict, protected_paths: list[Path]):
    """Replace a report only after its complete JSON has been flushed to disk."""
    protect_output(output, protected_paths)
    output.parent.mkdir(parents=True, exist_ok=True)
    reject_links(output.parent, 'Manifest output directory')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         prefix=f'.{output.name}.', suffix='.tmp',
                                         dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        protect_output(output, protected_paths)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class Iso9660:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve(strict=True)
        self.size = self.path.stat().st_size
        self.fp = self.path.open('rb')
        self.pvd = None
        self.entries: list[dict] = []
        self.volume_bytes = self.size

    def close(self):
        self.fp.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > min(self.size, self.volume_bytes):
            raise IsoError(f'Range outside image/declared volume: {offset}+{size}')
        self.fp.seek(offset)
        data = self.fp.read(size)
        if len(data) != size:
            raise IsoError('Short image read')
        return data

    def record(self, raw: bytes) -> dict:
        if len(raw) < 34 or raw[0] != len(raw) or 33 + raw[32] > len(raw):
            raise IsoError('Invalid directory record length')
        if raw[1]:
            raise IsoError('Extended-attribute records unsupported')
        if raw[25] & 0x80:
            raise IsoError('Multi-extent files unsupported')
        if raw[26] or raw[27]:
            raise IsoError('Interleaved files unsupported')
        extent, size = both32(raw, 2), both32(raw, 10)
        if both16(raw, 28) != 1:
            raise IsoError('Multi-volume files unsupported')
        if extent * SECTOR + size > min(self.size, self.volume_bytes):
            raise IsoError('Directory record extent outside image/declared volume')
        identifier = raw[33:33 + raw[32]]
        name, literal = ('', 'self' if identifier == b'\x00' else 'parent') if identifier in (b'\x00', b'\x01') else safe_component(identifier)
        return {'name': name, 'raw_identifier': literal, 'extent_lba': extent,
                'offset': extent * SECTOR, 'size': size,
                'kind': 'directory' if raw[25] & 2 else 'file', 'flags': raw[25],
                'recording_date_raw': raw[18:25].hex()}

    def inventory(self) -> list[dict]:
        pvd = None
        terminated = False
        for sector in range(16, min(self.size // SECTOR, 16 + 256)):
            desc = self.read(sector * SECTOR, SECTOR)
            if desc[1:6] != b'CD001' or desc[6] != 1:
                raise IsoError('Invalid ISO9660 volume descriptor')
            if desc[0] == 1:
                if pvd is not None:
                    raise IsoError('Multiple primary volume descriptors unsupported')
                pvd = desc
            if desc[0] == 255:
                terminated = True
                break
        if pvd is None or not terminated:
            raise IsoError('Missing primary descriptor or descriptor terminator')
        if both16(pvd, 128) != SECTOR:
            raise IsoError('Only 2048-byte logical sectors supported')
        volume_sectors = both32(pvd, 80)
        self.volume_bytes = volume_sectors * SECTOR
        if self.volume_bytes > self.size:
            raise IsoError('Declared volume extends beyond image')
        if both16(pvd, 120) != 1 or both16(pvd, 124) != 1:
            raise IsoError('Multi-volume sets unsupported')
        self.pvd = {
            'system_identifier': pvd[8:40].decode('ascii', errors='replace').rstrip(),
            'volume_identifier': pvd[40:72].decode('ascii', errors='replace').rstrip(),
            'volume_sectors': volume_sectors, 'logical_block_size': SECTOR,
            'volume_bytes': self.volume_bytes,
            'publisher_identifier': pvd[318:446].decode('ascii', errors='replace').rstrip(),
            'application_identifier': pvd[574:702].decode('ascii', errors='replace').rstrip(),
            'creation_time_raw': pvd[813:830].hex(),
        }
        root = self.record(pvd[156:156 + pvd[156]])
        if root['kind'] != 'directory':
            raise IsoError('Root is not a directory')
        entries, seen_dirs, seen_paths = [], set(), set()

        def walk(directory: dict, prefix: str, depth: int):
            if depth > 64:
                raise IsoError('Directory nesting limit exceeded')
            identity = (directory['extent_lba'], directory['size'])
            if identity in seen_dirs:
                raise IsoError('Directory extent cycle or alias')
            seen_dirs.add(identity)
            if directory['size'] > 64 * 1024 * 1024:
                raise IsoError('Directory exceeds 64 MiB safety limit')
            data = self.read(directory['offset'], directory['size'])
            cursor = 0
            children = []
            while cursor < len(data):
                length = data[cursor]
                if length == 0:
                    cursor = ((cursor // SECTOR) + 1) * SECTOR
                    continue
                if cursor + length > len(data) or cursor % SECTOR + length > SECTOR:
                    raise IsoError('Directory record crosses sector/directory boundary')
                entry = self.record(data[cursor:cursor + length])
                cursor += length
                if not entry['name']:
                    continue
                entry['path'] = f"{prefix}/{entry['name']}" if prefix else entry['name']
                folded = entry['path'].casefold()
                if folded in seen_paths:
                    raise IsoError(f'Duplicate normalized path: {entry["path"]}')
                seen_paths.add(folded)
                entries.append(entry)
                if len(entries) > 1_000_000:
                    raise IsoError('Entry count safety limit exceeded')
                if entry['kind'] == 'directory':
                    children.append(entry)
            for child in children:
                walk(child, child['path'], depth + 1)

        walk(root, '', 0)
        self.entries = sorted(entries, key=lambda e: e['path'])
        return self.entries

    def sha256(self) -> str:
        digest = hashlib.sha256()
        self.fp.seek(0)
        for block in iter(lambda: self.fp.read(8 * 1024 * 1024), b''):
            digest.update(block)
        return digest.hexdigest()

    def manifest(self) -> dict:
        if self.pvd is None:
            self.inventory()
        return {'schema_version': 1, 'evidence_id': 'ISO-001', 'evidence_type': 'observed-static',
                'source': {'path': str(self.path), 'size': self.size, 'sha256': self.sha256()},
                'pvd': self.pvd, 'file_count': sum(e['kind'] == 'file' for e in self.entries),
                'directory_count': sum(e['kind'] == 'directory' for e in self.entries),
                'limitations': ['Primary ISO9660 tree only; no UDF/Joliet interpretation.',
                                'No game execution or archive payload decoding.',
                                'Unsupported multi-extent, interleaving and extended attributes fail explicitly.'],
                'entries': self.entries}

    def extract(self, member: str, output_root: str | Path) -> dict:
        # Caller input is checked independently, even though inventory paths are validated.
        parts = PurePosixPath(member).parts
        if not parts or member.startswith('/') or any(s in ('', '.', '..') for s in member.split('/')):
            raise IsoError('Unsafe member path')
        for part in parts:
            try:
                safe_component(part.encode('ascii'))
            except UnicodeEncodeError as exc:
                raise IsoError('Non-ASCII member name') from exc
        matches = [entry for entry in self.entries if entry['path'] == member and entry['kind'] == 'file']
        if len(matches) != 1:
            raise IsoError(f'File not present: {member}')
        entry = matches[0]
        original_root = Path(output_root)
        reject_links(original_root, 'Extraction output root')
        root = original_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        candidate = root.joinpath(*parts)
        reject_links(candidate, 'Extraction output')
        target = candidate.resolve()
        if not target.is_relative_to(root) or target == root:
            raise IsoError('Extraction escaped output directory')
        target.parent.mkdir(parents=True, exist_ok=True)
        reject_links(candidate, 'Extraction output')
        digest = hashlib.sha256()
        self.fp.seek(entry['offset'])
        remaining = entry['size']
        try:
            with target.open('xb') as out:
                while remaining:
                    data = self.fp.read(min(1024 * 1024, remaining))
                    if not data:
                        raise IsoError('Short image read during extraction')
                    remaining -= len(data)
                    digest.update(data)
                    out.write(data)
        except FileExistsError as exc:
            raise IsoError(f'Refusing to overwrite {target}') from exc
        return {'member': member, 'path': str(target), 'size': entry['size'], 'sha256': digest.hexdigest(),
                'source_offset': entry['offset'], 'source_extent_lba': entry['extent_lba']}


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('iso', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--extract', action='append', default=[], metavar='MEMBER')
    parser.add_argument('--output', type=Path, default=Path('local/extracted'))
    parser.add_argument('--no-hash', action='store_true', help='List only; disallowed with manifest')
    args = parser.parse_args(argv)
    if args.no_hash and args.manifest:
        parser.error('--no-hash cannot be used with --manifest')
    with Iso9660(args.iso) as iso:
        entries = iso.inventory()
        if args.manifest:
            # Protect every known extraction destination, including files extracted
            # by an earlier invocation and members selected in this invocation.
            protected = [iso.path, *(args.output.joinpath(*entry['path'].split('/'))
                                     for entry in entries if entry['kind'] == 'file')]
            protect_output(args.manifest, protected)
            result = iso.manifest()
            write_manifest(args.manifest, result, protected)
            print(json.dumps({k: result[k] for k in ('source', 'pvd', 'file_count', 'directory_count')}, ensure_ascii=False))
        else:
            print(json.dumps({'pvd': iso.pvd, 'entries': entries}, indent=2, ensure_ascii=False))
        if args.extract:
            receipts = [iso.extract(member, args.output) for member in args.extract]
            print(json.dumps({'extracted': receipts}, indent=2))


if __name__ == '__main__':
    main()
