"""Read the observed X3 32-byte FAD index. Does not emulate game loading."""
from __future__ import annotations
import argparse
from collections import Counter
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import struct

SENTINEL = 0xFFFFFFFF


def component(raw: bytes) -> str:
    value = raw.split(b'\0', 1)[0].decode('ascii').rstrip(' ')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *('COM' + str(i) for i in range(1, 10)), *('LPT' + str(i) for i in range(1, 10))}
    if (not value or value in ('.', '..') or value.endswith('.')
            or value.split('.')[0].upper() in reserved
            or any(ord(c) < 32 or ord(c) == 127 or c in '/\\:<>"|?*' for c in value)):
        raise ValueError(f'Unsafe FAD component: {raw!r}')
    return value


def parse_index(data: bytes) -> list[dict]:
    if len(data) % 32:
        raise ValueError('FAD index length is not a multiple of 32')
    records = []
    padding = False
    for offset in range(0, len(data), 32):
        raw = data[offset:offset + 32]
        if raw == bytes(32):
            padding = True
            continue
        if padding:
            raise ValueError('Nonzero record after index padding')
        kind = struct.unpack_from('<I', raw)[0]
        size, sector, parent, child = struct.unpack_from('<4I', raw, 16)
        if kind not in (0, 1):
            raise ValueError(f'Unknown record kind {kind}')
        name = component(raw[4:16]) if kind else component(raw[4:12]) + '.' + component(raw[12:15])
        if kind == 0 and (sector == SENTINEL or child != SENTINEL):
            raise ValueError('Unexpected file index fields')
        records.append(dict(index=offset // 32, index_offset=offset,
                            kind='directory' if kind else 'file', name=name,
                            size=size, sector=sector, parent=parent, first_child=child))
    def path_for(index: int, seen: set[int]) -> str:
        if index in seen or index >= len(records):
            raise ValueError('Cyclic or out-of-range parent index')
        row = records[index]
        if row['parent'] == SENTINEL:
            return row['name']
        parent = row['parent']
        if parent >= len(records) or records[parent]['kind'] != 'directory':
            raise ValueError('Parent is not an indexed directory')
        return path_for(parent, seen | {index}) + '/' + row['name']
    paths = set()
    for row in records:
        row['path'] = path_for(row['index'], set())
        folded = row['path'].casefold()
        if folded in paths:
            raise ValueError('Duplicate path')
        paths.add(folded)
        if row['kind'] == 'directory':
            child = row['first_child']
            if child >= len(records) or records[child]['parent'] != row['index']:
                raise ValueError('Invalid first-child index')
    return records


def bound_range(row: dict, base: int, limit: int) -> tuple[int, int]:
    start = base + row['sector'] * 2048
    end = start + row['size']
    if base < 0 or start < base or end > limit:
        raise ValueError(f'Payload outside admitted range: {row["path"]}')
    return start, end


def safe_output(root: Path, path: str) -> Path:
    if any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in [root, *root.parents]):
        raise ValueError('Output root uses a link')
    root = root.resolve()
    out = root.joinpath(*path.split('/'))
    resolved = out.resolve()
    if not resolved.is_relative_to(root) or any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in [out, *out.parents]):
        raise ValueError('Output escapes root or uses symlink')
    return out


def protect_output(output: Path, inputs: list[Path]):
    for source in inputs:
        if output.resolve() == source.resolve() or (output.exists() and source.exists() and os.path.samefile(output, source)):
            raise ValueError('Output aliases an input file')
    if any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in [output, *output.parents]):
        raise ValueError('Report output uses a link')


def analyze(iso: Path, iso_manifest: dict, extracted: Path, output: Path,
            output_root: Path | None, patterns: list[str]) -> dict:
    """Only DISC.FAD payload base is corroborated by signatures in this build."""
    protect_output(output, [iso, *(extracted / n for n in ['DISC.FAD', 'DISC4.FAD', 'DISCE.FAD'])])
    if iso.stat().st_size != iso_manifest['source']['size']:
        raise ValueError('ISO size differs from manifest')
    # Recompute identity before using retained offsets; never trust a same-size replacement.
    with iso.open('rb') as stream:
        source_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    if source_hash != iso_manifest['source']['sha256']:
        raise ValueError('ISO digest differs from manifest')
    iso_rows = {r['path']: r for r in iso_manifest['entries']}
    main_base = iso_rows['DISC.FAD']['offset']
    main_limit = iso_rows['DISC3.FAD']['offset'] + iso_rows['DISC3.FAD']['size']
    chain = [iso_rows[n] for n in ['DISC.FAD', 'DISC1.FAD', 'DISC2.FAD', 'DISC3.FAD']]
    if main_base < 0 or main_limit > iso.stat().st_size or any(r['size'] < 0 for r in chain):
        raise ValueError('FAD extents outside ISO')
    for left, right in zip(chain, chain[1:]):
        if left['offset'] + left['size'] != right['offset']:
            raise ValueError('Main FAD extents are not contiguous')
    report = dict(schema_version=1, evidence_id='FAD-001', source_sha256=source_hash,
                  evidence_type='observed-static-with-inferred-record-semantics',
                  limitations=['No game execution; index semantics inferred from consistent fields and payload signatures.',
                               'DISC4.FAD and DISCE.FAD payload bases unresolved; their records are inventory only.'],
                  archives=[])
    with iso.open('rb') as stream:
        for name in ['DISC.FAD', 'DISC4.FAD', 'DISCE.FAD']:
            index_data = (extracted / name).read_bytes()
            source = iso_rows[name]
            stream.seek(source['offset'])
            if stream.read(source['size']) != index_data:
                raise ValueError('Extracted index differs from ISO')
            records = parse_index(index_data)
            files = [r for r in records if r['kind'] == 'file']
            item = dict(name=name, index_sha256=hashlib.sha256(index_data).hexdigest(),
                        payload_base=main_base if name == 'DISC.FAD' else None,
                        file_count=len(files), directory_count=len(records) - len(files),
                        extensions=dict(Counter(r['name'].rsplit('.', 1)[-1] for r in files)), records=records)
            for row in files:
                if name != 'DISC.FAD':
                    continue
                start, end = bound_range(row, main_base, main_limit)
                if start < main_base + source['size']:
                    raise ValueError('File points inside index')
                stream.seek(start)
                head = stream.read(min(64, row['size']))
                row.update(iso_offset=start, head_hex=head.hex())
                if output_root and any(fnmatch.fnmatchcase(row['path'], pat) for pat in patterns):
                    out = safe_output(output_root, row['path'])
                    stream.seek(start)
                    payload = stream.read(row['size'])
                    if len(payload) != row['size']:
                        raise ValueError('Short payload read')
                    digest = hashlib.sha256(payload).hexdigest()
                    out.parent.mkdir(parents=True, exist_ok=True)
                    if out.exists():
                        if out.read_bytes() != payload:
                            raise ValueError(f'Refusing to overwrite changed file: {out}')
                    else:
                        with out.open('xb') as target:
                            target.write(payload)
                    row.update(extracted_path=out.as_posix(), sha256=digest)
            report['archives'].append(item)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(output.name + '.tmp')
    with temp.open('x', encoding='utf-8') as target:
        target.write(json.dumps(report, ensure_ascii=False, indent=2))
    temp.replace(output)
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--iso-manifest', type=Path, default=Path('analysis/iso_manifest.json'))
    ap.add_argument('--extracted', type=Path, default=Path('local/extracted'))
    ap.add_argument('--output', type=Path, default=Path('analysis/fad_manifest.json'))
    ap.add_argument('--extract-to', type=Path)
    ap.add_argument('--pattern', action='append', default=[])
    args = ap.parse_args()
    manifest = json.loads(args.iso_manifest.read_text(encoding='utf-8'))
    protect_output(args.output, [args.iso_manifest])
    result = analyze(Path(manifest['source']['path']), manifest, args.extracted,
                     args.output, args.extract_to, args.pattern)
    print(json.dumps([{k:v for k,v in a.items() if k != 'records'} for a in result['archives']], indent=2))


if __name__ == '__main__':
    main()
