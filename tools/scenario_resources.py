"""Bounded ScenePack resource index; metadata is not a scene-program interpreter.

All offsets are bytes. Scene/cue offsets are ScenePack-block-relative unless
named absolute. No path/name prefix is used to guess script-to-scene semantics.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct

from scenario import parse_link, parse_scr

ROOT = Path(__file__).resolve().parents[1]
SPK_SHA = 'f3424310cebcc0ee374f2b7688ff69f1f06ed466daf2350df80786ce8d3d61f5'
SN4_SHA = 'f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3'
MAGIC = b'ScenePack\0\0\0\0\0\0\0:Ver:3.25.2.157\0'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unpack(fmt, data, at, limit):
    require(0 <= at and at + struct.calcsize(fmt) <= min(limit, len(data)),
            'Truncated or out-of-range structure')
    return struct.unpack_from(fmt, data, at)


def string(data, at, limit):
    require(0 <= at < limit <= len(data), 'Invalid string bounds')
    end = data.find(b'\0', at, limit)
    require(end > at, 'Missing/empty string')
    name = data[at:end].decode('ascii')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'Invalid identifier')
    return name, end + 1


def contiguous(ranges, start, end):
    require(bool(ranges), 'Empty structural region')
    ranges = sorted(ranges)
    require(ranges[0][0] == start and ranges[-1][1] == end and
            all(a[1] == b[0] for a, b in zip(ranges, ranges[1:])),
            'Structural regions overlap or leave unexplained bytes')


def parse_scene_pack(data: bytes) -> dict:
    """Parse the observed v3.25.2.157 ScenePack, rejecting inconsistent bounds."""
    require(len(data) >= 0x430 and data.startswith(MAGIC), 'Invalid ScenePack header')
    cue_base, dependency_base, program_base, reserved = unpack('<4I', data, 0x420, len(data))
    require(0x430 < cue_base <= dependency_base <= program_base < len(data), 'Invalid region pointers')
    buckets = unpack('<256I', data, 0x20, 0x420)
    pointers = [x for x in buckets if x]
    require(len(set(pointers)) == len(pointers), 'Duplicate bucket pointer')
    scenes, bucket_ranges = [], []
    names = set()
    for bucket, at in enumerate(buckets):
        if not at:
            continue
        require(0x430 <= at < cue_base, 'Bucket outside symbol region')
        start = at
        count, = unpack('<H', data, at, cue_base)
        require(count > 0, 'Empty bucket')
        at += 2
        for _ in range(count):
            size, cue_relative, dependency_relative = unpack('<HII', data, at, cue_base)
            require(size >= 10 and at + 2 + size <= cue_base, 'Invalid scene record length')
            name, stop = string(data, at + 10, at + 2 + size)
            require(stop == at + 2 + size, 'Scene string/record length mismatch')
            require(name not in names, 'Duplicate scene name in block')
            names.add(name)
            scenes.append(dict(name=name, bucket=bucket, symbol_offset=at, record_size=size + 2,
                               cue_group_offset=cue_base + cue_relative,
                               dependency_group_offset=dependency_base + dependency_relative))
            at += size + 2
        bucket_ranges.append((start, at))
    contiguous(bucket_ranges, 0x430, cue_base)
    cue_groups, dependency_groups, cue_ranges, dependency_ranges = {}, {}, [], []
    cue_names = set()
    for start in sorted({s['cue_group_offset'] for s in scenes}):
        require(cue_base <= start < dependency_base, 'Cue group outside region')
        count, = unpack('<H', data, start, dependency_base)
        at, cues = start + 2, []
        for _ in range(count):
            unknown16, size = unpack('<HH', data, at, dependency_base)
            require(size >= 8 and at + 4 + size <= dependency_base, 'Invalid cue length')
            name, stop = string(data, at + 4, at + 4 + size - 6)
            require(stop == at + 4 + size - 6, 'Cue string/record length mismatch')
            relative, trailer = unpack('<IH', data, stop, at + 4 + size)
            require(name not in cue_names, 'Duplicate cue name in block')
            cue_names.add(name)
            require(program_base + relative < len(data), 'Cue target outside program')
            cues.append(dict(name=name, record_offset=at, record_size=size + 4,
                             unknown16=unknown16, unknown_trailer16=trailer,
                             program_offset=program_base + relative))
            at += size + 4
        cue_groups[start] = cues
        cue_ranges.append((start, at))
    contiguous(cue_ranges, cue_base, dependency_base)
    for start in sorted({s['dependency_group_offset'] for s in scenes}):
        require(dependency_base <= start < program_base, 'Dependency group outside region')
        count, = unpack('<H', data, start, program_base)
        at, deps = start + 2, []
        for _ in range(count):
            name, stop = string(data, at, program_base)
            deps.append(dict(name=name, offset=at))
            at = stop
        dependency_groups[start] = deps
        dependency_ranges.append((start, at))
    contiguous(dependency_ranges, dependency_base, program_base)
    cue_starts = sorted({c['program_offset'] for group in cue_groups.values() for c in group})
    for group in cue_groups.values():
        for cue in group:
            i = bisect_right(cue_starts, cue['program_offset'])
            end = cue_starts[i] if i < len(cue_starts) else len(data)
            raw = data[cue['program_offset']:end]
            # This is a bounded byte range, not a decoded opcode sequence. The
            # final range can contain alignment padding; retain it unchanged.
            cue.update(program_end_upper_bound=end, raw_hex=raw.hex(), raw_sha256=sha(raw),
                       program_status='bounded-raw-not-interpreted')
    for scene in scenes:
        scene.update(cues=cue_groups[scene['cue_group_offset']],
                     dependencies=dependency_groups[scene['dependency_group_offset']])
    return dict(sha256=sha(data), size=len(data), cue_base=cue_base,
                dependency_base=dependency_base, program_base=program_base,
                unknown_header_word=reserved, scene_count=len(scenes),
                cue_count=len(cue_names), scenes=scenes)


def parse_mmv(data: bytes) -> list[dict]:
    """Observed 2048-byte index: 32 records of path[56], size:u32, sector:u32."""
    require(len(data) >= 2048, 'Truncated MMV index')
    result, padding = [], False
    for at in range(0, 2048, 64):
        raw = data[at:at + 64]
        if raw == bytes(64):
            padding = True
            continue
        require(not padding, 'Nonzero MMV record after padding')
        end = raw.find(b'\0', 0, 56)
        require(end > 0 and not any(raw[end:56]), 'Invalid MMV embedded path')
        path = raw[:end].decode('ascii')
        require(path.endswith(('.m2v','.m2i')), 'Unknown MMV member type')
        size, sector = struct.unpack_from('<II', raw, 56)
        start = sector * 2048
        require(size > 0 and 2048 <= start and start + size <= len(data), 'MMV member out of bounds')
        require(start == (2048 if not result else ((result[-1]['offset'] + result[-1]['size'] + 2047) // 2048) * 2048),
                'Non-contiguous/overlapping MMV sector allocation')
        require(data[start:start + 4] == b'\0\0\1\xb3', 'MMV member missing MPEG sequence header')
        payload = data[start:start + size]
        result.append(dict(index=len(result), record_offset=at, embedded_path=path,
                           size=size, sector=sector, offset=start, sha256=sha(payload)))
    require(bool(result), 'Empty MMV')
    last = result[-1]
    require(((last['offset'] + last['size'] + 2047) // 2048) * 2048 == len(data), 'Unexplained MMV tail')
    return result


def normalize_single_frame_ipu(data: bytes) -> tuple[bytes, dict]:
    """Remove only a proven extra sequence-end packet for FFmpeg's IPU parser.

    The compressed image payload is unchanged. This adapter admits this game's
    single-frame layout only; it is not a general IPU repair or transcoder.
    """
    require(16 < len(data) <= 32 * 1024 * 1024 and data[:4] == b'ipum', 'Invalid IPU file')
    length, width, height, frames = struct.unpack_from('<IHHI', data, 4)
    require(length == len(data) - 8, 'IPU declared length mismatch')
    require(0 < width <= 4096 and 0 < height <= 4096 and width % 16 == height % 16 == 0,
            'Unsupported IPU dimensions')
    require(frames == 1, 'Only single-frame IPU is admitted')
    require(data[-8:] == b'\0\0\1\xb0\0\0\1\xb1', 'Missing exact IPU frame/sequence terminators')
    require(data[16:].count(b'\0\0\1\xb0') == 1, 'Unexpected additional frame marker')
    require(data[16:].count(b'\0\0\1\xb1') == 1, 'Unexpected additional sequence marker')
    out = bytearray(data[:-4])
    struct.pack_into('<I', out, 4, len(out) - 8)
    return bytes(out), dict(source_sha256=sha(data), derived_sha256=sha(out),
                           width=width, height=height, frames=frames,
                           removed_tail_offset=len(data)-4, removed_tail_hex='000001b1',
                           old_length=length, new_length=len(out)-8,
                           unchanged_compressed_payload_sha256=sha(data[16:-4]),
                           status='lossless-container-adaptation-not-original-file')


def extract_mmv_member(data: bytes, member_index: int) -> tuple[bytes, dict]:
    members = parse_mmv(data)
    require(type(member_index) is int and 0 <= member_index < len(members), 'Invalid MMV member index')
    member = members[member_index]
    return data[member['offset']:member['offset'] + member['size']], dict(member, container_sha256=sha(data))


def lookup_se(data: bytes, name: str) -> dict:
    """Exact aligned name lookup; unused DAT slots are deliberately not decoded."""
    require(re.fullmatch(r'[0-9]{6}', name) is not None, 'SE identifier must be six digits')
    require(len(data) >= 57344, 'Truncated SE index')
    matches = []
    for at in range(0, 57344, 56):
        record = data[at:at + 56]
        if record[40:56].split(b'\0')[0] != name.encode('ascii'):
            continue
        words = struct.unpack_from('<10I', record)
        start, length = words[1] * 2048, words[2] * 2048
        require(start >= 57344 and length > 0 and start + length <= len(data), 'SE sector allocation out of range')
        matches.append(dict(name=name, record_offset=at, record_size=56, raw_hex=record.hex(),
                            raw_sha256=sha(record), words=words, sector=words[1],
                            sector_count=words[2], offset=start, allocation_size=length,
                            allocation_sha256=sha(data[start:start + length]),
                            status='named-bank-allocation-codec-and-playback-parameters-unresolved'))
    require(len(matches) == 1, f'SE name missing or ambiguous: {name}')
    return matches[0]


class ResourceIndex:
    def __init__(self, spk: bytes, assets: Path | None = None, records: list | None = None):
        self.spk_sha256 = sha(spk)
        self.assets = assets
        self.records = records or []
        self.blocks = []
        self._se = None
        self._se_sha256 = None
        for block in parse_link(spk):
            payload = spk[block['offset']:block['offset'] + block['size']]
            parsed = parse_scene_pack(payload)
            parsed.update(index=block['index'], absolute_offset=block['offset'])
            self.blocks.append(parsed)

    @classmethod
    def from_project(cls, root=ROOT):
        root = Path(root)
        spk = (root / 'local/assets/SCENARIO/sn4g.spk').read_bytes()
        require(sha(spk) == SPK_SHA, 'sn4g.spk identity mismatch')
        manifest = json.loads((root / 'analysis/fad_manifest.json').read_text(encoding='utf-8'))
        records = next(x['records'] for x in manifest['archives'] if x['name'] == 'DISC.FAD')
        return cls(spk, root / 'local/assets', records)

    def asset(self, name: str) -> dict:
        if re.fullmatch(r'[0-9]{6}', name):
            require(self.assets is not None, 'Asset directory unavailable')
            path = self.assets / 'SOUND/SSDVDAT/se.dat'
            if self._se is None:
                self._se = path.read_bytes()
                self._se_sha256 = sha(self._se)
                banks = [r for r in self.records if r.get('path') == 'SOUND/SSDVDAT/se.dat']
                require(len(banks) == 1 and len(self._se) == banks[0]['size'], 'SE bank size differs from FAD')
                require(self._se_sha256 == banks[0].get('sha256'), 'SE bank identity differs from FAD')
            return dict(kind='sound-bank-entry', path=path.as_posix(),
                        bank_sha256=self._se_sha256, **lookup_se(self._se, name))
        hits = [r for r in self.records if r['kind'] == 'file' and r['name'] == name]
        require(len(hits) == 1, f'FAD basename missing or ambiguous: {name}')
        row = hits[0]
        path = self.assets.joinpath(*row['path'].split('/'))
        data = path.read_bytes()
        require(len(data) == row['size'], 'Asset size differs from FAD manifest')
        if row.get('sha256'):
            require(sha(data) == row['sha256'], 'Asset hash differs from FAD manifest')
        result = dict(kind='file', name=name, path=path.as_posix(), fad_path=row['path'],
                      fad_index=row['index'], size=len(data), sha256=sha(data),
                      extension=path.suffix, iso_offset=row.get('iso_offset'))
        if path.suffix == '.mmv':
            result['members'] = parse_mmv(data)
            for member in result['members']:
                same = [r['path'] for r in self.records if r.get('sha256') == member['sha256']]
                member['identical_fad_files'] = same
        elif path.suffix == '.ipu':
            require(data.startswith(b'ipum') and len(data) >= 16, 'Unknown IPU header')
            length, width, height, frames = struct.unpack_from('<IHHI', data, 4)
            result['header'] = dict(declared_payload_size=length, width=width, height=height, frames=frames)
            result['decode_status'] = 'not-certified-stock-ffmpeg-can-emit-errors-and-exit-zero'
        return result

    def resolve(self, opcode: int, token: str, block_index: int | None = None) -> dict:
        require(opcode in (0x72, 0x73, 0x74), 'Not a resource opcode')
        matches = []
        for block in self.blocks:
            if block_index is not None and block['index'] != block_index:
                continue
            for scene in block['scenes']:
                cue = next((c for c in scene['cues'] if c['name'] == token), None)
                if (opcode in (0x72, 0x73) and scene['name'] == token) or (opcode == 0x74 and cue is not None):
                    matches.append((block, scene, cue if opcode == 0x74 else None))
        require(len(matches) == 1, f'Resource token missing or ambiguous: {token} ({len(matches)} matches)')
        block, scene, cue = matches[0]
        return dict(opcode=opcode, token=token, spk_block=block['index'],
                    spk_block_absolute_offset=block['absolute_offset'], scene=scene,
                    selected_cue=cue,
                    assets=[self.asset(d['name']) for d in scene['dependencies']] if self.assets else [],
                    status='exact-index-association-not-render-timeline')


def build_report(root=ROOT):
    from opening_instructions import frame_window
    root = Path(root)
    index = ResourceIndex.from_project(root)
    script = (root / 'local/assets/SCENARIO/sn4g.sn4').read_bytes()
    require(sha(script) == SN4_SHA, 'sn4g.sn4 identity mismatch')
    block = parse_link(script)[15]
    parsed = parse_scr(script[block['offset']:block['offset'] + block['size']])
    labels = {s['name']: s for s in parsed['symbols'] if s['label_prefix_offset'] is not None}
    start = block['offset'] + labels['pr01_0020']['destination_offset']
    end = block['offset'] + labels['pr01_0130']['label_prefix_offset']
    instructions = frame_window(script, start, end)
    resources, refs = {}, []
    for instruction in instructions:
        op = instruction['opcode']
        if op not in (0x72, 0x73, 0x74):
            continue
        payload = bytes.fromhex(instruction['payload_hex'])
        require(payload.endswith(b'\0') and b'\0' not in payload[:-1], 'Unexpected resource operand')
        token = payload[:-1].decode('ascii')
        key = f'{op:02x}:{token}'
        if key not in resources:
            resources[key] = index.resolve(op, token)
        refs.append(dict(offset=instruction['offset'], opcode=op, token=token, resource_key=key,
                         raw_hex=instruction['raw_hex'], raw_sha256=instruction['raw_sha256']))
    return dict(schema_version=1, evidence_id='SCENARIO-RESOURCES-001',
                sources=dict(spk_sha256=index.spk_sha256, sn4_sha256=sha(script)),
                scope=dict(start=start, end_exclusive=end, labels='pr01_0020..pr01_0120, including physical alternate branches',
                           status='static-range-not-executed-path', instruction_count=len(instructions)),
                pack_summary=[{k:b[k] for k in ('index','absolute_offset','size','sha256','scene_count','cue_count')} for b in index.blocks],
                references=refs, resources=resources,
                limitations=['Cue program bytes are not yet interpreted: timings/layers/audio triggers are unresolved.',
                             'Numeric SE entries resolve an allocation; sample rate, channels, loops and decoding are not asserted.',
                             'Stock FFmpeg IPU output must not be certified from exit status alone.',
                             'Resource associations do not determine branches or game progress.'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=ROOT)
    ap.add_argument('--output', type=Path, default=ROOT / 'analysis/scenario_resources.json')
    ap.add_argument('--resolve', help='Exact token; requires --opcode')
    ap.add_argument('--opcode', type=lambda s:int(s, 0))
    args = ap.parse_args()
    if args.resolve:
        require(args.opcode is not None, '--opcode required')
        print(json.dumps(ResourceIndex.from_project(args.root).resolve(args.opcode, args.resolve), ensure_ascii=False, indent=2))
    else:
        report = build_report(args.root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(dict(path=str(args.output), references=len(report['references']), resources=len(report['resources']),
                              scene_packs=len(report['pack_summary']))))


if __name__ == '__main__':
    main()
