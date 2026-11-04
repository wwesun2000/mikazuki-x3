"""Reproducible ELF layout, literal anchors and media-header observations."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct


def elf_report(path: Path) -> dict:
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    header = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    typ, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    sections = []
    def section(index):
        off = shoff + shsize * index
        if shsize < 40 or off + 40 > len(data):
            raise ValueError('Invalid section range')
        return struct.unpack_from('<10I', data, off)
    names = section(shstr)
    names_data = data[names[4]:names[4] + names[5]]
    for i in range(shnum):
        s = section(i)
        name = names_data[s[0]:].split(b'\0', 1)[0].decode('ascii', errors='strict')
        if s[1] != 8 and s[4] + s[5] > len(data):
            raise ValueError('Section outside file')
        sections.append(dict(index=i, name=name, type=s[1], flags=s[2], address=hex(s[3]),
                             offset=s[4], size=s[5], entry_size=s[9]))
    strings = []
    for match in re.finditer(rb'[ -~]{5,}', data):
        text = match.group().decode('ascii')
        if re.search(r'script/|font/|text/|\.fad|Vorbis|Save|SCENARIO|\.sn4|\.spk|\.fnt|\.cc|\.cpp', text, re.I):
            containers = [s for s in sections if s['type'] != 8 and s['offset'] <= match.start() < s['offset'] + s['size']]
            address = hex(int(containers[0]['address'], 16) + match.start() - containers[0]['offset']) if len(containers) == 1 else None
            strings.append(dict(offset=match.start(), address=address, text=text))
    return dict(evidence_id='ELF-LOCAL-001', sha256=hashlib.sha256(data).hexdigest(),
                machine=machine, elf_type=typ, flags=hex(flags), entry=hex(entry),
                sections=sections, literal_anchors=strings,
                limitations=['Static strings are navigation clues, not proof of executed features.',
                             'No disassembly or decompilation; R5900 semantics and VM behavior remain unknown.'])


def media_report(manifest: dict) -> dict:
    main = manifest['archives'][0]
    ipu, videos, audio, unknown = [], [], [], []
    for row in main['records']:
        if row['kind'] != 'file':
            continue
        data = bytes.fromhex(row['head_hex'])
        evidence = dict(path=row['path'], iso_offset=row['iso_offset'], size=row['size'])
        if data[:4] == b'ipum' and len(data) >= 16:
            length, width, height, frames = struct.unpack_from('<IHHI', data, 4)
            ipu.append(dict(**evidence, declared_payload_bytes=length, width=width, height=height,
                            declared_frames=frames, declared_size_matches=(length + 8 == row['size'])))
        elif data[:4] == b'\x00\x00\x01\xb3' and len(data) >= 8:
            width = (data[4] << 4) | (data[5] >> 4)
            height = ((data[5] & 15) << 8) | data[6]
            videos.append(dict(**evidence, width=width, height=height, frame_rate_code=data[7] & 15))
        elif data[:4] == b'OggS':
            p = data.find(b'\x01vorbis')
            audio.append(dict(**evidence, vorbis_id_in_head=p >= 0,
                              channels=data[p + 11] if p >= 0 and len(data) > p + 11 else None,
                              sample_rate=struct.unpack_from('<I', data, p + 12)[0] if p >= 0 and len(data) >= p + 16 else None))
        else:
            unknown.append(evidence)
    return dict(evidence_id='MEDIA-001', source_sha256=manifest['source_sha256'],
                ipu_count=len(ipu), ipu_dimension_counts=dict(Counter(f'{r["width"]}x{r["height"]}' for r in ipu)),
                mpeg_sequence_count=len(videos), ogg_count=len(audio),
                ipu=ipu, mpeg_sequences=videos, ogg=audio,
                unclassified_count=len(unknown),
                limitations=['Headers only; payloads have not all been decoded or rendered.',
                             'Pixel dimensions do not establish display aspect ratio, field order, or color accuracy.',
                             'Unknown files and auxiliary indexes require separate decoding.'])


def main():
    output = Path('analysis')
    for name, value in [('elf_report.json', elf_report(Path('local/extracted/SLPM_664.52'))),
                         ('media_report.json', media_report(json.loads((output / 'fad_manifest.json').read_text(encoding='utf-8'))))]:
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        print(name)


if __name__ == '__main__':
    main()
