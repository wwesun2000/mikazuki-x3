"""Evidence-preserving ScenarioLink/SN4Font inspection for this X3 build.

Text extraction is provisional: it recognizes observed 02/text/03 byte spans,
not a fully decoded VM. Candidates must not be treated as release-ready dialogue.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
import unicodedata

LINK_MAGIC = b'ScenarioLink\0\0\0\0'
LINK_VERSION = b':Ver:3.25.2.157\0'
SCR_MAGIC = b'SCR-file:Ver:3.25.2.157\0'
FONT_MAGIC = b'SN4Font:V.1.4.0\0'
TEXT_PATTERN = re.compile(rb'\x02([^\x00-\x1f]{1,4096})\x03')


class ScenarioError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ScenarioError(message)


def u32(data, offset):
    require(0 <= offset <= len(data) - 4, 'uint32 outside input')
    return struct.unpack_from('<I', data, offset)[0]


def cstring(data, start, end):
    require(0 <= start < end <= len(data), 'String bounds outside input')
    stop = data.find(b'\0', start, end)
    require(stop >= 0, 'Unterminated string')
    try:
        return data[start:stop].decode('ascii'), stop
    except UnicodeDecodeError as exc:
        raise ScenarioError('Non-ASCII identifier') from exc


def parse_link(data: bytes) -> list[dict]:
    require(len(data) >= 0xa4, 'Truncated ScenarioLink header')
    require(data[:16] == LINK_MAGIC and data[16:32] == LINK_VERSION, 'Unsupported ScenarioLink signature/version')
    count = u32(data, 0xa0)
    require(0 < count <= 4096, 'Invalid block count')
    expected = 0xa4 + count * 8
    require(expected <= len(data), 'Truncated block table')
    blocks = []
    for index in range(count):
        offset, size = struct.unpack_from('<II', data, 0xa4 + index * 8)
        require(offset == expected, 'Non-contiguous or overlapping block layout unsupported')
        require(size >= 32 and offset + size <= len(data), 'Block outside input')
        payload = data[offset:offset + size]
        if payload.startswith(SCR_MAGIC):
            kind = 'SCR-file'
        elif payload[:16] == b'ScenePack\0\0\0\0\0\0\0' and payload[16:32] == LINK_VERSION:
            kind = 'ScenePack'
        else:
            raise ScenarioError(f'Unknown block signature at {offset:#x}')
        blocks.append({'index': index, 'offset': offset, 'size': size, 'kind': kind,
                       'sha256': hashlib.sha256(payload).hexdigest()})
        expected = offset + size
    require(expected == len(data), 'Unaccounted trailing bytes')
    return blocks


def parse_scr(data: bytes) -> dict:
    require(data.startswith(SCR_MAGIC) and len(data) >= 0x434, 'Invalid/truncated SCR-file')
    code_offset = u32(data, 0x430)
    require(0x434 <= code_offset <= len(data), 'Code boundary outside SCR-file')
    buckets = list(struct.unpack_from('<256I', data, 0x30))
    symbols, cursor = [], 0x434
    while cursor < code_offset:
        require(cursor + 9 <= code_offset, 'Truncated symbol record')
        link, tag, relative = struct.unpack_from('<HHI', data, cursor)
        name, end = cstring(data, cursor + 8, code_offset)
        require(bool(name) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name), 'Invalid symbol identifier')
        size = ((end + 1 - cursor + 3) // 4) * 4
        require(cursor + size <= code_offset, 'Symbol record crosses code boundary')
        require(tag in (0x6f4e, 0xffff), 'Unknown symbol tag')
        require(code_offset + relative < len(data), 'Symbol destination outside code')
        require(link in (0, size), 'Unexpected symbol link distance')
        if tag == 0x6f4e:
            destination = code_offset + relative
            require(len(name) <= 253, 'Label exceeds one-byte length encoding')
            marker = b'\x85' + bytes((len(name) + 2,))
            start = destination - len(name) - 4
            require(start >= code_offset, 'Label prefix before code')
            require(data[start:start+2] == marker and
                    data[start+3:destination] == name.encode('ascii') + b'\0' and
                    data[destination] == 0x22, 'Label and code anchor disagree')
            block_selector = data[start + 2]
        else:
            destination, start, block_selector = code_offset + relative, None, None
        symbols.append({'table_offset': cursor, 'record_size': size, 'link_delta': link,
                        'tag': f'0x{tag:04x}', 'name': name, 'code_relative_offset': relative,
                        'destination_offset': destination, 'label_prefix_offset': start,
                        'block_selector': block_selector,
                        'classification': 'corroborated-label' if tag == 0x6f4e else 'unknown-symbol-kind'})
        cursor += size
    boundaries = {row['table_offset'] for row in symbols}
    require(all(value == 0 or value in boundaries for value in buckets), 'Bucket does not point to a symbol boundary')
    return {'code_offset': code_offset, 'code_size': len(data) - code_offset,
            'symbol_count': len(symbols), 'label_count': sum(s['tag'] == '0x6f4e' for s in symbols),
            'bucket_count': 256, 'nonzero_buckets': sum(bool(v) for v in buckets), 'symbols': symbols}


def text_candidates(data: bytes, code_offset: int, symbols: list[dict]) -> tuple[list[dict], int]:
    labels = sorted((s for s in symbols if s['classification'] == 'corroborated-label'), key=lambda s: s['destination_offset'])
    positions = [s['destination_offset'] for s in labels]
    result, rejected = [], 0
    for match in TEXT_PATTERN.finditer(data, code_offset):
        raw = match.group(1)
        try:
            text = raw.decode('cp932', errors='strict')
        except UnicodeDecodeError:
            rejected += 1
            continue
        # Ideographic spaces are valid text; str.isprintable() would discard them.
        if any(unicodedata.category(c) in ('Cc', 'Cs', 'Cn') for c in text):
            rejected += 1
            continue
        previous = bisect_right(positions, match.start()) - 1
        label = labels[previous] if previous >= 0 else None
        result.append({'delimiter_offset': match.start(), 'text_offset': match.start(1),
                       'byte_length': len(raw), 'end_delimiter_offset': match.end(1),
                       'raw_hex': raw.hex(), 'text': text, 'encoding': 'cp932',
                       'nearest_preceding_label': label['name'] if label else None,
                       'nearest_label_offset': label['destination_offset'] if label else None,
                       'context_before_hex': data[max(code_offset, match.start()-12):match.start()].hex(),
                       'context_after_hex': data[match.end():match.end()+12].hex(),
                       'status': 'candidate-static-not-vm-validated'})
    return result, rejected


def parse_font(data: bytes) -> dict:
    require(data.startswith(FONT_MAGIC) and len(data) >= 28, 'Invalid/truncated SN4Font')
    count = u32(data, 24)
    require(0 < count <= 4096, 'Invalid font group count')
    cursor, groups, all_offsets = 28, [], []
    for index in range(count):
        require(cursor + 20 <= len(data), 'Truncated font group header')
        family, nominal_size, format_id, glyph_count, next_offset = struct.unpack_from('<5I', data, cursor)
        require(0 < glyph_count <= 65536, 'Invalid glyph count')
        records_end = cursor + 20 + glyph_count * 12
        require(records_end <= len(data), 'Truncated glyph table')
        require(next_offset == (records_end if index < count - 1 else 0), 'Unexpected font descriptor chain')
        glyphs, previous_code = [], -1
        for glyph_index in range(glyph_count):
            offset = cursor + 20 + glyph_index * 12
            code, metrics, payload_offset = struct.unpack_from('<III', data, offset)
            require(previous_code < code <= 0xffff, 'Unsorted or invalid character code')
            require(payload_offset < len(data), 'Glyph payload outside font')
            raw = code.to_bytes(1 if code <= 0xff else 2, 'big')
            try:
                character = raw.decode('cp932', errors='strict')
            except UnicodeDecodeError as exc:
                raise ScenarioError('Invalid CP932 font character code') from exc
            glyphs.append({'index': glyph_index, 'record_offset': offset, 'cp932_code': f'0x{code:04x}',
                           'character': character, 'metrics_raw_hex': data[offset+4:offset+8].hex(),
                           'payload_offset': payload_offset})
            all_offsets.append(payload_offset)
            previous_code = code
        groups.append({'index': index, 'header_offset': cursor, 'family_id': family,
                       'nominal_size_candidate': nominal_size, 'payload_format_id': format_id,
                       'glyph_count': glyph_count, 'next_descriptor_offset': next_offset,
                       'glyphs': glyphs})
        cursor = records_end
    require(all_offsets and all_offsets[0] == cursor and all(a < b for a, b in zip(all_offsets, all_offsets[1:])),
            'Glyph payload ordering/table boundary mismatch')
    lengths = {a: b - a for a, b in zip(all_offsets, all_offsets[1:] + [len(data)])}
    for group in groups:
        for glyph in group['glyphs']:
            glyph['payload_size'] = lengths[glyph['payload_offset']]
    return {'group_count': count, 'glyph_count': len(all_offsets), 'payload_offset': cursor,
            'header_unknown_words': list(struct.unpack_from('<2I', data, 16)), 'groups': groups,
            'limitations': ['Metrics and payload compression are not decoded.',
                            'Family/size meanings are inferred; code bytes decode directly as CP932.']}


def analyze(input_directory: Path, report_path: Path, output_directory: Path):
    output_directory.mkdir(parents=True, exist_ok=True)
    report = {'schema_version': 1, 'evidence_id': 'SCENARIO-001', 'evidence_type': 'static-with-inferred-format-semantics',
              'files': [], 'total_text_candidates': 0, 'total_characters_in_candidates': 0,
              'limitations': ['No VM execution, branch coverage, speaker identification or control-flow decoding.',
                             'Text spans are provisional lexical candidates, not complete dialogue units.',
                             'Nearest label is a file-order association, not proof of runtime reachability.',
                             'ScenePack payload instructions and font compression remain undecoded.'],
              'outputs': {'text_candidates': str(output_directory / 'text_candidates.jsonl'),
                          'symbols': str(output_directory / 'symbols.jsonl'),
                          'font_map': str(output_directory / 'font_map.json')}}
    fonts = []
    with (output_directory / 'text_candidates.jsonl').open('w', encoding='utf-8', newline='\n') as text_file, (output_directory / 'symbols.jsonl').open('w', encoding='utf-8', newline='\n') as symbol_file:
        for path in sorted(input_directory.iterdir()):
            if path.suffix not in ('.sn4', '.spk', '.fnt', '.txt'):
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            item = {'name': path.name, 'size': len(data), 'sha256': digest}
            if path.suffix in ('.sn4', '.spk'):
                blocks = parse_link(data)
                item['blocks'] = blocks
                item['block_count'] = len(blocks)
                item['text_candidate_count'] = 0
                item['characters_in_candidates'] = 0
                item['label_count'] = 0
                for block in blocks:
                    if block['kind'] != 'SCR-file':
                        continue
                    payload = data[block['offset']:block['offset']+block['size']]
                    scr = parse_scr(payload)
                    block.update({key: value for key, value in scr.items() if key != 'symbols'})
                    for symbol in scr['symbols']:
                        symbol_file.write(json.dumps(dict(source_file=path.name, source_sha256=digest, block_index=block['index'],
                                                          block_file_offset=block['offset'], **symbol), ensure_ascii=False) + '\n')
                    candidates, rejected = text_candidates(payload, scr['code_offset'], scr['symbols'])
                    block['text_candidate_count'] = len(candidates)
                    block['rejected_delimited_spans'] = rejected
                    block['characters_in_candidates'] = sum(len(c['text']) for c in candidates)
                    for candidate in candidates:
                        absolute = block['offset'] + candidate['text_offset']
                        row = dict(id=f'{path.stem}:{absolute:08x}', source_file=path.name, source_sha256=digest,
                                   block_index=block['index'], block_file_offset=block['offset'],
                                   absolute_text_offset=absolute, **candidate)
                        text_file.write(json.dumps(row, ensure_ascii=False) + '\n')
                    item['text_candidate_count'] += len(candidates)
                    item['characters_in_candidates'] += block['characters_in_candidates']
                    item['label_count'] += scr['label_count']
                report['total_text_candidates'] += item['text_candidate_count']
                report['total_characters_in_candidates'] += item['characters_in_candidates']
            elif path.suffix == '.fnt':
                font = parse_font(data)
                fonts.append(dict(source_file=path.name, source_sha256=digest, **font))
                item.update({k:v for k,v in font.items() if k != 'groups'})
                item['groups'] = [{k:v for k,v in group.items() if k != 'glyphs'} for group in font['groups']]
            elif path.name == 'namkan.txt':
                text = data.decode('cp932', errors='strict')
                item.update(encoding='cp932', character_count=len(text),
                            classification='Japanese-character-list; candidate name-entry resource')
                (output_directory / 'namkan.utf8.txt').write_text(text, encoding='utf-8', newline='')
            report['files'].append(item)
    (output_directory / 'font_map.json').write_text(json.dumps(fonts, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('evidence_id', 'total_text_candidates', 'total_characters_in_candidates', 'outputs')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('local/assets/SCENARIO'))
    parser.add_argument('--report', type=Path, default=Path('analysis/scenario_report.json'))
    parser.add_argument('--output', type=Path, default=Path('local/scenario'))
    args = parser.parse_args()
    analyze(args.input, args.report, args.output)


if __name__ == '__main__':
    main()
