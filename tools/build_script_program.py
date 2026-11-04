"""Index original instructions and text for static analysis and localization.

This is a bytecode index, not a linear play order. Unknown handlers remain
unknown; no prose candidates or fabricated transitions enter this format.
"""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path

from choice_branch import Script, decode_operands
from opening_instructions import SCRIPT_SHA
from vm_handlers import ROOT
from vm_control_semantics import runtime_label_ids
from scenario import parse_link

FORMAT = 'kamaitachi-script-program'
CONTROL_OPS = {0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x70, 0x71, 0x85}
SOURCES = {
    SCRIPT_SHA: ('sn4g', 1724916),
    '0c157bd95b8d87d8aae608b671807b392de07af2e3d1a38000bcb735f598f17e': ('sn2', 508120),
    '9313675de61d7034bea8eb42727b4ce0738276ff999da292d4d6b954e9f0114e': ('sn4', 728052),
}


class SourceScript(Script):
    def __init__(self, data):
        self.sha256 = hashlib.sha256(data).hexdigest()
        if self.sha256 not in SOURCES:
            raise ValueError('Script SHA-256 mismatch; unrecognized original program')
        self.source_name, expected_size = SOURCES[self.sha256]
        if len(data) != expected_size:
            raise ValueError('Source size mismatch')
        self.data, self.blocks, self.parsed = data, parse_link(data), {}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def text_record(group, selector, source_name):
    raw = ''.join(u['raw_hex'] for u in group['units'])
    return dict(id=f'{source_name}:{selector:02x}:{group["start"]:08x}',
                offset=group['start'], raw_hex=raw, text=group['decoded_cp932'],
                skip_21_offsets=group['skip_21_offsets'],
                status='source-framed; original-font-mapping-not-fully-verified')


def build_program(data):
    script = SourceScript(data)
    label_rows = runtime_label_ids(script)
    blocks, counts, texts = [], Counter(), []
    for source_block in script.blocks:
        if source_block['kind'] != 'SCR-file':
            continue
        selector = source_block['index']
        block, parsed = script.block(selector)
        rows = script.instructions(selector)
        code_start = block['offset'] + parsed['code_offset']
        code_end = block['offset'] + block['size']
        joined = b''.join(bytes.fromhex(row['raw_hex']) for row in rows)
        if joined != data[code_start:code_end]:
            raise ValueError(f'Code coverage mismatch in block {selector}')
        boundaries = {r['offset'] for r in rows}
        labels = {}
        for symbol in parsed['symbols']:
            offset = block['offset'] + symbol['destination_offset']
            if symbol['name'] in labels or offset not in boundaries:
                raise ValueError('Duplicate label or label outside instruction boundaries')
            labels[symbol['name']] = offset
        instructions = []
        for row in rows:
            op = row['opcode']
            counts[op] += 1
            item = dict(offset=row['offset'], next=row['end_exclusive'], op=op,
                        raw_hex=row['raw_hex'])
            if op in CONTROL_OPS:
                item['operands'] = decode_operands(row)
            if 'unsigned_big_endian' in row:
                item['value'] = row['unsigned_big_endian']
            if op in (0x72, 0x73, 0x74):
                raw = bytes.fromhex(row['payload_hex'])
                if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
                    raise ValueError(f'Unexpected resource token at {row["offset"]:#x}')
                item['resource'] = raw[:-1].decode('ascii', errors='strict')
            if op == 2:
                item['text'] = text_record(row['text'], selector, script.source_name)
                texts.append(item['text'])
            if op == 6:
                item['ruby'] = [text_record(t, selector, script.source_name) for t in row['auxiliary_texts']]
                texts.extend(item['ruby'])
            instructions.append(item)
        blocks.append(dict(selector=selector, code_start=code_start, code_end=code_end,
                           code_sha256=hashlib.sha256(joined).hexdigest(),
                           labels=labels,
                           label_metadata={r['label']:dict(id=r['runtime_label_id'], internal=r['internal'])
                                           for r in label_rows if r['block_selector'] == selector},
                           instructions=instructions))
    # Resolve statically packaged targets. Runtime template selectors 32..41
    # are intentionally not invented as stored blocks.
    indexed = {b['selector']: b for b in blocks}
    unresolved = []
    for block in blocks:
        for row in block['instructions']:
            operation = row.get('operands', {})
            targets = operation.get('options', [operation] if 'label' in operation else [])
            for target in targets:
                selector, label = target['block_selector'], target['label']
                if selector not in indexed or label not in indexed[selector]['labels']:
                    unresolved.append(dict(offset=row['offset'], selector=selector, label=label))
    entry_names = [data[o:o+64].split(b'\0', 1)[0].decode('ascii') for o in (32, 96)]
    entries = []
    for name in entry_names:
        matches = [r for r in label_rows if r['label'] == name]
        if len(matches) != 1:
            raise ValueError('ScenarioLink header entry missing or ambiguous')
        entry = matches[0]
        entries.append(dict(selector=entry['block_selector'], label=name,
                            offset=entry['instruction_offset'], label_id=entry['runtime_label_id']))
    units = {}
    for group in texts:
        raw = group['raw_hex']
        for at in range(0, len(raw), 4):
            unit = raw[at:at+4]
            units[unit] = bytes.fromhex(unit).decode('cp932', errors='strict')
    program = dict(schema=1, source=dict(path=f'SCENARIO/{script.source_name}.sn4', sha256=script.sha256, size=len(data)),
                   entries=entries,
                   text_unit_decode=units,
                   blocks=blocks, unresolved_static_targets=unresolved,
                   semantics='framing-only; execution requires context-specific recovered handlers')
    payload = canonical(program)
    envelope = dict(format=FORMAT, payload=payload,
                    sha256=hashlib.sha256(payload.encode('utf-8')).hexdigest())
    report = dict(schema=1, program_id=envelope['sha256'], source=program['source'],
                  blocks=len(blocks), instructions=sum(counts.values()), labels=sum(len(b['labels']) for b in blocks),
                  public_labels=sum(not r['internal'] for r in label_rows), entries=entries,
                  text_unit_count=len(units),
                  text_records=len(texts), undecoded_text_records=sum(t['text'] is None for t in texts),
                  opcode_counts={f'{op:02x}':count for op, count in sorted(counts.items())},
                  unresolved_static_targets=unresolved, complete_execution=False)
    return envelope, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()
    if args.all and (args.output or args.report):
        parser.error('--all uses separate default outputs; cannot combine explicit output paths')
    paths = [ROOT/'local/assets/SCENARIO'/f'{name}.sn4' for name in ('sn2', 'sn4', 'sn4g')] if args.all else [args.source]
    for path in paths:
        envelope, report = build_program(path.read_bytes())
        name = Path(report['source']['path']).stem
        output = args.output or ROOT/f'analysis/script-programs/{name}.program.json'
        report_path = args.report or ROOT/f'analysis/script_program_{name}.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(canonical(envelope)+'\n', encoding='utf-8', newline='\n')
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        if name == 'sn4g' and args.report is None:
            (ROOT/'analysis/script_program.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
