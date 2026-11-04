"""Read-only framing probe for the other original ScenarioLink programs."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from scenario import parse_link, parse_scr
from opening_instructions import frame_window

ROOT = Path(__file__).resolve().parents[1]

def probe(path):
    data = path.read_bytes()
    result = dict(file=path.name, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                  entries=[data[o:o+64].split(b'\0')[0].decode('ascii') for o in (32, 96)], blocks=[])
    counts = Counter()
    for block in parse_link(data):
        if block['kind'] != 'SCR-file':
            continue
        parsed = parse_scr(data[block['offset']:block['offset']+block['size']])
        try:
            rows = frame_window(data, block['offset']+parsed['code_offset'], block['offset']+block['size'])
            counts.update(r['opcode'] for r in rows)
            result['blocks'].append(dict(selector=block['index'], instructions=len(rows), symbols=parsed['symbol_count']))
        except ValueError as exc:
            result['blocks'].append(dict(selector=block['index'], error=str(exc)))
    result['opcode_counts'] = {f'{op:02x}':n for op, n in sorted(counts.items())}
    return result

if __name__ == '__main__':
    reports = [probe(ROOT/'local/assets/SCENARIO'/name) for name in ('sn2.sn4', 'sn4.sn4')]
    (ROOT/'analysis/other_program_framing.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(reports, ensure_ascii=False))
