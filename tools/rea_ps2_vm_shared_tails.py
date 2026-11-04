"""Offline proof for the four rejected shared-return groups; never opens Ghidra."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

from vm_handlers import Image, hx

ROOT = Path(__file__).resolve().parents[1]
MAP_SHA = '8063a89ae6b9bc4c158ee8e51bf5f85e77b6d6e47cce280d326cc0ee1aa2104f'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))


def addr(value):
    return int(value.removeprefix('ram:'), 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'analysis/ghidra/vm-shared-tail-review-v1')
    args = parser.parse_args()
    image = Image((ROOT / 'local/extracted/SLPM_664.52').read_bytes())
    assert digest(ROOT / 'analysis/vm_handlers.json') == MAP_SHA
    seed = read('analysis/ghidra/vm-seed-review-v1/candidates.json')
    applied = read('analysis/ghidra/vm-seed-apply-v1/manifest.json')
    selection = read('analysis/ghidra/vm-dependency-review-v2/selection.json')
    for value in (seed['elf_sha256'], applied['source_sha256'], selection['elf_sha256']):
        assert value == image.sha256
    assert digest(ROOT / 'analysis/ghidra/vm-seed-review-v1/candidates.json') == applied['candidates_sha256']
    assert applied['status'] == 'seed_metadata_committed'
    outcomes = {x['entry']: x for x in applied['outcomes']}
    classes = {x['id']: x for x in seed['classes']}
    with (ROOT / 'analysis/ghidra/vm-dependencies-v1/functions.csv').open(newline='', encoding='utf-8') as stream:
        functions = {x['entry']: x for x in csv.DictReader(stream)}
    groups = {}
    for conflict in selection['seed_conflicts_with_owners']:
        assert len(conflict['overlaps']) == 1
        overlap = conflict['overlaps'][0]
        entry = addr(conflict['entry'])
        tail = addr(overlap['overlap_start'])
        assert addr(overlap['overlap_end']) == tail + 7
        assert [image.word(tail + i * 4) for i in range(2)] == [0x03e00008, 0x0000102d]
        outcome = outcomes[conflict['entry']]
        assert outcome['status'] == 'conflict_body_overlaps_function'
        inferred = {(addr(r['start']), addr(r['end_inclusive'])) for r in outcome['inferred_body']}
        assert inferred == {(tail, tail + 7), (entry, entry + 19)}
        expected = [0x27bdfff0, 0xffbf0000, 0xdfbf0000, 0x08000000 | (tail >> 2), 0x27bd0010]
        assert [image.word(entry + i * 4) for i in range(5)] == expected
        cls = classes[conflict['class_id']]
        assert addr(cls['targets'][conflict['slot']]) == entry
        table = addr(cls['vtable']['address'])
        assert image.word(table + 4 * conflict['slot']) == entry
        for proof in (cls['factory'], cls['constructor'], cls['vtable']):
            at, length = addr(proof['address']), proof['bytes']
            off = image.offset(at, length)
            assert image.data[off:off+length].hex() == proof['raw_hex']
        group = groups.setdefault(tail, dict(class_id=conflict['class_id'], opcodes=cls['opcodes'],
            tail_entry=hx(tail), tail_instructions=[image.record(tail+i*4) for i in range(2)],
            owner_before=functions[overlap['owner_entry']], rejected_wrappers=[]))
        assert group['class_id'] == conflict['class_id']
        owner_entry = addr(overlap['owner_entry'])
        assert owner_entry == tail + 8 == addr(cls['targets'][0])
        assert [image.word(owner_entry+i*4) for i in range(5)] == expected
        owner_ranges = json.loads(group['owner_before']['body_ranges_json'])
        assert len(owner_ranges) == 1
        assert (addr(owner_ranges[0]['min']), addr(owner_ranges[0]['max_inclusive'])) == (tail, owner_entry+19)
        group['owner_instructions'] = [image.record(owner_entry+i*4) for i in range(5)]
        group['rejected_wrappers'].append(dict(entry=hx(entry), slot=conflict['slot'],
            table_pointer=image.record(table+4*conflict['slot'], instruction=False),
            instructions=[image.record(entry+i*4) for i in range(5)]))
    assert len(groups) == 4
    for group in groups.values():
        assert sorted(x['slot'] for x in group['rejected_wrappers']) == list(range(1,25))
    files = ['analysis/vm_handlers.json', 'analysis/ghidra/vm-seed-review-v1/candidates.json',
        'analysis/ghidra/vm-seed-apply-v1/manifest.json',
        'analysis/ghidra/vm-dependency-review-v2/selection.json',
        'analysis/ghidra/vm-dependencies-v1/functions.csv', 'tools/rea_ps2_vm_shared_tails.py']
    report = dict(schema=1, status='offline-original-byte-and-export-proof', elf_sha256=image.sha256,
        source_files=[dict(path=p, sha256=digest(ROOT/p)) for p in files],
        counts=dict(shared_return_groups=4, rejected_wrappers=96, existing_slot0_wrappers=4),
        groups=list(groups.values()),
        limitations=['No Ghidra database opened or changed by this tool.',
            'Instruction text uses the bounded local decoder; original words and verified Ghidra inferred bodies are the evidence.',
            'Shared Return Calls behavior is source-reviewed; the proposed boundary repair has not been run.',
            'These are analysis function partitions, not recovered original symbols or ABI declarations.'])
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / 'proof.json'
    destination.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(output=str(destination), counts=report['counts'], elf_sha256=image.sha256)))


if __name__ == '__main__':
    main()
