"""Validate retained dispatch observations; never generate expected fixture outputs."""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from vm_handlers import Image

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/ghidra/oracle-dispatch-v1'
MASK = (1 << 64) - 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def reg(case, phase, name):
    return int(case[phase]['registers'][name], 16)


def memory(case, phase):
    return {r['name']: (int(r['address'], 16), bytes.fromhex(r['hex']))
            for r in case[phase]['memory']}


def word(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def signed64(word32):
    return (word32 if word32 < 0x80000000 else word32 - 0x100000000) & MASK


def main():
    image = Image((ROOT / 'local/extracted/SLPM_664.52').read_bytes())
    manifest = read(OUT / 'manifest.json')
    assert manifest['status'] == 'oracle_completed'
    assert manifest['elf_sha256'] == image.sha256
    assert digest(OUT / 'cases.jsonl') == manifest['cases_sha256']
    assert digest(OUT / 'EmulateKamaitachiDispatch.java') == manifest['harness_sha256']
    assert digest(ROOT / 'tools/ghidra/EmulateKamaitachiDispatch.java') == manifest['harness_sha256']
    extension = ROOT / 'local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC/Ghidra/Extensions/ghidra-emotionengine-reloaded'
    for item in manifest['extension_files']:
        assert digest(extension / item['path']) == item['sha256']
    ranges, declared_entries = [], set()
    for function in manifest['functions']:
        declared_entries.add(int(function['function_address'], 16))
        for item in function['source_ranges']:
            start, n = int(item['address'], 16), item['length']
            offset = image.offset(start, n)
            assert offset == item['file_offset']
            assert image.data[offset:offset+n].hex() == item['hex']
            assert hashlib.sha256(bytes.fromhex(item['hex'])).hexdigest() == item['sha256']
            ranges.append((start, start+n))
    for table in manifest['original_tables']:
        start, n = int(table['address'], 16), table['length']
        offset = image.offset(start, n)
        assert image.data[offset:offset+n].hex() == table['hex']
    admitted = {image.word(0x206010 + n*4) for n in range(113)}
    assert admitted == set(manifest['admitted_opcodes']) and len(admitted) == 113
    rows = [json.loads(line) for line in (OUT / 'cases.jsonl').read_text().splitlines()]
    assert len(rows) == manifest['planned_cases'] == manifest['case_count'] == manifest['returned_count'] == 355
    assert len({r['id'] for r in rows}) == 355 and not manifest['failed']
    categories, functions = Counter(), Counter()
    sweep, seen_pcs, observed_callbacks = {}, set(), 0
    max_steps = 0
    for case in rows:
        assert case['status'] == 'returned' and not case['faults']
        entry = int(case['function_address'], 16)
        categories[case['category']] += 1
        functions[case['function_address']] += 1
        assert reg(case, 'output', 'pc') == reg(case, 'input', 'ra')
        assert reg(case, 'output', 'sp') == reg(case, 'input', 'sp')
        assert reg(case, 'output', 'ra') == reg(case, 'input', 'ra')
        for name in ('s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7'):
            assert reg(case, 'output', name) == reg(case, 'input', name)
        raw_pcs = bytes.fromhex(case['pc_trace_le32_hex'])
        assert len(raw_pcs) % 4 == 0
        pcs = [value[0] for value in struct.iter_unpack('<I', raw_pcs)]
        assert len(pcs) == case['steps'] <= manifest['step_limit'] and pcs[0] == entry
        assert all(any(lo <= pc < hi for lo, hi in ranges) for pc in pcs)
        seen_pcs.update(pcs)
        max_steps = max(max_steps, len(pcs))
        for sample in case['trace']:
            pc = int(sample['pc_before'], 16)
            assert sample['step_ok'] and pc in pcs
            raw = bytes.fromhex(sample['hex'])
            offset = image.offset(pc, len(raw))
            assert offset == sample['file_offset'] and raw == image.data[offset:offset+len(raw)]
        before, after = memory(case, 'input'), memory(case, 'output')
        assert before.keys() == after.keys()
        allowed = {'stack': set(range(256))}
        if entry == 0x120308:
            allowed['script'] = set(range(0xd8, 0xdc))
        if entry == 0x1114f0:
            allowed['manager'] = set(range(0x40, 0x44))
        if entry == 0x120250:
            allowed['context'] = set(range(4))
        for name, (address, data) in before.items():
            address_after, data_after = after[name]
            assert address == address_after and len(data) == len(data_after)
            changed = {i for i, (x, y) in enumerate(zip(data, data_after)) if x != y}
            assert changed <= allowed.get(name, set()), (case['id'], name, changed)
        events = case['callback_entries']
        for event in events:
            assert pcs[event['step']] == int(event['entry'], 16)
        handlers = [e for e in events if int(e['entry'], 16) in (0x1227f0, 0x122808)]
        observed_callbacks += len(handlers)
        if entry == 0x120308:
            script, block, manager = before['script'][1], before['block'][1], before['manager'][1]
            cursor = word(script, 0xd8)
            opcode = before['data'][1][cursor - before['data'][0]]
            assert word(after['script'][1], 0xd8) == (cursor+1) & 0xffffffff
            assert len(handlers) == int(opcode in admitted)
            assert {0x1133a8, 0x10d610, 0x10d5d8} <= set(pcs)
            if opcode in admitted:
                assert {0x1133b0, 0x1203e0, 0x1227f0, 0x122680} <= set(pcs)
                delegate = [e for e in events if int(e['entry'], 16) == 0x1203e0]
                assert len(delegate) == 1
                d = {k: int(v, 16) for k, v in delegate[0]['registers'].items()}
                assert d['a0'] == reg(case, 'input', 'a0')
                assert d['a1'] == word(manager, 0x5c+opcode*4)
                assert d['a2'] == signed64((cursor-word(block, 0x430)) & 0xffffffff)
                assert d['a3'] == opcode
            else:
                assert not events and 0x1133b0 not in pcs and 0x1203e0 not in pcs
            if case['category'] == 'all-byte-opcodes':
                assert opcode not in sweep
                sweep[opcode] = len(handlers)
        if entry in (0x120308, 0x1203e0, 0x120410):
            if handlers:
                source = ([e for e in events if int(e['entry'], 16) == 0x1203e0][0]['registers']
                          if entry == 0x120308 else case['input']['registers'])
                target = handlers[0]['registers']
                assert target['a0'] == source['a1'] and target['a1'] == source['a0']
                assert target['a2'] == source['a2'] and target['a3'] == source['a3']
                expected_target = 0x122808 if entry == 0x120410 else 0x1227f0
                assert int(handlers[0]['entry'], 16) == expected_target
            assert reg(case, 'output', 'v0') == 0
        if entry == 0x120300:
            assert reg(case, 'output', 'v0') == 0
        if entry == 0x120250:
            assert word(after['context'][1], 0) == 0x2239f0
        if entry in (0x1133a8, 0x111560):
            off = 0x38 if entry == 0x1133a8 else 0x40
            assert reg(case, 'output', 'v0') == signed64(word(before['manager'][1], off))
        if entry == 0x1114f0:
            assert word(after['manager'][1], 0x40) == reg(case, 'input', 'a1') & 0xffffffff
        if entry == 0x1133b0:
            a0, a1 = reg(case, 'input', 'a0'), reg(case, 'input', 'a1')
            address = (a0 + ((a1 << 2) & 0xffffffff) + 0x5c) & 0xffffffff
            assert reg(case, 'output', 'v0') == signed64(word(before['manager'][1], address-before['manager'][0]))
    assert set(sweep) == set(range(256)) and sum(sweep.values()) == 113
    summary = dict(schema=1, status='retained_observations_audited', elf_sha256=image.sha256,
        cases_sha256=manifest['cases_sha256'], cases=len(rows), categories=dict(categories),
        tested_entries=dict(functions), opcode_sweep=dict(total=256, real_handler_calls=113, rejected_without_callback=143),
        actual_handler_invocations=observed_callbacks, executed_unique_pcs=len(seen_pcs),
        original_function_closure=len(declared_entries), max_steps=max_steps,
        callback_argument_fidelity=True, script_cursor_changes_bounded=True, canaries_preserved=True,
        original_tables_unchanged=True, source_harness_language_hashes_verified=True,
        case_file_bytes=(OUT/'cases.jsonl').stat().st_size,
        checks='This validates actual retained observations and original-byte provenance; it does not generate fixture return values or compare C++.',
        limitations=['All real handler callbacks in this batch return zero; nonzero/blocking handler paths are not covered.',
            'Synthetic objects and Ghidra SLEIGH execution are not original cold-state or PS2 hardware observations.'])
    (OUT / 'audit.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
