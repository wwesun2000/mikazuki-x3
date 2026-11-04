"""Validate standard enhanced-MMI oracle fixtures and bounded write/canary evidence."""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/ghidra/oracle-mmi-libc-v3'
SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()
    assert hashlib.sha256(elf).hexdigest() == SHA
    manifest = json.loads((OUT / 'manifest.json').read_text())
    assert manifest['status'] == 'oracle_completed'
    assert manifest['case_count'] == manifest['returned_count'] == manifest['planned_cases'] == 248
    assert manifest['elf_sha256'] == SHA and manifest['program_mutations'] == []
    assert manifest['cases_sha256'] == digest(OUT / 'cases.jsonl')
    assert manifest['harness_sha256'] == digest(OUT / 'EmulateKamaitachiMmiLibc.java')
    assert manifest['mmi_helper_sha256'] == digest(OUT / 'KamaitachiMmiUserops.java')
    assert manifest['mmi_helper_sha256'] == digest(ROOT / 'tools/ghidra/KamaitachiMmiUserops.java')
    assert len(manifest['functions']) == 8
    for function in manifest['functions']:
        for span in function['source_ranges']:
            raw = bytes.fromhex(span['hex'])
            assert raw == elf[span['file_offset']:span['file_offset'] + span['length']]
    cases = [json.loads(line) for line in (OUT / 'cases.jsonl').read_text().splitlines()]
    functions, userops = Counter(), Counter()
    instructions = set()
    max_steps = 0
    for case in cases:
        assert case['status'] == 'returned' and not case['faults'] and not case['emulator_error']
        entry = int(case['function_address'], 16)
        functions[case['function_address']] += 1
        assert sum(case['mmi_userop_counts'].values()) > 0
        userops.update(case['mmi_userop_counts'])
        max_steps = max(max_steps, case['steps'])
        for step in case['trace']:
            raw = bytes.fromhex(step['hex'])
            assert step['step_ok'] and raw == elf[step['file_offset']:step['file_offset'] + len(raw)]
            instructions.add(step['pc_before'])
        before = {m['name']: bytes.fromhex(m['hex']) for m in case['input']['memory']}
        after = {m['name']: bytes.fromhex(m['hex']) for m in case['output']['memory']}
        length = case['parameters']['length']
        alignment = case['parameters']['alignment']
        selector = case['parameters']['selector']
        allowed = {name: set() for name in before}
        if entry == 0x1fdb50:
            allowed['destination'].update(range(alignment, alignment + length + 1))
        elif entry in (0x10d4c8, 0x10d590):
            allowed['self'].update(range(0xe4 + 16 * selector, 0xe4 + 16 * selector + length + 1))
            allowed['block'].update(range(0x434, 0x435 + max(12, length)))
            allowed['block'].update((0x441, 0x442))
        elif entry == 0x10d680:
            allowed['self'].update(range(0xd8, 0xdc))
        for name in before:
            assert len(before[name]) == len(after[name])
            if name == 'stack':
                continue  # Original ABI stack is recorded, excluded only in native comparison.
            changed = {i for i, (a, b) in enumerate(zip(before[name], after[name])) if a != b}
            assert changed <= allowed[name], (case['id'], name, changed - allowed[name])
    assert functions == {'0x001fdb50': 33, '0x001fdc64': 33, '0x001fda0c': 88,
                         '0x0010d4c8': 36, '0x0010d590': 36, '0x0010d680': 22}
    diff_path = ROOT / 'analysis/native-core/diff-20261030-110316-16ee7d.json'
    diff = json.loads(diff_path.read_text())
    # Preserve the complete native differential artifact; its schema owns its result detail.
    report = {'schema': 1, 'status': 'passed', 'oracle_directory': str(OUT.relative_to(ROOT)),
              'elf_sha256': SHA, 'cases_sha256': manifest['cases_sha256'],
              'case_count': len(cases), 'per_function': functions,
              'executed_userops': userops, 'all_cases_executed_mmi': True,
              'unique_executed_instruction_addresses': len(instructions), 'maximum_steps': max_steps,
              'guest_write_canaries': 'Only declared destination/name/template/cursor ranges changed; all other supplied nonstack bytes identical',
              'native_diff': str(diff_path.relative_to(ROOT)), 'native_diff_sha256': digest(diff_path),
              'failed_predecessors': {'v1': 'Harness incorrectly treated register/unique writes as guest RAM; corrected RAM-only gate',
                                      'v2': 'Reader closure lacked original 10D720/10D610; both verified existing callees and object fields added'},
              'authority': 'Original ELF instructions with explicitly enhanced Ghidra MMI semantics; not stock Ghidra or console/PCSX2 execution'}
    (OUT / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'cases': len(cases), 'max_steps': max_steps,
                      'unique_pcs': len(instructions), 'mmi_executions': sum(userops.values())}))


if __name__ == '__main__':
    main()
