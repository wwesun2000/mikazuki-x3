"""Audit fixed-RAM control-transfer oracle identity, code, branches and writes."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/ghidra/oracle-control-transfer-v1'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((OUT / 'manifest.json').read_text())
    plan = json.loads((OUT / 'input-plan.json').read_text())
    elf_path = ROOT / 'local/extracted/SLPM_664.52'
    elf = elf_path.read_bytes()
    ram_path = Path(plan['ram_input_path']); ram = ram_path.read_bytes()
    assert manifest['status'] == 'oracle_completed'
    assert manifest['case_count'] == manifest['returned_count'] == len(plan['cases']) == 54
    assert digest(elf_path) == plan['elf_sha256'] == manifest['source_elf_sha256']
    assert digest(ROOT / plan['archive']) == manifest['source_archive_sha256'] == plan['archive_sha256']
    assert digest(ram_path) == manifest['source_ram_sha256'] == plan['ram_sha256']
    assert len(ram) == 32 * 1024 * 1024
    assert digest(OUT / 'input-plan.json') == manifest['source_plan_sha256']
    assert digest(OUT / 'cases.jsonl') == manifest['cases_sha256']
    assert digest(OUT / 'EmulateKamaitachiControlTransfer.java') == manifest['harness_sha256']
    assert digest(OUT / 'KamaitachiMmiUserops.java') == manifest['mmi_helper_sha256']
    assert manifest['original_ghidra_mmi_support'] is False
    planned = {case['id']: case for case in plan['cases']}
    cases = [json.loads(line) for line in (OUT / 'cases.jsonl').read_text().splitlines()]
    assert set(planned) == {case['id'] for case in cases}
    functions, userops, calls = Counter(), Counter(), Counter()
    branches = []; pcs = set(); persistent_bytes = 0
    for case in cases:
        spec = planned[case['id']]
        assert case['input'] == spec['input'] and case['return_defined'] == spec['return_defined']
        assert case['status'] == 'returned' and not case['faults'] and not case['emulator_error']
        assert case['output']['registers']['pc'] == '0x003ff000'
        functions[case['function_address']] += 1
        userops.update(case['enhanced_mmi_counts'])
        path = {int(step['pc'], 16) for step in case['trace']}
        pcs.update(path)
        for patch in case['input']['memory']:
            address = int(patch['address'], 16); data = bytes.fromhex(patch['hex'])
            assert 0 <= address <= len(ram) - len(data)
            assert not (address < 0x204b38 and address + len(data) > 0x100000)
            assert patch['reason']
        for step in case['trace']:
            raw = bytes.fromhex(step['hex']); offset = step['file_offset']
            assert step['step_ok'] and elf[offset:offset + len(raw)] == raw
        for entry in (0x11a220, 0x10d868, 0x119de8):
            if entry in path:
                calls[f'0x{entry:08x}'] += 1
        entry = int(case['function_address'], 16)
        if entry in (0x124d48, 0x1253e8, 0x124f00):
            coverage = spec['coverage']
            restore = bool(coverage['active'] and
                           (coverage['opcode'] == 0x85 or coverage['label_kind'] != 'private-prefix'))
            assert (0x11a220 in path) == restore
            transfer = entry != 0x124d48 and not restore
            assert (0x10d868 in path) == transfer
            branches.append({'id': case['id'], 'opcode': coverage['opcode'],
                             'label_kind': coverage['label_kind'], 'resume_active': coverage['active'],
                             'executed_restore': restore, 'executed_label_transfer': transfer})
        for write in case['tracked_writes']:
            address = int(write['address'], 16); size = write['size']
            assert len(bytes.fromhex(write['hex'])) == size and 0 <= address <= len(ram) - size
            assert write['role'] in ('stack', 'persistent')
            if write['role'] == 'persistent': persistent_bytes += size
    assert functions == {'0x0011a210': 4, '0x0011a220': 4, '0x00124d48': 24,
                         '0x001253e8': 12, '0x00124f00': 4, '0x00124e38': 6}
    assert calls['0x0011a220'] == 18 and calls['0x0010d868'] == 16
    report = {'schema': 1, 'status': 'passed', 'cases': 54, 'per_function': functions,
              'source_elf_sha256': manifest['source_elf_sha256'], 'source_archive_sha256': manifest['source_archive_sha256'],
              'source_ram_sha256': manifest['source_ram_sha256'], 'cases_sha256': manifest['cases_sha256'],
              'original_instruction_PCs': len(pcs), 'maximum_steps': max(case['steps'] for case in cases),
              'real_callee_case_counts': calls, 'enhanced_mmi_counts': userops,
              'recorded_persistent_write_bytes_across_cases': persistent_bytes,
              'branch_coverage': branches,
              'native_differential': {'status': 'deferred_to_parent_final_stable_build',
                                      'initial_guard': 'Sources changed after build: choice_pipeline.cpp / choice_pipeline.hpp',
                                      'command': 'tools/python.ps1 tools/diff_original_state_calls.py analysis/ghidra/oracle-control-transfer-v1'},
              'limits': ['Original RAM plus explicitly declared synthetic input patches; not an unmodified observed execution',
                         'Engine uses the audited six-operation MMI enhancement, not stock Ghidra/PCSX2/hardware',
                         'Branch assertions audit coverage against recovered raw-code control flow; output fixtures themselves come only from emulator',
                         'Only actual RAM writes are persistent; register/unique-space writes are excluded from that classification',
                         'Guest ABI stack remains recorded and is the only planned native memory-comparison exclusion']}
    (OUT / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'cases': 54, 'unique_pcs': len(pcs),
                      'real_restore_cases': calls['0x0011a220'], 'real_transfer_cases': calls['0x0010d868']}))


if __name__ == '__main__':
    main()
