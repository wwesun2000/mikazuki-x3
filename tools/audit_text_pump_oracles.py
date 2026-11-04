"""Audit the Oct 31 source instruction fixtures and index their actual coverage."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
GHIDRA = ROOT / 'analysis/ghidra'
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
GROUPS = {'base': (3, 71), 'ready': (1, 4), 'glyph': (1, 4), 'ruby': (1, 4),
          'styles': (1, 9), 'timer': (1, 27), 'gate': (1, 7)}
EXPORTS = ('text-pump-direct-v1', 'text-pump-closure-v1', 'text-glyph-closure-v1',
           'text-manager-tick-v1', 'text-gs-clut-v1', 'text-gate-closure-v1')
WATCHED = (0x1126e0, 0x119f80, 0x16b200, 0x16b498, 0x16adc8, 0x16b608, 0x16a998,
           0x16afa8, 0x16b6e8, 0x16bfa8, 0x168d08, 0x168dd0, 0x1698a0, 0x121e50,
           0x122220, 0x121aa8, 0x16ca10, 0x16c998, 0x15fe30)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text())


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def main():
    elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()
    assert digest(elf) == ELF_SHA
    base_plan = read(GHIDRA / 'oracle-text-base-plan.json')
    ram = Path(base_plan['ram_input_path']).read_bytes()
    assert digest(ram) == base_plan['ram_sha256'] and ram[0x100000:0x204b38] == elf[0x1000:0x105b38]
    groups, total = {}, 0
    for group, (version, expected) in GROUPS.items():
        directory = GHIDRA / f'oracle-text-{group}-v{version}'
        manifest = read(directory / 'manifest.json')
        plan = read(directory / 'input-plan.json')
        assert manifest['status'] == 'oracle_completed'
        assert manifest['returned_count'] == manifest['case_count'] == expected
        assert manifest['source_elf_sha256'] == ELF_SHA
        assert manifest['source_ram_sha256'] == plan['ram_sha256'] == base_plan['ram_sha256']
        assert manifest['source_plan_sha256'] == digest((directory / 'input-plan.json').read_bytes())
        assert manifest['harness_sha256'] == digest((directory / 'EmulateKamaitachiControlTransfer.java').read_bytes())
        assert manifest['mmi_helper_sha256'] == digest((directory / 'KamaitachiMmiUserops.java').read_bytes())
        assert manifest['pcpyh_helper_sha256'] == digest((directory / 'KamaitachiPcpyh.java').read_bytes())
        assert manifest['pcpyh_instruction_validation']['passed'] == 256
        raw_cases = (directory / 'cases.jsonl').read_bytes()
        assert manifest['cases_sha256'] == digest(raw_cases)
        specs = {case['id']: case for case in plan['cases']}
        calls, userops, functions = Counter(), Counter(), Counter()
        rows = []
        for line in raw_cases.splitlines():
            case = json.loads(line)
            ident = case['id']
            spec = specs.pop(ident)
            assert case['input'] == spec['input'] and case['return_defined'] == spec['return_defined']
            assert case['status'] == 'returned' and not case['faults'] and not case['emulator_error']
            assert case['steps'] == len(case['trace']) and case['output']['registers']['pc'] == '0x003ff000'
            pcs = set()
            for step in case['trace']:
                pc = int(step['pc'], 16)
                assert step['step_ok'] and step['file_offset'] == pc - 0xff000
                assert 0x100000 <= pc <= 0x204b34
                assert bytes.fromhex(step['hex']) == elf[pc - 0xff000:pc - 0xff000 + 4] == ram[pc:pc + 4]
                pcs.add(pc)
            values = {item['name']: bytes.fromhex(item['hex']) for item in case['output']['memory']}
            original = {item['name']: bytes.fromhex(item['hex']) for item in case['initial_observed_memory']}
            value = int(case['output']['registers']['v0'], 16)
            if ident.startswith('end-after'):
                assert value == 0 and u32(values['manager'], 0x2b4) == 0
                assert u32(values['script'], 0xd8) == 0x1f80000 + int(ident.split('-')[2]) + 1
            if ident.startswith('not-ready'):
                assert value == 1 and u32(values['manager'], 0x2b4) == 1
                assert u32(values['script'], 0xd8) == 0x1f80000 + int(ident.split('-')[2])
            if ident.startswith(('setter-', 'cadence-')):
                assert u32(values['manager'], 0x294) == 0
                assert u32(values['manager'], 0x298) == u32(original['manager'], 0x298)
            if group == 'gate':
                assert value == 0 and {0x121e50, 0x122220, 0x121aa8, 0x16c998, 0x16ca10} <= pcs
            if ident in ('style9-817e', 'style9-81a2', 'style9-81a0'):
                assert 0x16b6e8 in pcs
            if ident == 'layout-kinsoku-close':
                assert {0x16afa8, 0x16a998} <= pcs
            if group == 'ruby' or ident == 'ruby-distinct-sjis':
                assert {0x16adc8, 0x16b608, 0x16bfa8} <= pcs
                assert u32(values['script'], 0xdc) == 0x1f80105 and u32(values['manager'], 0x2b8) == 0
            persistent = [write for write in case['tracked_writes'] if write['role'] == 'persistent']
            for write in case['tracked_writes']:
                address = int(write['address'], 16)
                assert 0 <= address <= len(ram) - write['size']
                assert write['size'] == len(bytes.fromhex(write['hex']))
                assert write['role'] in ('stack', 'persistent')
            covered = [f'0x{addr:08x}' for addr in WATCHED if addr in pcs]
            calls.update(covered)
            userops.update(case['enhanced_mmi_counts'])
            functions[case['function_address']] += 1
            rows.append(dict(id=ident, steps=case['steps'], reached=covered, persistent_ranges=len(persistent),
                             persistent_bytes=sum(write['size'] for write in persistent)))
        assert not specs and len(rows) == expected
        groups[group] = dict(directory=str(directory.relative_to(ROOT)), cases=expected,
                             cases_sha256=manifest['cases_sha256'], per_function=functions,
                             reached_in_cases=calls, userop_invocations=userops, coverage=rows)
        total += expected
    failures = {}
    for directory, reason in [('oracle-text-base-v1', 'Original memset needs _pcpyh at 001FC704'),
                              ('oracle-text-base-v2', 'Saved caller FPR was uninitialized in the original fixture'),
                              ('oracle-text-active-v1', 'Ghidra lacks authentic kernel GetThreadId syscall semantics')]:
        manifest = read(GHIDRA / directory / 'manifest.json')
        assert manifest['status'] == 'oracle_failed'
        failures[directory] = dict(reason=reason, stopped=manifest['failed'], returned_before_stop=manifest['returned_count'])
    dossiers = {}
    for name in EXPORTS:
        directory = GHIDRA / name
        manifest = read(directory / 'manifest.json')
        assert manifest['status'] == 'export_completed' and manifest['source_sha256'] == ELF_SHA
        assert manifest['counts']['database_functions_including_external'] == 6683
        for item in manifest['selected']:
            if item.get('decompilation_status') != 'completed':
                continue
            path = directory / item['file']
            dossier = read(path)
            assert dossier['disassembly']['complete']
            for unit in dossier['disassembly']['units']:
                assert unit['matches_original_elf']
            dossiers[item['requested_address']] = {'path': str(path.relative_to(ROOT)), 'sha256': digest(path.read_bytes())}
    transient = {}
    for name, status in [('text-font-vtable-leaves-v2', 'font_leaves_inspected'), ('text-input-gate-vtable-v1', 'gate_inspected')]:
        path = GHIDRA / name / 'manifest.json'
        manifest = read(path)
        assert manifest['status'] == status and manifest['temporary_functions_explicitly_removed']
        assert manifest['before_functions'] == manifest['after_functions'] == 6683
        for row in manifest['functions']:
            address = int(row['entry'], 16)
            assert digest(elf[address - 0xff000:address - 0xff000 + row['bytes']]) == row['raw_sha256']
            transient[row['entry']] = {'path': str(path.relative_to(ROOT)), 'raw_sha256': row['raw_sha256']}
    differentials = {}
    for path in sorted((ROOT / 'analysis/native-core').glob('state-calls-*.json')):
        report = read(path)
        name = Path(report['oracle']).name
        if name.startswith('oracle-text-'):
            differentials[name] = dict(path=str(path.relative_to(ROOT)), cases=report['cases'],
                                       passed=report['passed'], all_passed=report['all_passed'],
                                       probe_sha256=report['build']['state_call_sha256'])
    result = dict(schema=1, status='original_instruction_audit_passed', elf_sha256=ELF_SHA,
                  original_ram_sha256=base_plan['ram_sha256'], original_archive_sha256=base_plan['archive_sha256'],
                  total_returned=total, groups=groups, retained_failures=failures,
                  existing_function_dossiers=dossiers, transient_function_dossiers=transient,
                  native_differentials_present_at_audit=differentials,
                  limits=['Synthetic case registers and explicit data patches over verified slot7 RAM',
                          'Enhanced Ghidra p-code oracle with source-fingerprinted MMI callbacks',
                          'Active random transform stops at real kernel GetThreadId. The six planned active inputs are excluded from the pass count',
                          'The 113148 method enters kernel locks. Direct timer and input-gate execution does not establish a full game-tick oracle',
                          'Temporary vtable boundaries are distinct from the persisted Ghidra function inventory'])
    output = GHIDRA / 'text-recovery-audit-v1.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], cases=total, exported=len(dossiers), transient=len(transient),
                          native_differential_groups=len(differentials))))


if __name__ == '__main__':
    main()
