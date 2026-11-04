"""Index real VM function dossiers and verify the bounded metadata repair evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
CONTEXT = [0x120300, 0x120308, 0x1203e0, 0x120410, 0x120250, 0x120260]
CHAIN = [0x113148, 0x1126e0, 0x120308, 0x1203e0, 0x110628, 0x111738,
         0x1133a8, 0x1133b0, 0x1133c8, 0x1114f0, 0x111560]


def read(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def number(value):
    return int(value.removeprefix('ram:'), 16)


def main():
    assert sha('local/extracted/SLPM_664.52') == SHA
    repair_dir = Path('analysis/ghidra/vm-shared-tail-main-v1')
    repair = read(repair_dir / 'manifest.json')
    assert repair['status'] == 'repair_metadata_committed'
    assert repair['functions_added'] == 103 and repair['owners_changed'] == 4
    assert repair['flow_overrides_changed'] == 100 and repair['functions_after'] == 6683
    assert read(repair_dir / 'memory-before.json') == read(repair_dir / 'memory-after.json')
    assert read(repair_dir / 'oracle-before.json') == read(repair_dir / 'oracle-after.json')
    assert len(read(repair_dir / 'oracle-before.json')) == 200
    assert all(x['status'] == 'passed' for x in read(repair_dir / 'oracle-before.json'))
    copy_dir = Path('analysis/ghidra/vm-shared-tail-remainder-v2')
    assert read(repair_dir / 'functions-after.json') == read(copy_dir / 'functions-after.json')
    assert repair['flows_after_sha256'] == read(copy_dir / 'manifest.json')['flows_after_sha256']
    backup = read('analysis/ghidra/vm-shared-tail-review-v1/database-backup.json')
    for item in backup['files']:
        assert hashlib.sha256((Path(backup['backup']) / item['path']).read_bytes()).hexdigest() == item['sha256']
    found, missing = {}, {}
    for directory in ('analysis/ghidra/vm-primary-v1', 'analysis/ghidra/vm-execution-chain-v1'):
        manifest = read(Path(directory) / 'manifest.json')
        assert manifest['status'] == 'export_completed' and manifest['source_sha256'] == SHA
        for item in manifest['selected']:
            entry = number(item['requested_address'])
            if item['status'] != 'existing_function':
                missing[entry] = item
                continue
            assert item['decompilation_status'] == 'completed'
            path = Path(directory) / item['file']
            dossier = read(path)
            assert number(dossier['function']['entry']) == entry
            assert dossier['decompilation']['status'] == 'completed'
            assert all(u['matches_original_elf'] for u in dossier['disassembly']['units'])
            found[entry] = dict(entry=f'0x{entry:08x}', path=path.as_posix(),
                sha256=sha(path), status='real-ghidra-decompilation-completed',
                body_ranges=dossier['function']['body_ranges'])
    anchors = read('analysis/ghidra/vm-seed-review-v1/anchors.json')['anchors']
    primary = []
    for anchor in anchors:
        entry = number(anchor['address'])
        assert entry in found
        primary.append(dict(role=anchor['role'], **found[entry]))
    assert len(primary) == 144
    context = [dict(slot=i, **found[e]) for i, e in enumerate(CONTEXT)]
    chain = [found[e] if e in found else dict(entry=f'0x{e:08x}',
        status='requested-address-not-exact-function-entry', evidence=missing[e]) for e in CHAIN]
    assert [e for e in CHAIN if e not in found] == [0x1133c8]
    sources = [repair_dir / name for name in ('manifest.json', 'function-diff.json', 'flow-diff.json',
        'memory-before.json', 'memory-after.json', 'oracle-before.json', 'oracle-after.json')]
    result = dict(schema=1, source_elf_sha256=SHA,
        counts=dict(primary_anchors_completed=144, default_context_completed=6,
            requested_chain_completed=10, requested_chain_not_exact_entry=1),
        primary_anchors=primary, default_context=context, requested_execution_chain=chain,
        shared_return_helpers=[found[e] for e in (0x122680, 0x126fc0, 0x130348, 0x133180)],
        repair=dict(functions_added=103, wrapper_functions_added=96, tail_functions_added=4,
            context_functions_added=3, owner_bodies_changed=4, tail_flows_changed=100,
            original_code_oracle_cases_before_and_after=200, copy_main_inventory_equal=True,
            all_initialized_memory_unchanged=True, backup_files_unchanged=True,
            source_files=[dict(path=p.as_posix(), sha256=sha(p)) for p in sources]),
        limitations=['Evidence-guided analytical function partitions; not original symbols.',
            'Wrapper decompiler prototypes may remain void despite machine-code return-zero proof; no ABI types forced.',
            '0x1133c8 is inside existing 0x1133c0; no function was created there.',
            'Original-instruction oracle is Ghidra SLEIGH execution, not PS2 hardware or full-game validation.'])
    result['repair']['official_sources'] = read(repair_dir / 'upstream-sources.json')
    destination = ROOT / 'analysis/ghidra/vm-execution-index-v1.json'
    destination.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(output=str(destination), counts=result['counts'], repair=result['repair'])))


if __name__ == '__main__':
    main()
