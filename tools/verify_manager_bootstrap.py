"""Cross-check fresh native factories against disk tables and actual slot7 objects."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from generate_cold_manager_bindings import context_rows
from vm_handlers import Image

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, address):
    return struct.unpack_from('<I', data, address)[0]


def main():
    build = json.loads((ROOT / 'local/pc-core/manager_bootstrap_probe.build.json').read_text())
    exe = Path(build['output'])
    stable = lambda: all(sha(Path(p).read_bytes()) == h for p, h in build['sources'].items())
    assert stable() and sha(exe.read_bytes()) == build['output_sha256']
    baseline = json.loads((ROOT / 'analysis/native-core/script-bootstrap-v1.json').read_text())
    entry = {r['script']: r for r in baseline['cases'] if r['native']['heap_fill'] == 0}
    elf = ROOT / 'local/extracted/SLPM_664.52'
    assert sha(elf.read_bytes()) == baseline['elf_sha256']
    contexts = context_rows(Image(elf.read_bytes()))
    source = json.loads((ROOT / 'analysis/vm_handlers.json').read_text())
    slot7 = (ROOT / 'local/ghidra-oracle-inputs/choice-slot7-ee.bin').read_bytes()
    assert sha(slot7) == 'acc9bf38c3ce3b4d8a4a375f2851425a4bde549881614b40214a474a2e61550c'
    observed_manager = u32(slot7, 0x235e40)
    rows = []
    with tempfile.TemporaryDirectory(dir=ROOT / 'local/pc-core') as tmp:
        for asset, reference in entry.items():
            path = ROOT / f'local/assets/SCENARIO/{asset}.sn4'
            assert sha(path.read_bytes()) == reference['source_sha256']
            for fill in (0, 165):
                memory_path = Path(tmp) / 'ram.bin'
                run = subprocess.run([str(exe), str(elf), str(path), str(fill), str(memory_path)],
                                     capture_output=True, text=True, timeout=60)
                if run.returncode: raise RuntimeError(run.stderr + run.stdout)
                result = json.loads(run.stdout); memory = memory_path.read_bytes()
                assert len(memory) == 32 * 1024 * 1024
                manager, registry = result['manager'], result['registry']
                for _, cell, primary, secondary in contexts:
                    current, observed = u32(memory, cell), u32(slot7, cell)
                    assert current and observed and u32(memory, current) == u32(slot7, observed) == primary
                    if secondary:
                        assert u32(memory, current+4) == u32(slot7, observed+4) == secondary
                for opcode in range(137):
                    current = u32(memory, manager + 0x5c + 4 * opcode)
                    observed = u32(slot7, observed_manager + 0x5c + 4 * opcode)
                    row = source['opcode_entries'][opcode] if opcode < 135 else None
                    expected = int(row['vtable'], 16) if row and row['vtable'] else None
                    if expected is None:
                        assert current == observed == 0
                    else:
                        assert current and observed and u32(memory, current) == u32(slot7, observed) == expected
                        size = source['factory_cases'][row['factory_case']]['allocation_size']
                        assert memory[current+4:current+size] == bytes([fill]) * (size - 4)
                for number in range(5):
                    current = u32(memory, manager + 0x280 + 4 * number)
                    observed = u32(slot7, observed_manager + 0x280 + 4 * number)
                    assert current and observed and u32(memory, current) == u32(slot7, observed)
                expected_objects = [manager + 0x308, manager + 0x724, manager + 0x804,
                                    u32(memory, manager + 0x20), result['script'], u32(memory, manager + 0x850) + 20]
                assert u32(memory, registry + 0xf4) == 6
                observed_registry = u32(slot7, 0x235cd8)
                assert u32(slot7, observed_registry + 0xf4) == 6
                for number, obj in enumerate(expected_objects):
                    assert u32(memory, registry + 4 + number * 12) == obj
                    expected_size = reference['native']['registration_bytes'] if number == 4 else 64
                    assert u32(memory, registry + 8 + 12 * number) == expected_size
                    if asset == 'sn4g':
                        assert expected_size == u32(slot7, observed_registry + 8 + 12 * number)
                assert result['selector'] == reference['native']['selector'] and result['entry_offset'] == 14
                assert result['opcode'] == 34 and result['source_target'] == 0x12f8d8
                assert result['first_opcode_completed'] and result['first_result'] == 0
                assert result['committed_steps'] >= 1 and not result['first_call_frontier']
                rows.append(dict(script=asset, script_sha256=reference['source_sha256'], heap_fill=fill,
                                 native=result, ram_sha256=sha(memory)))
    assert stable()
    report = dict(schema=1, status='cold_dispatch_graph_verified', build=build, cases=rows,
                  source_elf_sha256=baseline['elf_sha256'], original_observation_ram_sha256=sha(slot7),
                  inputs='Native construction uses original ELF+ScenarioLink and fresh 32 MiB RAM; observed RAM is read only by this independent comparison',
                  verified=['137 registry slots and per-instance vtables agree with original slot7 RAM and ELF case table',
                            '26 singleton objects including six secondary vtables agree with the original slot7 objects',
                            'All 115 original objects allocated separately, 22 null entries, five auxiliary handlers',
                            'Six save registration records in source order. Original SN4G sizes agree with running source state',
                            'First actual 0x22 returns 0 through the default dispatcher on each original file and heap fill'],
                  limitations=['Per-command validation; full platform scene activation and later story execution require separate frame tests'])
    dest = ROOT / 'analysis/native-core/manager-bootstrap-v2.json'
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], cases=len(rows), first_frontier=rows[0]['native']['first_call_frontier'],
                          report=str(dest.relative_to(ROOT)))))


if __name__ == '__main__':
    main()
