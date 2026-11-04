"""Compare cold C++ construction to the three untouched ScenarioLink images."""
import hashlib
import json
from pathlib import Path
import subprocess
import time
from scenario import parse_link, parse_scr
from vm_control_semantics import runtime_label_ids

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_HASHES = {
    'sn2': '0c157bd95b8d87d8aae608b671807b392de07af2e3d1a38000bcb735f598f17e',
    'sn4': '9313675de61d7034bea8eb42727b4ce0738276ff999da292d4d6b954e9f0114e',
    'sn4g': 'f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class DiskScript:
    """Adapter for the existing bounded SCR parser and independent ID traversal."""
    def __init__(self, data):
        self.data = data
        self.blocks = parse_link(data)
        self.parsed = [parse_scr(data[b['offset']:b['offset'] + b['size']]) for b in self.blocks]

    def block(self, index):
        return self.blocks[index], self.parsed[index]


def main():
    build_path = ROOT / 'local/pc-core/script_bootstrap_probe.build.json'
    build = json.loads(build_path.read_text())
    executable = Path(build['output'])
    assert sha(executable.read_bytes()) == build['output_sha256']
    source_stable = lambda: all(sha(Path(p).read_bytes()) == h for p, h in build['sources'].items())
    assert source_stable(), 'Rebuild the probe after source changes'
    elf = ROOT / 'local/extracted/SLPM_664.52'
    assert sha(elf.read_bytes()) == '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
    rows = []
    for name, expected_hash in SCRIPT_HASHES.items():
        path = ROOT / 'local/assets/SCENARIO' / f'{name}.sn4'
        data = path.read_bytes()
        assert sha(data) == expected_hash
        script = DiskScript(data)
        symbols = runtime_label_ids(script)
        label = data[0x20:0x60].split(b'\0')[0].decode('ascii')
        candidates = [row for row in symbols if row['label'] == label]
        assert len(candidates) == 1
        entry = candidates[0]
        count = sum(not row['internal'] for row in symbols)
        for fill in (0, 0xa5):
            command = [str(executable), str(elf), str(path), str(fill)]
            if fill == 0xa5 and name == 'sn4g':
                command.append('check-failure')
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if run.returncode:
                raise RuntimeError(run.stdout + run.stderr)
            observed = json.loads(run.stdout)
            assert observed['status'] == 'passed' and observed['blocks'] == len(script.blocks)
            assert observed['labels'] == count
            assert observed['selector'] == entry['block_selector'] and observed['label_id'] == entry['runtime_label_id']
            assert observed['entry_relative'] == entry['code_relative_offset']
            assert observed['entry_cursor'] - observed['image'] == entry['instruction_offset']
            assert observed['entry_bytes_hex'] == data[entry['instruction_offset']:entry['instruction_offset']+16].hex()
            assert observed['registry_index'] == int(fill != 0)
            assert observed['registration_bytes'] == (count * 8 + 0x60 + 63) & ~63
            assert observed['failure_rollback_retry'] == (len(command) == 5)
            rows.append(dict(script=name, source_sha256=expected_hash, header_label=label, native=observed))
        assert sha(path.read_bytes()) == expected_hash
    assert source_stable()
    report = dict(schema=1, status='passed', run_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  build=build, elf_sha256=sha(elf.read_bytes()), cases=rows,
                  verified=['Real disk assets and original static executable constants; no snapshot supplied',
                            'Full independent SCR bucket-chain enumeration determines entry ID and exact initial instruction bytes',
                            'All 15 template blocks, all indexed labels, both cursors and all four history allocations checked',
                            'Zero / A5 arena initial contents, fresh / preexisting registry and names preserved',
                            'Late fourth-history allocation failure preserves all 32 MiB and ready resource; successful retry is byte-identical'],
                  scope=['ScriptData construction and manager+38 publication only',
                         'Probe initializes the required manager/special normal-mode fields. The rest of manager/tasks/input/presentation startup remains external',
                         'Native arena placement and resolved ready disk resource replace original heap and asynchronous I/O services',
                         'Static original-code contract and file-level validation. No claim of executing original PS2 cold heap or full boot'])
    destination = ROOT / 'analysis/native-core/script-bootstrap-v1.json'
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'cases': len(rows), 'script_entries': [
        [r['script'], r['header_label'], r['native']['selector'], r['native']['label_id'], r['native']['entry_relative']]
        for r in rows if r['native']['heap_fill'] == 0], 'report': str(destination.relative_to(ROOT))}))


if __name__ == '__main__':
    main()
