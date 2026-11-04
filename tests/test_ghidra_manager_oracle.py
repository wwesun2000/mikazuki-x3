"""Audit actual manager SLEIGH outputs; do not calculate semantic expected data."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ManagerOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ROOT / 'analysis/ghidra/oracle-manager-v1'
        if not (cls.directory / 'manifest.json').exists():
            raise unittest.SkipTest('Original manager oracle not generated')
        cls.manifest = json.loads((cls.directory / 'manifest.json').read_text())
        cls.raw = (cls.directory / 'cases.jsonl').read_bytes()
        cls.cases = [json.loads(line) for line in cls.raw.splitlines()]
        cls.elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()

    def test_provenance_and_complete_execution(self):
        m = self.manifest
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), m['elf_sha256'])
        self.assertEqual(m['status'], 'oracle_completed')
        self.assertEqual(m['planned_cases'], 300)
        self.assertEqual(m['case_count'], 300)
        self.assertEqual(m['returned_count'], 300)
        self.assertEqual(m['failed'], [])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), m['cases_sha256'])
        self.assertEqual(hashlib.sha256((self.directory / 'EmulateKamaitachiManager.java').read_bytes()).hexdigest(), m['harness_sha256'])
        self.assertEqual(len({c['function_address'] for c in self.cases}), 30)
        self.assertEqual(len({c['id'] for c in self.cases}), 300)

    def test_original_function_and_step_bytes(self):
        ranges = [r for f in self.manifest['functions'] for r in f['source_ranges']]
        for region in ranges:
            raw = bytes.fromhex(region['hex'])
            offset = region['file_offset']
            self.assertEqual(raw, self.elf[offset:offset + len(raw)])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), region['sha256'])
        for case in self.cases:
            for step in case['trace']:
                self.assertTrue(step['step_ok'])
                pc, raw = int(step['pc_before'], 16), bytes.fromhex(step['hex'])
                matches = [r for r in ranges if int(r['address'], 16) <= pc and pc + len(raw) <= int(r['address'], 16) + r['length']]
                self.assertEqual(len(matches), 1)
                offset = matches[0]['file_offset'] + pc - int(matches[0]['address'], 16)
                self.assertEqual(step['file_offset'], offset)
                self.assertEqual(raw, self.elf[offset:offset + len(raw)])

    def test_gp_snapshot_scope_and_ram_writes(self):
        for case in self.cases:
            self.assertEqual(case['status'], 'returned')
            self.assertEqual(case['faults'], [])
            self.assertIsNone(case['emulator_error'])
            self.assertEqual(case['steps'], len(case['trace']))
            self.assertEqual(int(case['input']['registers']['gp'], 16), 0x23DAF0)
            self.assertEqual(case['output']['registers']['pc'], '0x01fffff0')
            before = {s['name']: s for s in case['input']['memory']}
            after = {s['name']: s for s in case['output']['memory']}
            self.assertEqual(set(before), set(after))
            self.assertEqual(sum(len(s['hex']) // 2 for s in before.values()), 10612)
            for name in before:
                self.assertEqual(before[name]['address'], after[name]['address'])
                self.assertEqual(len(before[name]['hex']), len(after[name]['hex']))
            self.assertEqual(before['mode_jump_table'], after['mode_jump_table'])
            for write in case['tracked_writes']:
                if not write['start'].startswith('ram:'):
                    continue
                lo, hi = (int(write[k].split(':')[-1], 16) for k in ('start', 'end_inclusive'))
                self.assertTrue(any(int(s['address'], 16) <= lo and hi < int(s['address'], 16) + len(s['hex']) // 2 for s in before.values()))

    def test_mode_alias_and_input_type_coverage(self):
        modes = [c for c in self.cases if c['function_address'] == '0x001134e8']
        self.assertEqual({int(c['input']['registers']['a0'], 16) for c in modes}, {0x1f08000, 0x1f002c4, 0x1f010d4})
        handlers = [c for c in self.cases if c['function_address'] == '0x00125c40']
        self.assertTrue({13, 14, 15, 16, 17, 0x10000000d}.issubset({int(c['input']['registers']['a1'], 16) for c in handlers}))
        tokens = [c for c in self.cases if c['function_address'] == '0x00111738']
        self.assertTrue({2, 6, 0x68, 0x100000002, 0xffffffffffffffff}.issubset({int(c['input']['registers']['a2'], 16) for c in tokens}))
        voids = {0x1134d0, 0x1137f8, 0x114470, 0x114a50, 0x114a68, 0x114a78, 0x115cd8}
        for case in self.cases:
            self.assertEqual(case['return_defined'], int(case['function_address'], 16) not in voids)

    def test_cold_paths_stop_at_real_unrecovered_allocator(self):
        for suffix, caller in [('instance', '0x0010fb50'), ('mode', '0x001204b8')]:
            directory = ROOT / f'analysis/ghidra/oracle-manager-cold-{suffix}-v1'
            manifest = json.loads((directory / 'manifest.json').read_text())
            case = json.loads((directory / 'cases.jsonl').read_text().splitlines()[0])
            self.assertEqual(manifest['status'], 'oracle_failed')
            self.assertEqual(manifest['returned_count'], 0)
            self.assertEqual(case['status'], 'escaped_known_original_functions')
            self.assertEqual(case['trace'][-1]['pc_before'], caller)
            self.assertEqual(case['trace'][-1]['pc_after'], '0x0010fad0')
            self.assertEqual(case['faults'], [])


if __name__ == '__main__':
    unittest.main()
