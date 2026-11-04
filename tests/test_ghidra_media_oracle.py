"""Audit original media instructions/output, without a second semantic model."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MediaOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ROOT / 'analysis/ghidra/oracle-media-v1'
        if not (cls.directory / 'manifest.json').exists():
            raise unittest.SkipTest('Original media oracle not generated')
        cls.manifest = json.loads((cls.directory / 'manifest.json').read_text())
        cls.raw = (cls.directory / 'cases.jsonl').read_bytes()
        cls.cases = [json.loads(line) for line in cls.raw.splitlines()]
        cls.elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()

    def test_identity_and_complete_execution(self):
        m = self.manifest
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), m['elf_sha256'])
        self.assertEqual(m['status'], 'oracle_completed')
        for key in ('planned_cases', 'case_count', 'returned_count'):
            self.assertEqual(m[key], 264)
        self.assertEqual(m['failed'], [])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), m['cases_sha256'])
        self.assertEqual(hashlib.sha256((self.directory / 'EmulateKamaitachiMedia.java').read_bytes()).hexdigest(), m['harness_sha256'])
        self.assertEqual(len({c['function_address'] for c in self.cases}), 14)
        self.assertEqual(len({c['id'] for c in self.cases}), 264)

    def test_original_instruction_bytes_and_closure(self):
        ranges = [r for f in self.manifest['functions'] for r in f['source_ranges']]
        for region in ranges:
            raw, offset = bytes.fromhex(region['hex']), region['file_offset']
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

    def test_snapshot_scope_and_all_tracked_writes(self):
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
            self.assertEqual(sum(len(s['hex']) // 2 for s in before.values()), 12560)
            for name in before:
                self.assertEqual(before[name]['address'], after[name]['address'])
                self.assertEqual(len(before[name]['hex']), len(after[name]['hex']))
            for write in case['tracked_writes']:
                if not write['start'].startswith('ram:'):
                    continue
                lo, hi = (int(write[k].split(':')[-1], 16) for k in ('start', 'end_inclusive'))
                self.assertTrue(any(int(s['address'], 16) <= lo and hi < int(s['address'], 16) + len(s['hex']) // 2 for s in before.values()))

    def test_retry_inhibitor_modes_and_output_alias_coverage(self):
        handlers = [c for c in self.cases if c['function_address'] == '0x00127520']
        self.assertEqual(len(handlers), 32)
        self.assertEqual({int(c['output']['registers']['v0'], 16) for c in handlers}, {0, 1})
        self.assertEqual({bytes.fromhex(next(s['hex'] for s in c['input']['memory'] if s['name'] == 'data'))[0x11] for c in handlers}, {0, 1, 8, 255})
        for c in handlers:
            globals_ = next(s for s in c['input']['memory'] if s['name'] == 'globals')
            offset = 0x2360C4 - int(globals_['address'], 16)
            self.assertEqual(int.from_bytes(bytes.fromhex(globals_['hex'])[offset:offset + 4], 'little'), 1)
        modes = [c for c in self.cases if c['function_address'] == '0x0011e310']
        self.assertEqual({int(c['input']['registers']['a2'], 16) for c in modes}, {0, 1, 2, 3, 0x100000001, 0xffffffffffffffff})
        lookups = [c for c in self.cases if c['function_address'] == '0x00101b58']
        self.assertTrue(any(c['input']['registers']['a1'] == c['input']['registers']['a2'] != '0x0000000000000000' for c in lookups))
        for case in self.cases:
            self.assertEqual(case['return_defined'], int(case['function_address'], 16) not in {0x137578, 0x137598})

    def test_unimplemented_paths_are_failed_boundary_evidence(self):
        for suffix, caller, dependency in [('active-boundary', '0x001376b8', '0x001384b0'), ('cold-provider', '0x0011dad8', '0x0010fad0')]:
            directory = ROOT / f'analysis/ghidra/oracle-media-{suffix}-v1'
            manifest = json.loads((directory / 'manifest.json').read_text())
            raw = (directory / 'cases.jsonl').read_bytes()
            case = json.loads(raw.splitlines()[0])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['cases_sha256'])
            self.assertEqual(manifest['status'], 'oracle_failed')
            self.assertEqual(manifest['returned_count'], 0)
            self.assertEqual(case['status'], 'escaped_known_original_functions')
            self.assertEqual(case['trace'][-1]['pc_before'], caller)
            self.assertEqual(case['trace'][-1]['pc_after'], dependency)
            self.assertEqual(case['faults'], [])


if __name__ == '__main__':
    unittest.main()
