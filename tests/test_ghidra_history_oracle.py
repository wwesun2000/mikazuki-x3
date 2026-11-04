"""Audit history/label SLEIGH observations, never synthesize expected semantics."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


class GhidraHistoryOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ROOT / 'analysis/ghidra/oracle-history-v1'
        if not (cls.directory / 'manifest.json').exists():
            raise unittest.SkipTest('Local machine-code oracle has not been generated')
        cls.manifest = json.loads((cls.directory / 'manifest.json').read_text())
        cls.raw = (cls.directory / 'cases.jsonl').read_bytes()
        cls.cases = [json.loads(line) for line in cls.raw.splitlines()]
        cls.elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()

    def test_hashes_and_actual_completed_execution(self):
        m = self.manifest
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), ELF_SHA)
        self.assertEqual(m['elf_sha256'], ELF_SHA)
        self.assertEqual(m['language_id'], 'r5900:LE:32:default')
        self.assertEqual(m['status'], 'oracle_completed')
        self.assertEqual(m['failed'], [])
        self.assertEqual(m['planned_cases'], 809)
        self.assertEqual(m['case_count'], len(self.cases))
        self.assertEqual(m['returned_count'], len(self.cases))
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), m['cases_sha256'])
        self.assertEqual(hashlib.sha256((self.directory / 'EmulateKamaitachiHistory.java').read_bytes()).hexdigest(), m['harness_sha256'])
        self.assertEqual(len({c['id'] for c in self.cases}), len(self.cases))

    def test_source_function_bytes_and_trace_closure(self):
        regions = [r for f in self.manifest['functions'] for r in f['source_ranges']]
        for region in regions:
            raw = bytes.fromhex(region['hex'])
            self.assertEqual(len(raw), region['length'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), region['sha256'])
            offset = region['file_offset']
            self.assertEqual(raw, self.elf[offset:offset + len(raw)])
        for case in self.cases:
            for step in case['trace']:
                self.assertTrue(step['step_ok'])
                pc = int(step['pc_before'], 16)
                raw = bytes.fromhex(step['hex'])
                matches = [r for r in regions if int(r['address'], 16) <= pc and
                           pc + len(raw) <= int(r['address'], 16) + r['length']]
                self.assertEqual(len(matches), 1)
                offset = matches[0]['file_offset'] + pc - int(matches[0]['address'], 16)
                self.assertEqual(step['file_offset'], offset)
                self.assertEqual(raw, self.elf[offset:offset + len(raw)])

    def test_guest_state_and_write_coverage(self):
        names = {'self', 'data', 'block', 'records', 'label_table', 'label_record', 'out', 'stack'}
        for case in self.cases:
            with self.subTest(case=case['id']):
                self.assertEqual(case['status'], 'returned')
                self.assertEqual(case['faults'], [])
                self.assertIsNone(case['emulator_error'])
                self.assertEqual(case['steps'], len(case['trace']))
                self.assertLessEqual(case['steps'], self.manifest['step_limit'])
                self.assertEqual(int(case['input']['registers']['v0'], 16), 0)
                self.assertEqual(int(case['output']['registers']['pc'], 16), int(case['input']['registers']['ra'], 16))
                before = {s['name']: s for s in case['input']['memory']}
                after = {s['name']: s for s in case['output']['memory']}
                self.assertEqual(set(before), names)
                self.assertEqual(set(after), names)
                self.assertEqual(len(bytes.fromhex(before['self']['hex'])), 0x200)
                self.assertEqual(len(bytes.fromhex(before['records']['hex'])), 24)
                for name in names:
                    self.assertEqual(before[name]['address'], after[name]['address'])
                    self.assertEqual(len(before[name]['hex']), len(after[name]['hex']))
                for write in case['tracked_writes']:
                    space = write['start'].split(':')[0]
                    self.assertIn(space, {'ram', 'register', 'unique'})
                    if space != 'ram':
                        continue
                    start = int(write['start'].split(':')[-1], 16)
                    end = int(write['end_inclusive'].split(':')[-1], 16)
                    self.assertTrue(any(int(s['address'], 16) <= start and end <
                                        int(s['address'], 16) + len(bytes.fromhex(s['hex']))
                                        for s in before.values()), 'RAM write outside captured fixture')

    def test_adjacent_record_and_pointer_canaries_unchanged(self):
        for case in self.cases:
            before = {s['name']: bytes.fromhex(s['hex']) for s in case['input']['memory']}
            after = {s['name']: bytes.fromhex(s['hex']) for s in case['output']['memory']}
            self.assertEqual(before['records'][:8], after['records'][:8], case['id'])
            self.assertEqual(before['records'][16:], after['records'][16:], case['id'])
            self.assertEqual(before['label_table'], after['label_table'], case['id'])

    def test_input_alias_boundary_and_return_contract_coverage(self):
        entries = {c['function_address'] for c in self.cases}
        self.assertEqual(len(entries), 30)
        for entry in ('0x0010e748', '0x0010e8d8'):
            cases = [c for c in self.cases if c['function_address'] == entry]
            modes = {c['category'] for c in cases if c['category'].startswith('getter-output-alias-')}
            self.assertEqual(modes, {f'getter-output-alias-{i}' for i in range(9)})
        saved = [c for c in self.cases if c['function_address'] == '0x0010e708']
        self.assertEqual({int(c['input']['registers']['a1'], 16) for c in saved},
                         {1, 2, 0x100000001, 0xffffffff00000001})
        labels = [c for c in self.cases if c['category'] == 'label-pointer-offset-boundary']
        self.assertEqual({c['fixture']['label_id'] for c in labels}, {0, 1, 6565, 6566, 16382, 16383})
        masks = [c for c in self.cases if c['category'] == 'history-field-masks']
        self.assertTrue(any(int(c['input']['registers']['a2'], 16) > 0xffffffff for c in masks))
        voids = {'0x0010f100', '0x0010fab8', '0x0010fac8'}
        for case in self.cases:
            self.assertEqual(case['return_defined'], case['function_address'] not in voids)
            for phase in ('input', 'output'):
                self.assertIn('a3', case[phase]['registers'])
                for value in case[phase]['registers'].values():
                    self.assertGreaterEqual(int(value, 16), 0)
                    self.assertLess(int(value, 16), 1 << 64)


if __name__ == '__main__':
    unittest.main()
