"""Audit original SLEIGH output and provenance; no replacement semantic model."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
TABLE_ENTRIES = {f'0x00{x.lower()}' for x in '''10D4C8 10D590 10DB48 10DC30
10EE18 10EFC0 10F018 10F070 10F0C0 10F628 10F678 10F6E0 10F820 10F8B0
10F938 10F9B0 10FA48 10FA88'''.split()}


class GhidraTablesOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = {}
        for group in ('tables', 'libc'):
            directory = ROOT / f'analysis/ghidra/oracle-{group}-v1'
            if not (directory / 'manifest.json').exists():
                raise unittest.SkipTest(f'{group} machine-code oracle is not generated yet')
            manifest = json.loads((directory / 'manifest.json').read_text())
            raw = (directory / 'cases.jsonl').read_bytes()
            cls.runs[group] = directory, manifest, raw, [json.loads(line) for line in raw.splitlines()]
        cls.elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()

    def test_provenance_hashes_and_completed_status(self):
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), ELF_SHA)
        for group, (directory, manifest, raw, cases) in self.runs.items():
            self.assertEqual(manifest['elf_sha256'], ELF_SHA)
            self.assertEqual(manifest['status'], 'oracle_completed')
            self.assertEqual(manifest['language_id'], 'r5900:LE:32:default')
            self.assertEqual(manifest['failed'], [])
            self.assertEqual(manifest['case_group'], group)
            self.assertEqual(manifest['planned_cases'], len(cases))
            self.assertEqual(manifest['case_count'], len(cases))
            self.assertEqual(manifest['returned_count'], len(cases))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['cases_sha256'])
            self.assertEqual(hashlib.sha256((directory / 'EmulateKamaitachiTables.java').read_bytes()).hexdigest(), manifest['harness_sha256'])
            self.assertEqual(len({case['id'] for case in cases}), len(cases))

    def test_original_function_and_trace_bytes(self):
        for _, manifest, _, cases in self.runs.values():
            ranges = [r for f in manifest['functions'] for r in f['source_ranges']]
            for region in ranges:
                raw = bytes.fromhex(region['hex'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), region['sha256'])
                start = region['file_offset']
                self.assertEqual(raw, self.elf[start:start + len(raw)])
            for case in cases:
                for step in case['trace']:
                    self.assertTrue(step['step_ok'], case['id'])
                    pc, raw = int(step['pc_before'], 16), bytes.fromhex(step['hex'])
                    matching = [r for r in ranges if int(r['address'], 16) <= pc and pc + len(raw) <= int(r['address'], 16) + r['length']]
                    self.assertEqual(len(matching), 1, case['id'])
                    offset = matching[0]['file_offset'] + pc - int(matching[0]['address'], 16)
                    self.assertEqual(offset, step['file_offset'])
                    self.assertEqual(raw, self.elf[offset:offset + len(raw)])

    def test_observed_memory_is_bounded_and_all_writes_captured(self):
        for _, manifest, _, cases in self.runs.values():
            for case in cases:
                self.assertEqual(case['status'], 'returned', case['id'])
                self.assertEqual(case['faults'], [], case['id'])
                self.assertIsNone(case['emulator_error'])
                self.assertEqual(case['steps'], len(case['trace']))
                self.assertLessEqual(case['steps'], manifest['step_limit'])
                self.assertEqual(case['output']['registers']['pc'], '0x01fffff0')
                before = {s['name']: s for s in case['input']['memory']}
                after = {s['name']: s for s in case['output']['memory']}
                self.assertEqual(set(before), set(after))
                total_bytes = sum(len(bytes.fromhex(s['hex'])) for s in before.values())
                self.assertEqual(total_bytes, 7424)
                for name in before:
                    self.assertEqual(before[name]['address'], after[name]['address'])
                    self.assertEqual(len(before[name]['hex']), len(after[name]['hex']))
                for write in case['tracked_writes']:
                    if not write['start'].startswith('ram:'):
                        continue
                    start = int(write['start'].split(':')[-1], 16)
                    end = int(write['end_inclusive'].split(':')[-1], 16)
                    self.assertTrue(any(int(s['address'], 16) <= start and end < int(s['address'], 16) + len(s['hex']) // 2 for s in before.values()), case['id'])

    def test_required_input_branches_and_return_contract(self):
        tables = self.runs['tables'][3]
        libc = self.runs['libc'][3]
        self.assertEqual({c['function_address'] for c in tables}, TABLE_ENTRIES)
        self.assertEqual({c['function_address'] for c in libc}, {'0x001fdb50', '0x001fdc64', '0x001fda0c', '0x001fc524'})
        for case in tables:
            self.assertEqual(case['return_defined'], case['function_address'] not in {'0x0010f678', '0x0010f6e0'})
        copies = [c for c in libc if c['function_address'] == '0x001fc524']
        distances = {int(c['input']['registers']['a0'], 16) - int(c['input']['registers']['a1'], 16) for c in copies}
        self.assertEqual(distances, {-16, 0, 16, 0x100})
        self.assertTrue(any('identical-pointer' in c['category'] for c in tables))
        self.assertTrue(any('safe-miss' in c['category'] for c in tables))
        self.assertTrue(any('relocation' in c['category'] for c in tables))
        self.assertTrue(any('enumeration' in c['category'] for c in tables))

    def test_mmi_failure_probes_are_not_pass_fixtures(self):
        for group, pc in [('strcpy', '0x001fdba0'), ('strcmp', '0x001fda5c'), ('template', '0x001fdc98')]:
            directory = ROOT / f'analysis/ghidra/oracle-tables-mmi-{group}-v1'
            manifest = json.loads((directory / 'manifest.json').read_text())
            cases = [json.loads(line) for line in (directory / 'cases.jsonl').read_text().splitlines()]
            self.assertEqual(manifest['status'], 'oracle_failed')
            self.assertEqual(manifest['case_count'], 1)
            self.assertEqual(manifest['returned_count'], 0)
            self.assertEqual(cases[0]['status'], 'emulation_error')
            self.assertEqual(cases[0]['trace'][-1]['pc_before'], pc)
            self.assertIn('_pcpyld', cases[0]['emulator_error'])
            self.assertFalse(cases[0]['trace'][-1]['step_ok'])


if __name__ == '__main__':
    unittest.main()
