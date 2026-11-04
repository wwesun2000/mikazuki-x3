"""Audit actual SLEIGH-run fixtures; intentionally no replacement reader formula.

These tests validate provenance, trace bounds and complete snapshot structure.
They do not certify SLEIGH against a console or synthesize expected return values.
"""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


class GhidraReaderOracleTests(unittest.TestCase):
    DIRECTORY = 'oracle-readers-v1'
    @classmethod
    def setUpClass(cls):
        cls.directory = ROOT / 'analysis/ghidra' / cls.DIRECTORY
        if not (cls.directory / 'manifest.json').exists():
            raise unittest.SkipTest('Local original-ELF oracle artifact has not been generated')
        cls.manifest = json.loads((cls.directory / 'manifest.json').read_text(encoding='utf-8'))
        cls.case_bytes = (cls.directory / 'cases.jsonl').read_bytes()
        cls.cases = [json.loads(line) for line in cls.case_bytes.decode('utf-8').splitlines()]
        cls.elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()

    def test_identity_and_complete_real_execution(self):
        m = self.manifest
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), ELF_SHA)
        self.assertEqual(m['elf_sha256'], ELF_SHA)
        self.assertEqual(m['language_id'], 'r5900:LE:32:default')
        self.assertEqual(m['status'], 'oracle_completed')
        self.assertEqual(hashlib.sha256(self.case_bytes).hexdigest(), m['cases_sha256'])
        self.assertEqual(len(self.cases), m['case_count'])
        self.assertEqual(m['case_count'], m['planned_cases'])
        self.assertEqual(m['returned_count'], m['case_count'])
        self.assertEqual(m['failed'], [])
        self.assertIn('EmulatorHelper', m['engine'])
        if 'harness_sha256' in m:
            self.assertEqual(hashlib.sha256((self.directory / 'EmulateKamaitachiReaders.java').read_bytes()).hexdigest(), m['harness_sha256'])

    def test_original_function_bytes_not_rewritten(self):
        for function in self.manifest['functions']:
            for region in function['source_ranges']:
                raw = bytes.fromhex(region['hex'])
                self.assertEqual(len(raw), region['length'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), region['sha256'])
                start = region['file_offset']
                self.assertEqual(raw, self.elf[start:start+len(raw)])

    def test_every_case_has_full_guest_snapshots_and_no_faults(self):
        for case in self.cases:
            with self.subTest(case=case['id']):
                self.assertEqual(case['status'], 'returned')
                self.assertEqual(case['faults'], [])
                self.assertIsNone(case['emulator_error'])
                self.assertEqual(case['steps'], len(case['trace']))
                self.assertLessEqual(case['steps'], self.manifest['step_limit'])
                self.assertEqual(int(case['output']['registers']['pc'], 16),
                                 int(case['input']['registers']['ra'], 16))
                self.assertEqual(int(case['input']['registers']['v0'], 16), 0)
                before = {s['name']: s for s in case['input']['memory']}
                after = {s['name']: s for s in case['output']['memory']}
                self.assertEqual(set(before), {'self', 'block', 'data', 'stack'})
                self.assertEqual(set(before), set(after))
                for name in before:
                    self.assertEqual(before[name]['address'], after[name]['address'])
                    self.assertEqual(len(bytes.fromhex(before[name]['hex'])),
                                     len(bytes.fromhex(after[name]['hex'])))
                self.assertEqual(len(bytes.fromhex(before['self']['hex'])), 0x200)
                for write in case['tracked_writes']:
                    space = write['start'].split(':')[0]
                    self.assertIn(space, {'ram', 'register', 'unique'})
                    if space != 'ram':
                        continue  # SLEIGH temporaries/register storage are not guest RAM.
                    start = int(write['start'].split(':')[-1], 16)
                    end = int(write['end_inclusive'].split(':')[-1], 16)
                    self.assertTrue(any(int(segment['address'], 16) <= start and
                                        end < int(segment['address'], 16) + len(bytes.fromhex(segment['hex']))
                                        for segment in before.values()), 'Observed memory write missing from snapshots')
                for phase in ('input', 'output'):
                    for register, raw in case[phase]['registers'].items():
                        self.assertIsInstance(raw, str)
                        self.assertGreaterEqual(int(raw, 16), 0)
                        self.assertLess(int(raw, 16), 1 << 64)

    def test_traced_instructions_are_original_and_within_declared_closure(self):
        regions = [r for f in self.manifest['functions'] for r in f['source_ranges']]
        for case in self.cases:
            for step in case['trace']:
                self.assertTrue(step['step_ok'])
                pc = int(step['pc_before'], 16)
                raw = bytes.fromhex(step['hex'])
                matching = [r for r in regions if int(r['address'], 16) <= pc and
                            pc + len(raw) <= int(r['address'], 16) + r['length']]
                self.assertEqual(len(matching), 1)
                region = matching[0]
                actual_offset = region['file_offset'] + pc - int(region['address'], 16)
                self.assertEqual(step['file_offset'], actual_offset)
                self.assertEqual(raw, self.elf[actual_offset:actual_offset+len(raw)])

    def test_requested_input_coverage_and_void_contract(self):
        for entry in ('0x0010d5d8', '0x0010d6c8'):
            cases = [c for c in self.cases if c['function_address'] == entry]
            self.assertEqual({int(c['input']['registers']['a1'], 16) for c in cases}, set(range(9)))
            self.assertTrue(any(c['category'] == 'reader-random-fixed-seed' for c in cases))
            self.assertTrue(any(any(b > 127 for b in bytes.fromhex(c['input']['memory'][1]['hex'])) for c in cases))
        self.assertTrue(any(c['category'] == 'cursor-wrap-register-only' for c in self.cases))
        void_entries = {'0x0010d700', '0x0010d728', '0x0010d738', '0x0010d780',
                        '0x0010d7b0', '0x0010d7d0', '0x0010d800', '0x0010d830'}
        for case in self.cases:
            self.assertEqual(case['return_defined'], case['function_address'] not in void_entries)
        self.assertTrue(all(c['return_defined'] for c in self.cases if c['function_address'] == '0x0010d638'))


class GhidraStringOracleTests(GhidraReaderOracleTests):
    DIRECTORY = 'oracle-strings-v1'

    def test_requested_input_coverage_and_void_contract(self):
        alignments = set()
        lengths = set()
        for case in self.cases:
            self.assertEqual(case['function_address'], '0x0010d680')
            self.assertTrue(case['return_defined'])
            segments = {segment['name']: segment for segment in case['input']['memory']}
            state_bytes = bytes.fromhex(segments['self']['hex'])
            pointer = int.from_bytes(state_bytes[0xd8:0xdc], 'little')
            alignments.add(pointer % 16)
            data = bytes.fromhex(segments['data']['hex'])
            start = pointer - int(segments['data']['address'], 16)
            lengths.add(data.index(0, start) - start)  # Fixture input coverage, not expected return.
        self.assertIn(8, alignments)
        self.assertNotIn(0, alignments)
        self.assertTrue(any(value % 8 for value in alignments))
        self.assertEqual(lengths, {0, 1, 7, 8, 15, 16, 31, 63})


class GhidraMmiOracleLimitationTests(unittest.TestCase):
    def test_unsupported_original_mmi_is_a_failure_not_a_fixture(self):
        directory = ROOT / 'analysis/ghidra/oracle-mmi-probe-v1'
        if not (directory / 'manifest.json').exists():
            self.skipTest('Local MMI engine capability probe not generated')
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['status'], 'oracle_failed')
        self.assertEqual(manifest['returned_count'], 0)
        self.assertEqual(manifest['case_count'], 1)
        case = json.loads((directory / 'cases.jsonl').read_text(encoding='utf-8').splitlines()[0])
        self.assertEqual(case['status'], 'emulation_error')
        self.assertIn('Unimplemented CALLOTHER pcodeop (_pcpyld)', case['emulator_error'])
        self.assertEqual(case['trace'][-1]['pc_before'], '0x001fdc98')
        self.assertFalse(case['trace'][-1]['step_ok'])


if __name__ == '__main__':
    unittest.main()
