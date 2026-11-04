"""Source-bound SLEIGH choice-leaf evidence; expected values are not modeled here."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GhidraChoiceOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = ROOT/'analysis/ghidra/oracle-choice-v1'
        if not (cls.base/'manifest.json').exists():
            raise unittest.SkipTest('Local original instruction oracle not generated')
        cls.manifest = json.loads((cls.base/'manifest.json').read_text())
        cls.raw = (cls.base/'cases.jsonl').read_bytes()
        cls.cases = [json.loads(line) for line in cls.raw.splitlines()]
        cls.elf = (ROOT/'local/extracted/SLPM_664.52').read_bytes()

    def test_provenance_and_complete_execution(self):
        m = self.manifest
        self.assertEqual(m['status'], 'oracle_completed')
        self.assertEqual(m['case_count'], 154)
        self.assertEqual(m['returned_count'], 154)
        self.assertEqual(m['failed'], [])
        self.assertEqual(hashlib.sha256(self.elf).hexdigest(), m['elf_sha256'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), m['cases_sha256'])
        self.assertEqual(hashlib.sha256((self.base/'EmulateKamaitachiChoice.java').read_bytes()).hexdigest(), m['harness_sha256'])
        self.assertEqual(len({c['function_address'] for c in self.cases}), 11)

    def test_trace_source_and_no_memory_faults(self):
        ranges = [r for f in self.manifest['functions'] for r in f['source_ranges']]
        for region in ranges:
            raw = bytes.fromhex(region['hex'])
            start = region['file_offset']
            self.assertEqual(raw, self.elf[start:start+len(raw)])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), region['sha256'])
        for c in self.cases:
            self.assertEqual(c['status'], 'returned')
            self.assertEqual(c['faults'], [])
            self.assertIsNone(c['emulator_error'])
            self.assertEqual(c['steps'], len(c['trace']))
            self.assertEqual(int(c['output']['registers']['pc'],16),int(c['input']['registers']['ra'],16))
            for step in c['trace']:
                pc = int(step['pc_before'],16)
                matches = [r for r in ranges if int(r['address'],16) <= pc < int(r['address'],16)+r['length']]
                self.assertEqual(len(matches),1)
                self.assertTrue(step['step_ok'])
                raw = bytes.fromhex(step['hex'])
                self.assertEqual(raw,self.elf[step['file_offset']:step['file_offset']+len(raw)])

    def test_real_slot_seven_object_bytes_not_synthetic_expected_values(self):
        fixture = json.loads((ROOT/'analysis/observations/OBS-001/state-analysis/slot-07-slices.json').read_text())
        choice = next(s for s in fixture['memory'] if s['name']=='choice')
        observed = [c for c in self.cases if c['category']=='OBS-001-slot7-original-choice-bytes']
        self.assertEqual(len(observed),11)
        for c in observed:
            before = next(s for s in c['input']['memory'] if s['name']=='choice')
            self.assertEqual(before['address'],choice['address'])
            self.assertEqual(bytes.fromhex(before['hex'])[:0x1d4],bytes.fromhex(choice['hex']))
            self.assertEqual(c['observed_fixture']['archive_sha256'],fixture['archive_sha256'])
            self.assertEqual(c['observed_fixture']['observed_sha256'],choice['sha256'])

    def test_only_source_setter_changes_guest_choice_bytes(self):
        for c in self.cases:
            before = {s['name']:bytes.fromhex(s['hex']) for s in c['input']['memory']}
            after = {s['name']:bytes.fromhex(s['hex']) for s in c['output']['memory']}
            self.assertEqual(set(before),{'choice','stack'})
            self.assertEqual(c['return_defined'], c['function_address']!='0x00117d00')
            if c['function_address']=='0x00117d00':
                self.assertEqual(before['choice'][:12],after['choice'][:12])
                self.assertEqual(before['choice'][16:],after['choice'][16:])
            else:
                self.assertEqual(before,after)


if __name__ == '__main__':
    unittest.main()
