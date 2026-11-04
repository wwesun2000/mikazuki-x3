"""Validate immutable original-machine evidence and the native differential."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
ELF_SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


def sha(raw):return hashlib.sha256(raw).hexdigest()


class ChoiceTransferEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=ROOT/'analysis/ghidra/oracle-choice-transfer-enhanced-v1'
        cls.manifest=json.loads((cls.directory/'manifest.json').read_text())
        cls.plan=json.loads((cls.directory/'input-plan.json').read_text())
        cls.cases=[json.loads(line) for line in (cls.directory/'cases.jsonl').read_text().splitlines()]
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()

    def test_source_and_engine_identity(self):
        self.assertEqual(sha(self.elf),ELF_SHA)
        self.assertEqual(self.manifest['source_elf_sha256'],ELF_SHA)
        self.assertEqual(self.manifest['status'],'oracle_completed')
        self.assertFalse(self.manifest['original_ghidra_mmi_support'])
        for field,name in [('source_plan_sha256','input-plan.json'),('cases_sha256','cases.jsonl'),
                           ('harness_sha256','EmulateKamaitachiChoiceTransfer.java'),('mmi_helper_sha256','KamaitachiMmiUserops.java')]:
            self.assertEqual(self.manifest[field],sha((self.directory/name).read_bytes()))

    def test_actual_source_execution_and_mmi(self):
        self.assertEqual(len(self.cases),33)
        executed=0
        for case in self.cases:
            self.assertEqual(case['status'],'returned')
            self.assertEqual(case['faults'],[])
            self.assertFalse(case['return_defined'])
            self.assertEqual(case['output']['registers']['pc'],'0x003ff000')
            executed+=sum(case['enhanced_mmi_counts'].values())
            for instruction in case['trace']:
                offset=instruction['file_offset']
                self.assertEqual(bytes.fromhex(instruction['hex']),self.elf[offset:offset+4])
                self.assertTrue(instruction['step_ok'])
        self.assertGreater(executed,0)

    def test_three_original_targets_and_no_string_relocation(self):
        fixture=json.loads((ROOT/'analysis/choice_runtime_slot7.json').read_text())
        original=bytes.fromhex(next(r['hex'] for r in fixture['memory'] if r['name']=='choice'))
        for case in self.cases:
            option=int(case['id'].split('-')[1]);registers=case['input']['registers']
            self.assertEqual(int(registers['a1'],16),int.from_bytes(original[0x44+option*4:0x48+option*4],'little'))
            self.assertEqual(int(registers['a2'],16),int.from_bytes(original[0x1c+option*4:0x20+option*4],'little'))
            self.assertFalse(any(int(p['address'],16)==0x1f80001 for p in case['input']['memory']))

    def test_prior_engine_failure_preserved(self):
        failure=json.loads((ROOT/'analysis/ghidra/oracle-choice-transfer-v1/manifest.json').read_text())
        self.assertEqual(failure['status'],'oracle_failed')
        self.assertEqual(failure['returned_count'],0)
        self.assertIn('_pcpyld',failure['failed'][0]['emulator_error'])

    def test_native_matches_all_persistent_state(self):
        native=json.loads((ROOT/'analysis/native-core/choice-transfer-diff.json').read_text())
        self.assertEqual(native['oracle'].replace('\\','/'),'analysis/ghidra/oracle-choice-transfer-enhanced-v1')
        self.assertEqual(native['status'],'passed')
        self.assertEqual(native['cases'],33)
        self.assertEqual(native['passed'],33)
        self.assertFalse(native['string_alignment_adaptation'])
        self.assertEqual(native['oracle_manifest_sha256'],sha((self.directory/'manifest.json').read_bytes()))
        self.assertTrue(all(r['compared_bytes']>52000 and not r['differences'] for r in native['rows']))


if __name__=='__main__':unittest.main()
