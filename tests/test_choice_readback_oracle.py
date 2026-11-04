import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


def sha(b):return hashlib.sha256(b).hexdigest()


class ReadbackEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=ROOT/'analysis/ghidra/oracle-choice-readback-v1'
        cls.manifest=json.loads((cls.root/'manifest.json').read_text())
        cls.cases=[json.loads(x) for x in (cls.root/'cases.jsonl').read_text().splitlines()]
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()

    def test_identity_and_returned_source_execution(self):
        self.assertEqual(self.manifest['status'],'oracle_completed')
        self.assertEqual(self.manifest['returned_count'],14)
        self.assertEqual(sha(self.elf),self.manifest['source_elf_sha256'])
        self.assertEqual(sha((self.root/'cases.jsonl').read_bytes()),self.manifest['cases_sha256'])
        self.assertFalse(self.manifest['original_ghidra_mmi_support'])
        for c in self.cases:
            self.assertEqual(c['status'],'returned');self.assertTrue(c['return_defined']);self.assertEqual(c['faults'],[])
            for instruction in c['trace']:
                off=instruction['file_offset']
                self.assertEqual(bytes.fromhex(instruction['hex']),self.elf[off:off+4])

    def test_actual_snapshot_case_has_no_memory_patches(self):
        actual=next(c for c in self.cases if c['id']=='up-original-slot7')
        self.assertEqual(actual['input']['memory'],[])
        self.assertEqual(int(actual['input']['registers']['t0'],16),0)
        self.assertEqual(int(actual['output']['registers']['v0'],16),1)

    def test_complete_native_differential(self):
        d=json.loads((ROOT/'analysis/native-core/choice-readback-diff.json').read_text())
        self.assertEqual(d['status'],'passed');self.assertEqual(d['passed'],14)
        self.assertEqual(d['oracle_manifest_sha256'],sha((self.root/'manifest.json').read_bytes()))
        self.assertTrue(all(r['passed'] and not r['differences'] for r in d['rows']))
        self.assertTrue(all(r['compared_bytes']>100000 for r in d['rows']))
        self.assertFalse(any('v0' in e for e in d['exclusions']))


if __name__=='__main__':unittest.main()
