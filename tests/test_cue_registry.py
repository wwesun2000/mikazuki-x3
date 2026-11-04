import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from cue_registry import cue_hash,registry,lookup,report
from scenario_resources import ResourceIndex

class CueRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index=ResourceIndex.from_project()
    def test_hash_matches_every_original_record(self):
        records=registry(self.index)
        self.assertGreater(records['count'],1000)
        self.assertEqual([r['assignment_ordinal'] for r in records['records']],list(range(records['count'])))
    def test_ids_are_runtime_assigned_not_on_disk_trailer(self):
        records=registry(self.index)['records']
        self.assertTrue(all(r['original_trailer']==0 for r in records))
        for name in ['top0000_00','pr0000_00','pr5011m_00','pr1034_00']:
            self.assertGreater(lookup(self.index,name),0)
            row=next(r for r in records if r['name']==name)
            self.assertEqual(lookup(self.index,name),row['assignment_ordinal'])
    def test_missing_lookup_and_original_hash_examples(self):
        self.assertEqual(lookup(self.index,'missing_00'),-1)
        self.assertEqual(lookup(self.index,'pr1034_missing'),-1)
        self.assertEqual(cue_hash('pr1034_00'),185)
    def test_report_bound_to_unchanged_machine_code(self):
        result=report()
        self.assertEqual(len(result['regions']),7)
        self.assertEqual(result['samples']['pr1034_00'],lookup(self.index,'pr1034_00'))

if __name__=='__main__':unittest.main()
