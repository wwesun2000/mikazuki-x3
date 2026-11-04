import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from vm_record_scope import execute,initial_scope,build_report


class ScopeTests(unittest.TestCase):
    def fixture(self):
        return dict(current_label_id=2,history=[[0x0fffffff,0x00ffffff] for _ in range(4)],
            host=dict(script_014c=False,script_0150=False),
            script_runtime=dict(pending_edge=False,forward_snapshot_valid=True,forward_snapshot_label=1,
                forward_snapshot_selector=3,forward_snapshot_target=0),
            presentation=dict(manager=dict(plus32c=0),record_scope=initial_scope(),record_pool={'sentinel':'untouched'}))

    def test_begin_captures_prior_link_and_snapshot(self):
        state=self.fixture();state['history'][2]=[0x0fffc001,0x00ffffe3]
        after=execute(state,0x34);scope=after['presentation']['record_scope']
        self.assertEqual((scope['back_selector'],scope['back_label']),(3,1))
        self.assertTrue(scope['restore_valid'])
        self.assertEqual((scope['restore_selector'],scope['restore_label']),(3,0))
        self.assertEqual(after['history'][2][0],0x2fffc001)
        self.assertEqual(state['history'][2][0],0x0fffc001)
        self.assertEqual(after['presentation']['record_pool'],state['presentation']['record_pool'])

    def test_35_does_not_restore_and_next34_preserves_capture(self):
        state=self.fixture();state['history'][2]=[0x0fffc001,0x00ffffe3]
        begun=execute(state,0x34);ended=execute(begun,0x35)
        self.assertEqual(ended['history'],begun['history'])
        self.assertTrue(ended['host']['script_0150'])
        ended['history'][2]=[0x0fffc003,0x00ffffe4]
        next_begin=execute(ended,0x34)
        self.assertEqual(next_begin['presentation']['record_scope']['back_label'],1)
        self.assertFalse(next_begin['host']['script_0150'])

    def test_unmatched_snapshot_preserves_unused_fields(self):
        state=self.fixture();state['presentation']['record_scope'].update(restore_selector=2,restore_label=3)
        after=execute(state,0x34)['presentation']['record_scope']
        self.assertFalse(after['restore_valid'])
        self.assertEqual((after['restore_selector'],after['restore_label']),(2,3))

    def test_bound_evidence_contains_real_first_opcode(self):
        report=build_report()
        self.assertEqual(report['first_native_block']['offset'],661556)
        self.assertEqual(len(report['evidence_regions']),11)


if __name__=='__main__':unittest.main()
