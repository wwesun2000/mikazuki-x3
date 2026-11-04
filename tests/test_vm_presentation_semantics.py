"""Executable reference contracts; no target execution or UI."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import vm_presentation_semantics as vm


def state(**changes):
    d={'object24_plus00':0,'object24_plus10':0,'object24_plus0c':2,
       'manager_plus808':0,'manager_plus814':3,'global_gp_minus7f9c':0,
       'setting1':0,'object18_plus00':0,'context_vtable':0x2239D0}
    d.update(changes)
    return d


class Models(unittest.TestCase):
    def test_57_zero_and_setting_override(self):
        for r in [vm.op57_values(0),vm.op57_values(60,True)]:
            self.assertEqual((r['channel_plus_08'],r['channel_plus_0c']),(128.0,0.0))

    def test_57_signed_conversion_and_numeric_scope(self):
        pos=vm.op57_values(60);neg=vm.op57_values(0xFFFFFFC4)
        self.assertEqual(neg['operand_signed'],-60)
        self.assertAlmostEqual(pos['channel_plus_0c'],128/60,places=6)
        self.assertEqual(neg['channel_plus_0c'],-pos['channel_plus_0c'])
        self.assertIn('not bit-exact',pos['arithmetic_status'])

    def test_57_bad_bits(self):
        for x in [-1,2**32,1.25]:
            with self.assertRaises(ValueError):vm.op57_values(x)

    def test_font_barrier_bidirectional_and_empty(self):
        self.assertFalse(vm.font_transition_pending([[],[]]))
        self.assertFalse(vm.font_transition_pending([[(128,1),(0,-1),(50,0)],[]]))
        self.assertTrue(vm.font_transition_pending([[],[(127,1)]]))
        self.assertTrue(vm.font_transition_pending([[(1,-1)],[]]))

    def test_nonfinite_does_not_silently_complete(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.font_transition_pending([[(float('nan'),1)],[]])

    def test_15_retries_opcode_until_transition_finishes(self):
        self.assertEqual(vm.op15_decision(123,[[(50,1)],[]])['set_main_cursor_relative'],123)
        result=vm.op15_decision(123,[[(128,1)],[]])
        self.assertEqual(result['handler_return'],0)
        self.assertIsNone(result['set_main_cursor_relative'])

    def test_wait_no_input_and_raw_mask(self):
        for mask,expected in [(0,False),(0x800,False),(0x100,True),(0x2000,True)]:
            r=vm.wait_context_step(state(),mask)
            self.assertEqual(r['accepted'],expected)
            self.assertEqual(r['state']['context_vtable'],0x2239F0 if expected else 0x2239D0)

    def test_mode_counter_has_priority_over_input_and_timer(self):
        s=state(object24_plus00=1,manager_plus808=1,manager_plus814=0)
        r=vm.wait_context_step(s,0x2100)
        self.assertFalse(r['accepted']);self.assertEqual(r['state']['object24_plus10'],1)
        r=vm.wait_context_step(r['state'],0)
        self.assertTrue(r['accepted']);self.assertEqual(r['state']['object24_plus10'],0)

    def test_timer_decrements_to_accept_without_input(self):
        s=state(manager_plus808=1,manager_plus814=2)
        r=vm.wait_context_step(s,0);self.assertFalse(r['accepted'])
        r=vm.wait_context_step(r['state'],0);self.assertTrue(r['accepted'])
        self.assertEqual(r['state']['manager_plus814'],0)
        self.assertEqual(s['manager_plus814'],2)

    def test_paused_timer_still_accepts_input(self):
        s=state(manager_plus808=1,global_gp_minus7f9c=1)
        r=vm.wait_context_step(s,0);self.assertFalse(r['accepted'])
        self.assertEqual(r['state']['manager_plus814'],3)
        self.assertTrue(vm.wait_context_step(s,0x100)['accepted'])

    def test_setting1_returns_zero_without_overwriting_timer(self):
        r=vm.wait_context_step(state(manager_plus808=1,setting1=1),0)
        self.assertTrue(r['accepted']);self.assertEqual(r['state']['manager_plus814'],3)

    def test_special_input_mode_requires_dependency(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.wait_context_step(state(object18_plus00=1),0)
        r=vm.wait_context_step(state(object18_plus00=1),0,lambda enabled,mask:(1,True))
        self.assertTrue(r['accepted']);self.assertEqual(r['state']['object18_plus00'],0)
        self.assertFalse(r['complete_runtime_semantics'])

    def test_line_advance_keeps_raw_metric_units(self):
        f,b=vm.line_advance({0x10:20,0x20:2},{0x04:500,0x08:100,0x18:3},16)
        self.assertEqual(b[0x04],20);self.assertEqual(b[0x08],119);self.assertEqual(f[0x20],3)

    def test_35_exact_nonzero_record_end_path(self):
        s,result=vm.op34_35({},0x35)
        self.assertEqual(s,{'manager_plus32c':0,'script_plus14c':0,'script_plus150':1,'global_gp_minus7fb4':0})
        self.assertEqual(result,0)

    def test_34_missing_record_setup_blocks(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.op34_35({},0x34)

    def test_22_dependency_preflight_runs_no_partial_prefix(self):
        seen=[]
        with self.assertRaises(vm.UnresolvedDependency):vm.execute22_callbacks({0x114A50:lambda:seen.append(1)})
        self.assertEqual(seen,[])

    def test_22_known_order_contract(self):
        seen=[]
        callbacks={a:(lambda x=a:seen.append(x)) for a,_ in vm.OP22_SEQUENCE}
        self.assertEqual(vm.execute22_callbacks(callbacks),{'manager_plus2c0':0,'handler_return':0})
        self.assertEqual(seen,[a for a,_ in vm.OP22_SEQUENCE])

    def test_22_unknown_delegate_blocks(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.scan22(bytes([0x70,1,0]),0,3)

    def test_22_bounded_truncation(self):
        with self.assertRaises(ValueError):vm.scan22(bytes([0x50,0]),0,2)
        with self.assertRaises(ValueError):vm.scan22(bytes([0x15,0x15]),0,2,max_steps=1)

    def test_refuse_source_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'source';p.write_bytes(b'keep')
            with self.assertRaises(ValueError):vm.write_report({},p,[p])
            self.assertEqual(p.read_bytes(),b'keep')


@unittest.skipUnless((ROOT/'local/assets/SCENARIO/sn4g.sn4').is_file(),'local source missing')
class ActualEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
        cls.script=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.image=vm.Image(cls.data)
        cls.report=vm.analyze(cls.image,cls.script)

    def test_script_hash_refused(self):
        with self.assertRaises(ValueError):vm.analyze(self.image,self.script+b'bad')

    def test_elf_hash_refused(self):
        with self.assertRaises(ValueError):vm.Image(self.data+b'bad')

    def test_opening_scans_reach_verified34(self):
        self.assertEqual([(s['stop_offset'],s['stop_opcode'],s['result']) for s in self.report['opcode22']['opening_scans']],[(0xA192C,0x34,1),(0xA19B0,0x34,1)])

    def test_all_raw_regions_match_source(self):
        for r in self.report['evidence_regions'].values():
            off=r['file_offset'];size=int(r['end_exclusive'],16)-int(r['start'],16)
            self.assertEqual(hashlib.sha256(self.data[off:off+size]).hexdigest(),r['raw_sha256'])

    def test_actual_defaults_and_seven_opcodes(self):
        covered={o for c in self.report['handler_classes'] for o in c['opcodes']}
        self.assertTrue(set(vm.TARGETS)<=covered)
        by_op={o:c for c in self.report['handler_classes'] for o in c['opcodes']}
        self.assertEqual(by_op[0x22]['default_context_entry'],'0x0012f8d8')
        self.assertEqual(by_op[0x15]['default_context_entry'],'0x0012bfb0')


if __name__=='__main__':unittest.main()
