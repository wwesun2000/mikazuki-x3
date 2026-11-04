"""Bounded static/reference tests. No native code or graphics backend runs."""
from dataclasses import asdict
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import vm_scalar_semantics as vm


def native(command,args):
    payload=command.to_bytes(4,'big')+bytes([len(args)])+b''.join((x&0xffffffff).to_bytes(4,'big') for x in args)
    return b'\x6f'+bytes([len(payload)])+payload


class ScalarTests(unittest.TestCase):
    def test_signed_big_endian_operand(self):
        row=vm.parse_scalar(b'\x50\xff\xff\xff\xfe',0)
        self.assertEqual(row['value'],-2)
        self.assertEqual(row['raw_u32'],0xfffffffe)

    def test6f_header_argc_and_words(self):
        row=vm.parse_scalar(native(0x67,[0,0,60,0,0,0]),0)
        self.assertEqual((row['command_id'],row['argc']),(0x67,6))
        self.assertEqual(row['arguments_s32'],[0,0,60,0,0,0])
        self.assertTrue(row['declared_matches_payload'])

    def test6f_declared_length_does_not_override_argument_reads(self):
        raw=bytearray(native(0x65,[30]));raw[1]=1
        row=vm.parse_scalar(raw,0)
        self.assertFalse(row['declared_matches_payload'])
        self.assertEqual(row['end_exclusive'],len(raw))

    def test_truncated_native_and_scalar_rejected(self):
        for raw in (b'',b'\x40',b'\x50\0',b'\x6f\0\0',native(0x65,[30])[:-1]):
            with self.assertRaises(ValueError):vm.parse_scalar(raw,0)

    def test17_busy_rewinds_and_setting18_bypasses(self):
        state=vm.ScalarState(manager_plus2d0=1)
        r=vm.step(b'\x17',state,{})
        self.assertEqual((r['handler_return'],r['state'].cursor),(1,0))
        r=vm.step(b'\x17',state,{},setting18=True)
        self.assertEqual((r['handler_return'],r['state'].cursor),(0,1))

    def test1e_no_setting18_bypass(self):
        r=vm.step(b'\x1e',vm.ScalarState(),{0x138FB0:lambda:False},setting18=True)
        self.assertTrue(r['retry'])
        with self.assertRaises(vm.UnresolvedDependency):vm.step(b'\x1e',vm.ScalarState(),{})

    def test_aggregate_ready_requires_all_sources(self):
        self.assertTrue(vm.aggregate_ready(0,0,0,0,1))
        for key in range(4):
            values=[0,0,0,0];values[key]=1
            self.assertFalse(vm.aggregate_ready(*values,1))
        with self.assertRaises(vm.UnresolvedDependency):vm.aggregate_ready(0,0,0,0,0)
        self.assertFalse(vm.aggregate_ready(0,0,0,0,0,2))
        self.assertTrue(vm.aggregate_ready(0,0,0,0,0,4))

    def test6f_busy_defers_before_reading_truncated_operand(self):
        state=vm.ScalarState(manager_plus2d0=1)
        r=vm.step(b'\x6f',state,{0x135760:lambda:True})
        self.assertTrue(r['retry']);self.assertIsNone(r['operand'])

    def test6f_start_and_setting18_skip_are_distinct(self):
        called=[]
        raw=native(0x65,[30])
        callbacks={0x135760:lambda:True,0x18ED58:lambda args:called.append(args) or 'task1'}
        r=vm.step(raw,vm.ScalarState(),callbacks)
        self.assertEqual(called,[(30,)])
        self.assertEqual((r['state'].manager_plus2d0,r['state'].manager_plus2d4),(1,'task1'))
        skip=vm.step(raw,vm.ScalarState(),{0x135760:lambda:True},setting18=True)
        self.assertEqual(skip['state'].manager_plus2d0,0)
        self.assertEqual(skip['state'].cursor,len(raw))

    def test6f_unknown_command_is_not_nop(self):
        with self.assertRaises(vm.UnresolvedDependency):
            vm.step(native(999,[1]),vm.ScalarState(),{0x135760:lambda:True})

    def test40_resets_counter_but_not_ready_flag(self):
        r=vm.step(b'\x40\x05',vm.ScalarState(manager_plus294=10,manager_plus298=1),{})
        self.assertEqual((r['state'].manager_plus29c,r['state'].manager_plus294,r['state'].manager_plus298),(5,0,1))

    def test_text_cadence_and_full_width_space_exception(self):
        state=vm.ScalarState(manager_plus29c=2)
        state=vm.text_cadence_tick(state)
        self.assertEqual(state.manager_plus298,0)
        self.assertEqual(vm.text_unit_gate(state,0x889f)['rewind_bytes'],2)
        self.assertTrue(vm.text_unit_gate(state,0x8140)['accepted'])
        state=vm.text_cadence_tick(state)
        self.assertEqual((state.manager_plus294,state.manager_plus298),(0,1))
        state=vm.text_unit_gate(state,0x889f,consumed=True)['state']
        self.assertEqual(state.manager_plus298,0)

    def test46_main_addition_then_virtual_alignment(self):
        seen=[]
        state=vm.ScalarState(font_main_plus04=20,font_main_plus08=30)
        r=vm.step(b'\x46\x05',state,{0x169E68:lambda s:seen.append(s.font_main_plus04) or [27,30,8,3]})
        self.assertEqual(seen,[25])
        self.assertEqual((r['state'].font_secondary_plus04,r['state'].font_secondary_plus08,r['state'].font_plus24),(27,25,11))
        with self.assertRaises(vm.UnresolvedDependency):vm.step(b'\x46\x05',state,{})

    def test50_zero_still_yields_without_rewind(self):
        r=vm.step(b'\x50\0\0\0\0',vm.ScalarState(),{})
        self.assertEqual(r['handler_return'],1);self.assertFalse(r['retry'])
        self.assertEqual(r['state'].cursor,5)

    def test_timer_positive_clamp_negative_and_cancel(self):
        self.assertEqual(vm.timer_tick(vm.ScalarState(manager_plus2ec=1)).manager_plus2ec,0)
        self.assertEqual(vm.timer_tick(vm.ScalarState(manager_plus2ec=-1)).manager_plus2ec,-1)
        state=vm.ScalarState(manager_plus2ec=10,manager_plus2e8=1)
        with self.assertRaises(vm.UnresolvedDependency):vm.timer_tick(state)
        self.assertEqual(vm.timer_tick(state,0x2100).manager_plus2ec,0)

    def test2f_defaults_and5c_existing_nodes_are_different(self):
        state=vm.ScalarState()
        for ch in state.font_channels:ch['nodes']=[{'plus04':64.0,'plus08':1.0}]
        r=vm.step(b'\x2f',state,{})
        self.assertEqual(r['state'].font_channels[0]['plus08'],128.0)
        self.assertEqual(r['state'].font_channels[0]['nodes'][0]['plus04'],64.0)
        r=vm.step(b'\x5c\0\0\0\x20',state,{})
        ch=r['state'].font_channels[0]
        self.assertEqual(ch['plus08'],0.0)
        self.assertEqual(ch['nodes'][0],{'plus04':128.0,'plus08':-4.0})
        self.assertEqual(vm.glyph_tick(ch['nodes'][0])['plus04'],124.0)

    def test_glyph_clamps_and_stops(self):
        self.assertEqual(vm.glyph_tick({'plus04':1.0,'plus08':-4.0}),{'plus04':0.0,'plus08':0.0})
        self.assertEqual(vm.glyph_tick({'plus04':127.0,'plus08':4.0}),{'plus04':128.0,'plus08':0.0})

    def test67_three_phases_and_manager_release(self):
        task=vm.make_effect_task(0x67,[0,0,60,0,0,0],'task')
        manager=vm.ScalarState(manager_plus2d0=1,manager_plus2d4='task',manager_plus2d8=1,manager_plus2dc=1)
        phases=[];steps=0
        while not task['finished']:
            r=vm.effect_tick(task,manager,pause_predicate=False)
            task,manager=r['task'],r['state'];phases.append(task['data']['plus00']);steps+=1
            self.assertLess(steps,100)
        self.assertEqual(steps,62);self.assertEqual(phases[:2],[1,2])
        self.assertEqual((manager.manager_plus2d0,manager.manager_plus2d8,manager.manager_plus2dc),(0,0,0))
        self.assertEqual(manager.manager_plus2d4,'task')
        self.assertEqual(vm.step(b'\x17',manager,{})['handler_return'],0)

    def test65_finishes_at_less_than_one_threshold(self):
        task=vm.make_effect_task(0x65,[30],'task');state=vm.ScalarState(manager_plus2d0=1)
        for _ in range(30):
            r=vm.effect_tick(task,state,pause_predicate=False);task,state=r['task'],r['state']
        self.assertTrue(task['finished']);self.assertEqual(task['data']['plus00'],0.0)

    def test_paused_task_does_not_change_arithmetic(self):
        task=vm.make_effect_task(0x67,[10,20,30,0,0,0],'task')
        r=vm.effect_tick(task,vm.ScalarState(),pause_predicate=True)
        self.assertEqual(r['task'],task)
        self.assertEqual(r['required_actions'],['17A198(task)'])

    def test65_divide_by_zero_is_explicitly_blocked(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.make_effect_task(0x65,[0],'task')

    def test67_fog_is_not_alpha_and65_is_textured(self):
        c=vm.effect_draw_contract(vm.make_effect_task(0x67,[0,0,30,0,0,0],'task'))
        self.assertEqual(c['vertex_rgba'],[128]*4)
        self.assertEqual(c['fog_integer'],255)
        self.assertEqual(c['vertex_fog_packed_word'],4080)
        self.assertEqual(c['fogcolor_rgb'],[0,0,0])
        c=vm.effect_draw_contract(vm.make_effect_task(0x65,[30],'task'))
        self.assertEqual(c['vertex_rgba'],[128]*4)
        self.assertIn('framebuffer',c['texture_setup'])


@unittest.skipUnless((ROOT/'local/extracted/SLPM_664.52').is_file(),'Local source absent')
class SourceEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
        cls.script=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.report=vm.analyze(vm.Image(cls.elf),cls.script)

    def test_changed_source_refused(self):
        with self.assertRaises(ValueError):vm.Image(self.elf+b'x')
        with self.assertRaises(ValueError):vm.analyze(vm.Image(self.elf),self.script+b'x')

    def test_raw_evidence_ranges_bind_original(self):
        for r in self.report['evidence_regions'].values():
            size=int(r['end_exclusive'],16)-int(r['start'],16);off=r['file_offset']
            self.assertEqual(hashlib.sha256(self.elf[off:off+size]).hexdigest(),r['raw_sha256'])

    def test_samples_raw_and_opening_command(self):
        for samples in self.report['samples'].values():
            for row in samples:
                self.assertEqual(self.script[row['offset']:row['end_exclusive']].hex(),row['raw_hex'])
        first=self.report['samples'][vm.hx(0x6f)][0]
        self.assertEqual(first['offset'],0xA190C)
        self.assertEqual(first['arguments_s32'],[0,0,60,0,0,0])
        self.assertEqual(first['command_id'],0x67)


if __name__=='__main__':unittest.main()
