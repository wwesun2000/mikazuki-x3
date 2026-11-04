import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import vm_control_semantics as vm
from choice_branch import decode_operands
from opening_instructions import frame_one


def framed(raw):
    data=bytes.fromhex(raw)
    return frame_one(data,0,len(data))


class ArithmeticTests(unittest.TestCase):
    def test_signed16_wrap_and_assignment(self):
        self.assertEqual(vm.arithmetic(3,32767,1),-32768)
        self.assertEqual(vm.arithmetic(2,-32768,1),32767)
        self.assertEqual(vm.arithmetic(4,256,256),0)
        self.assertEqual(vm.arithmetic(6,100,-1),-1)

    def test_division_and_remainder_c_signs(self):
        for lhs,rhs,q,r in [(-7,3,-2,-1),(7,-3,-2,1),(-7,-3,2,-1),(7,3,2,1)]:
            self.assertEqual(vm.arithmetic(5,lhs,rhs),q)
            self.assertEqual(vm.arithmetic(13,lhs,rhs),r)
        self.assertEqual(vm.arithmetic(5,-32768,-1),-32768)

    def test_zero_divisor_is_not_python_default_or_nop(self):
        for op in (5,13):
            with self.assertRaises(ZeroDivisionError):vm.arithmetic(op,5,0)

    def test_unknown_operator_and_rng_refuse(self):
        for op in (0,1,7,15,16):
            with self.assertRaises(vm.UnknownControlState):vm.arithmetic(op,1,2)
        with self.assertRaises(vm.UnknownControlState):vm.arithmetic(14,0,4)
        calls=[]
        self.assertEqual(vm.arithmetic(14,0,4,rng_provider=lambda a,b:calls.append((a,b)) or 3),3)
        self.assertEqual(calls,[(0,4)])

    def test_comparison_direction_and_equal_aliases(self):
        expected={6:False,7:False,8:False,9:True,10:False,11:True,12:True}
        for op,value in expected.items():self.assertEqual(vm.compare(op,-1,0),value)
        for op in (6,7,10,11):self.assertTrue(vm.compare(op,-1,-1))
        with self.assertRaises(vm.UnknownControlState):vm.compare(0,1,1)

    def test_variable_reference_and_missing_value(self):
        op=decode_operands(framed('69050001030002'))
        self.assertEqual(vm.evaluate_variable(op,{1:32767,2:2}),-32767)
        with self.assertRaises(vm.UnknownControlState):vm.evaluate_variable(op,{1:5})
        assignment=decode_operands(framed('6805000106ffff'))
        self.assertEqual(vm.evaluate_variable(assignment,{}),-1)

    def test_gate_requires_known_variable_and_jumps_on_false(self):
        op=decode_operands(framed('700b017d0700010f5f70723000'))
        self.assertFalse(vm.evaluate_condition(op,{381:1})['jump_taken'])
        self.assertTrue(vm.evaluate_condition(op,{381:0})['jump_taken'])
        with self.assertRaises(vm.UnknownControlState):vm.evaluate_condition(op,{})

    def test_71_compares_signed_variable_contents(self):
        op=decode_operands(framed('710800010900020f7800'))
        result=vm.evaluate_condition(op,{1:-2,2:1})
        self.assertTrue(result['comparison_result'])
        self.assertFalse(result['jump_taken'])

    def test_operand_range_does_not_silently_truncate_input(self):
        with self.assertRaises(ValueError):vm.compare(7,65535,-1)


class LinkTests(unittest.TestCase):
    def test_forward_only_replaces_its_bitfields(self):
        old=[0xA1234567,0x89ABCDEF]
        new=vm.forward_link(old,17,1234)
        decoded=vm.unpack_links(new)
        self.assertEqual((decoded['forward_selector'],decoded['forward_label']),(17,1234))
        self.assertEqual(new[0]&0xF0003FFF,old[0]&0xF0003FFF)
        self.assertEqual(new[1]&0xFFFFFC1F,old[1]&0xFFFFFC1F)

    def test_backward_only_replaces_its_bitfields(self):
        old=[0xA1234567,0x89ABCDEF]
        new=vm.backward_link(old,31,16383)
        decoded=vm.unpack_links(new)
        self.assertEqual((decoded['backward_selector'],decoded['backward_label']),(31,16383))
        self.assertEqual(new[0]&0xFFFFC000,old[0]&0xFFFFC000)
        self.assertEqual(new[1]&0xFFFFFFE0,old[1]&0xFFFFFFE0)

    def test_visited_preserves_other_bits(self):
        self.assertEqual(vm.mark_visited([0x80000005,77]),[0x90000005,77])

    def test_template_bounds(self):
        for i in (-1,10,32):
            with self.assertRaises(ValueError):vm.option_template(i)
        self.assertEqual(len(vm.option_template(9)),22)

    def test_history_initialization_preserves_only_unspecified_high_bits(self):
        self.assertEqual(vm.initial_history_record(0xFE000000),[0x0FFFFFFF,0xFEFFFFFF])
        self.assertEqual(vm.initial_history_record(0xFFFFFFFF),[0x0FFFFFFF,0xFEFFFFFF])

    def test_media_association_only_fills_sentinel(self):
        initial=vm.initial_history_record()
        self.assertEqual(vm.associate_media_once(initial,-1),initial)
        first=vm.associate_media_once(initial,17)
        self.assertEqual((first[1]>>10)&0x3FFF,17)
        self.assertEqual(vm.associate_media_once(first,22),first)
        self.assertEqual(first[0],initial[0])

    def test_chapter_classification_and_suspend(self):
        initial=vm.initial_chapter_tracker()
        updated=vm.chapter_tracker_update(initial,'pr01_0110')
        self.assertEqual((updated['current_category'],updated['current_chapter']),(16,1))
        self.assertEqual(updated['retained_label'],'pr01_0110')
        self.assertEqual(initial['retained_label'],'')
        alternate=vm.chapter_tracker_update(updated,'rxb02_0010')
        self.assertEqual((alternate['current_category'],alternate['current_chapter']),(5,2))
        invalid=vm.chapter_tracker_update(updated,'top00_0000')
        self.assertFalse(invalid['current_valid'])
        self.assertEqual(invalid['retained_label'],'pr01_0110')
        suspended=vm.chapter_tracker_update(dict(updated,suspend_retained_updates=True),'pk01_0010')
        self.assertEqual(suspended['retained_label'],'pr01_0110')

    def test_nonnull_record_callback_is_explicit_blocker(self):
        tracker=dict(vm.initial_chapter_tracker(),callback_slot8=123)
        with self.assertRaises(vm.UnknownControlState):vm.chapter_tracker_update(tracker,'pr01_0110')


@unittest.skipUnless((ROOT/'local/assets/SCENARIO/sn4g.sn4').is_file() and
                    (ROOT/'local/extracted/SLPM_664.52').is_file(),'Local fixtures absent')
class OriginalBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
        cls.script=vm.ControlScript(cls.data)
        cls.report=vm.build_report(cls.data,cls.elf)
        cls.environment=dict(pending_text=False,readback_active=False,script_014c=False,
            manager_0740=False,recorder_0744_active=False,manager_mode_113368=True,script_0150=False)
        cls.state=dict(block_selector=15,code_relative_offset=100,
                       current_label_id=cls.script.resolve_runtime(15,'pr01_0110')['runtime_label_id'])

    def transfer(self,op=0x6A,label='pr01_0115',state=None,environment=None):
        payload=b'\x0f'+label.encode()+b'\0'
        raw=bytes((op,len(payload)))+payload
        return vm.plan_transfer(self.script,state or self.state,frame_one(raw,0,len(raw)),
                                self.environment if environment is None else environment)

    def test_runtime_label_ids_are_contiguous_and_not_disk_tags(self):
        rows=self.script.label_rows
        self.assertEqual(len(rows),8004)
        public=[r['runtime_label_id'] for r in rows if not r['internal']]
        self.assertEqual(public,list(range(6566)))
        self.assertTrue(all(r['runtime_label_id']==65535 for r in rows if r['internal']))
        self.assertNotEqual(self.script.resolve_runtime(15,'pr01_0110')['runtime_label_id'],0x6F4E)

    def test_internal_transfer_retains_page_id_and_has_no_history(self):
        plan=self.transfer(label='_pr2')
        self.assertEqual(plan['after']['current_label_id'],self.state['current_label_id'])
        self.assertEqual(plan['effects'],[])
        self.assertEqual(vm.commit_plan(plan,[]),plan['after'])

    def test_6b_has_forward_and_visited_but_no_reverse_or_stack(self):
        plan=self.transfer(0x6B)
        self.assertEqual([e['kind'] for e in plan['effects']],['forward_link_with_snapshot','mark_visited'])
        self.assertFalse(plan['pushes_return_stack'])
        self.assertEqual(plan['flag_to_0x10D868'],1)

    def test_6a_and_85_have_same_normal_effects(self):
        a,b=self.transfer(0x6A),self.transfer(0x85)
        self.assertEqual(a['after'],b['after'])
        self.assertEqual(a['effects'],b['effects'])
        self.assertEqual([e['kind'] for e in a['effects']],
                         ['forward_link_with_snapshot','mark_visited','backward_link'])

    def test_unimplemented_effects_cannot_commit(self):
        plan=self.transfer()
        with self.assertRaises(vm.UnknownControlState):vm.commit_plan(plan,[])
        self.assertEqual(vm.commit_plan(plan,[0,1,2]),plan['after'])
        with self.assertRaises(vm.UnknownControlState):vm.commit_plan(plan,[2,1,0])

    def test_runtime_or_initial_source_skips_history(self):
        for state in [dict(self.state,block_selector=32),dict(self.state,current_label_id=-1)]:
            self.assertEqual(self.transfer(state=state)['effects'],[])

    def test_pending_text_consumes_without_transfer(self):
        env=dict(self.environment,pending_text=True)
        plan=self.transfer(environment=env)
        self.assertEqual(plan['after'],self.state)
        self.assertEqual(plan['effects'][0]['function'],'0x0011a220')
        self.assertEqual(self.transfer(label='_pr2',environment=env)['effects'],[])
        self.assertEqual(self.transfer(0x85,label='_pr2',environment=env)['after'],self.state)

    def test_readback_public_transfer_skips_history(self):
        plan=self.transfer(environment=dict(self.environment,readback_active=True))
        self.assertEqual(plan['outcome'],'readback_raw_transfer_no_history')
        self.assertEqual(plan['effects'],[])

    def test_conditional_false_bypasses_handler_pending_guard(self):
        payload=bytes.fromhex('017d0700010f')+b'pr01_0115\0'
        raw=bytes((0x70,len(payload)))+payload
        row=frame_one(raw,0,len(raw))
        env=dict(self.environment,pending_text=True)
        plan=vm.plan_conditional_transfer(self.script,self.state,row,{381:0},env)
        self.assertNotEqual(plan['after'],self.state)
        self.assertTrue(plan['handler_pending_guard_bypassed'])
        self.assertNotIn('0x0011a220',[e.get('function') for e in plan['effects']])
        plan=vm.plan_conditional_transfer(self.script,self.state,row,{381:1},env)
        self.assertEqual(plan['after'],self.state)
        self.assertEqual(plan['effects'],[])

    def test_environment_must_be_known_and_special_link_retained(self):
        with self.assertRaises(vm.UnknownControlState):self.transfer(environment={})
        env=dict(self.environment,script_0150=True,script_0154_selector=13,script_0158_label=123)
        plan=self.transfer(environment=env)
        self.assertEqual([e['kind'] for e in plan['effects'][-3:]],
                         ['clear_script_0150','backward_link','forward_link_with_snapshot'])

    def test_runtime_templates_and_file_offsets_stay_distinct(self):
        row=self.script.read_at(32,8)
        self.assertEqual(row['opcode'],2)
        self.assertEqual(row['text']['decoded_cp932'],'Ａ：')
        self.assertIsNone(row['file_offset'])
        for selector in (30,31,42):
            with self.assertRaises(ValueError):self.script.read_at(selector,0)
        for offset in (22,-1):
            with self.assertRaises(ValueError):self.script.read_at(32,offset)

    def test_all_source_accesses_and_raw_evidence(self):
        scan=self.report['variable_017d']
        self.assertEqual(scan['source_scan']['framed_instructions'],135040)
        writes=[r for r in scan['all_explicit_accesses'] if r['instruction']['opcode']==0x68]
        self.assertEqual([(r['instruction']['offset'],r['operands']['rhs']) for r in writes],[(0x5B20,1)])
        for region in self.report['elf_evidence']:
            raw=b''.join(bytes.fromhex(r['raw_hex']) for r in region['instructions'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),region['raw_sha256'])
            off=region['file_offset']
            self.assertEqual(raw,self.elf[off:off+len(raw)])

    def test_wrong_build_rejected(self):
        with self.assertRaises(ValueError):vm.ControlScript(self.data[:-1]+b'\xff')

    def test_cold_constructor_is_header_entry_and_has_all_512_variables(self):
        snap=vm.cold_manager_snapshot(self.script)
        self.assertEqual(snap['variables'],{i:0 for i in range(512)})
        self.assertEqual((snap['entry']['block_selector'],snap['entry']['label']),(17,'top00_0000'))
        self.assertEqual(len(snap['history']),6566)
        self.assertEqual(snap['environment']['manager_mode_113368'],False)
        self.assertTrue(snap['script_runtime']['recording_enabled'])
        self.assertEqual(snap['script_runtime']['media_id'],-1)

    def test_normal_history_reducer_runs_core_without_discarding_records(self):
        snap=vm.cold_manager_snapshot(self.script)
        plan=self.transfer(environment=snap['environment'])
        old=self.state['current_label_id'];new=plan['after']['current_label_id']
        result=vm.execute_normal_history_plan(self.script,plan,snap['history'],snap['script_runtime'],snap['chapter_tracker'])
        self.assertTrue(vm.unpack_links(result['history'][old])['visited_bit'])
        self.assertEqual(vm.unpack_links(result['history'][old])['forward_label'],new)
        self.assertEqual(vm.unpack_links(result['history'][new])['backward_label'],old)
        self.assertEqual(result['script_runtime']['forward_snapshot_target'],16383)
        self.assertEqual(result['chapter_tracker']['retained_label'],'pr01_0110')
        self.assertEqual(snap['history'][old],vm.initial_history_record())
        self.assertIsNone(snap['script_runtime']['last_recorded_label'])

    def test_non_normal_callback_blocks_before_mutation(self):
        snap=vm.cold_manager_snapshot(self.script)
        plan=self.transfer(environment=dict(snap['environment'],script_014c=True))
        before=snap['history'].copy()
        with self.assertRaises(vm.UnknownControlState):
            vm.execute_normal_history_plan(self.script,plan,snap['history'],snap['script_runtime'],snap['chapter_tracker'])
        self.assertEqual(snap['history'],before)

    def test_repeated_visit_avoids_progress_callback_unless_force(self):
        runtime=dict(media_id=-1,recording_enabled=True,record_force=False,last_recorded_label='pr01_0110')
        tracker=dict(vm.initial_chapter_tracker(),callback_slot8=123)
        result=vm.visit_and_record(vm.initial_history_record(),'pr01_0110',runtime,tracker)
        self.assertTrue(vm.unpack_links(result['words'])['visited_bit'])
        with self.assertRaises(vm.UnknownControlState):
            vm.visit_and_record(vm.initial_history_record(),'pr01_0110',dict(runtime,record_force=True),tracker)


if __name__=='__main__':unittest.main()
