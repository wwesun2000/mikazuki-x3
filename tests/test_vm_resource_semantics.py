"""Resource contract tests; no loader, emulator or UI is invoked."""
from dataclasses import asdict
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import vm_resource_semantics as vm


def instruction(op,name=b'cue',declared=None):
    n=len(name)+1 if declared is None else declared
    return bytes([op,n])+name+b'\0'


class ContractTests(unittest.TestCase):
    def test_short_header_and_literal_name(self):
        r=vm.parse_operand(instruction(0x74,b'pr5011m_00'),0)
        self.assertEqual(r['token_ascii'],'pr5011m_00')
        self.assertTrue(r['declared_matches_cstring'])

    def test_extended_header(self):
        data=b'\x73\0\0\x04cue\0'
        r=vm.parse_operand(data,0)
        self.assertEqual((r['header_bytes'],r['end_exclusive']),(3,len(data)))

    def test_header_is_not_cursor_length(self):
        r=vm.parse_operand(instruction(0x73,b'abcdef',1),0)
        self.assertEqual(r['actual_cstring_bytes'],7)
        self.assertFalse(r['declared_matches_cstring'])
        self.assertEqual(r['end_exclusive'],9)

    def test_raw_non_ascii_name_is_preserved(self):
        r=vm.parse_operand(instruction(0x72,b'\x81\x40'),0)
        self.assertEqual(r['token_hex'],'8140');self.assertIsNone(r['token_ascii'])

    def test_truncation_and_opcode_rejected(self):
        for d in [b'',b'\x73',b'\x73\0\0',b'\x74\x03abc',b'\x01\x01\0']:
            with self.assertRaises(ValueError):vm.parse_operand(d,0)

    def test_token_bound_not_silent_truncation(self):
        with self.assertRaises(ValueError):vm.parse_operand(instruction(0x73,b'abc'),0,max_token_bytes=3)

    def test_missing_backend_blocks(self):
        with self.assertRaises(vm.UnresolvedDependency):vm.step(instruction(0x72),vm.ResourceState(),{})

    def test72_not_ready_retries_without_request(self):
        r=vm.step(instruction(0x72),vm.ResourceState(),{0x137350:lambda:False})
        self.assertEqual(r['handler_return'],1);self.assertEqual(r['state'].cursor,0)
        self.assertEqual(len(r['events']),1)

    def test72_accepts_started_request_without_completion(self):
        called=[]
        callbacks={0x137350:lambda:True,0x11E310:lambda name,mode:called.append((name,mode)) or 12}
        s=vm.ResourceState(provider_plus10=5)
        r=vm.step(instruction(0x72),s,callbacks)
        self.assertEqual(called,[(b'cue',1)])
        self.assertTrue(r['accepted']);self.assertEqual(r['state'].provider_plus08,2)
        self.assertEqual(r['state'].provider_plus10,5)
        self.assertEqual(s.provider_plus08,0)

    def test73_requires_second_dispatch_to_complete(self):
        callbacks={0x137350:lambda:True,0x11E310:lambda name,mode:12,
                   0x135618:lambda:True,0x135660:lambda:None}
        r=vm.step(instruction(0x73),vm.ResourceState(),callbacks)
        self.assertFalse(r['accepted']);self.assertEqual(r['state'].provider_plus08,1)
        self.assertEqual(r['state'].manager_plus71c,1)
        r=vm.step(instruction(0x73),r['state'],callbacks)
        self.assertTrue(r['accepted']);self.assertEqual(r['state'].provider_plus10,12)
        self.assertEqual(r['state'].provider_plus08,0)

    def test73_phase2_starts_mode0(self):
        modes=[]
        callbacks={0x137350:lambda:True,0x11E310:lambda name,mode:modes.append(mode) or 7}
        r=vm.step(instruction(0x73),vm.ResourceState(provider_plus08=2),callbacks)
        self.assertEqual(modes,[0]);self.assertEqual(r['state'].provider_plus08,1)

    def test73_pending_does_not_restart_request(self):
        r=vm.step(instruction(0x73),vm.ResourceState(provider_plus08=1),{0x135618:lambda:False})
        self.assertFalse(r['accepted']);self.assertEqual(r['events'][0]['address'],'0x00135618')

    def test_unknown_provider_phase_does_not_succeed(self):
        r=vm.step(instruction(0x73),vm.ResourceState(provider_plus08=99),{})
        self.assertFalse(r['accepted']);self.assertEqual(r['events'],[])

    def test74_found_activates_then_records_index(self):
        order=[]
        callbacks={0x101CA8:lambda group,name:object(),
            0x138E10:lambda cue,name:order.append('activate'),
            0x101928:lambda name:order.append('index') or 42}
        r=vm.step(instruction(0x74),vm.ResourceState(),callbacks)
        self.assertEqual(order,['activate','index']);self.assertEqual(r['state'].script_plus_e0,42)
        self.assertEqual((r['state'].manager_plus718,r['state'].manager_plus720),(1,1))

    def test74_missing_fallback_finishes_but_still_retries(self):
        callbacks={0x101CA8:lambda group,name:None,0x101DC0:lambda:b'package',
            0x135618:lambda:True,0x135660:lambda:None}
        s=vm.ResourceState(provider_plus08=1,provider_plus0c=7,manager_plus720=1)
        r=vm.step(instruction(0x74),s,callbacks)
        self.assertFalse(r['accepted']);self.assertEqual(r['state'].cursor,0)
        self.assertEqual(r['state'].provider_plus10,7)
        self.assertEqual((r['state'].manager_plus718,r['state'].manager_plus720),(0,2))
        self.assertEqual(r['state'].manager_plus71c,0) # calls helper, not73 default slot

    def test74_full_missing_to_lookup_contract(self):
        activated=[]
        callbacks={0x101CA8:lambda group,name:123 if group==7 else None,
            0x101DC0:lambda:b'parent',0x137350:lambda:True,
            0x11E310:lambda name,mode:7,0x135618:lambda:True,0x135660:lambda:None,
            0x138E10:lambda cue,name:activated.append((cue,name)),0x101928:lambda name:4}
        s=vm.ResourceState()
        returns=[]
        for _ in range(3):
            r=vm.step(instruction(0x74),s,callbacks);s=r['state'];returns.append(r['handler_return'])
        self.assertEqual(returns,[1,1,0]);self.assertEqual(activated,[(123,b'cue')])
        self.assertEqual((s.manager_plus720,s.script_plus_e0),(3,4))

    def test_backend_return_contracts_are_checked(self):
        with self.assertRaises(ValueError):vm.step(instruction(0x72),vm.ResourceState(),{0x137350:lambda:77})
        with self.assertRaises(ValueError):vm.step(instruction(0x72),vm.ResourceState(),{0x137350:lambda:True,0x11E310:lambda n,m:None})


class ChoiceContractTests(unittest.TestCase):
    def setUp(self):
        self.data=b'\x7f\x08\x01\x11one\0\x11x\0'
        self.record=vm.parse_graphical_choice(self.data,0)
        self.position=vm.ScriptPosition(17,123,0)
        # Deliberate model fixtures. These callbacks do not load original UI.
        self.callbacks={a:lambda *args:None for a in vm.DEPENDENCIES}
        self.callbacks.update({0x100EC8:lambda i:4,0x117560:lambda:False,
            0x16AB38:lambda:40,0x16AB60:lambda:60,0x16A698:lambda:3,0x16A668:lambda:4,
            0x10D7D0:lambda i:vm.ScriptPosition(32+i,123,0),
            0x10D868:lambda old,selector,label,flag:vm.ScriptPosition(selector,456,1000),
            0x16BA10:lambda:False})
        self.operation={'kind':'choice_setup','mode':1,'option_count':2,'extra_byte_count':0,
            'extra_hex':'','options':[{'raw_flag':0,'block_selector':15,'label':'a'},
                {'raw_flag':0,'block_selector':13,'label':'b'}]}
        self.post=vm.ScriptPosition(15,123,456)

    def test7f_parser_keeps_selector_and_fallback(self):
        self.assertEqual(self.record['options'][0]['label_ascii'],'one')
        self.assertEqual(self.record['fallback']['label_ascii'],'x')
        self.assertEqual(self.record['end_exclusive'],len(self.data))
        self.assertFalse(self.record['declared_matches_payload'])

    def test7f_truncations_rejected(self):
        for n in range(len(self.data)):
            with self.assertRaises(ValueError):vm.parse_graphical_choice(self.data[:n],0)

    def test7f_begin_changes_context_and_saves_after_operand(self):
        r=vm.graphical_choice_begin(self.record,self.position,'default15',0,self.callbacks)
        self.assertEqual(r['handler_return'],1)
        self.assertEqual(r['choice']['saved_position']['cursor'],len(self.data))
        self.assertEqual((r['manager_plus294'],r['manager_plus29c']),(0,0))
        addresses=[e['address'] for e in r['events']]
        self.assertLess(addresses.index('0x001114f0'),addresses.index('0x00135bd8'))
        self.assertEqual(self.position.cursor,0)

    def test7f_pending_does_not_restore_or_jump(self):
        r=vm.graphical_choice_begin(self.record,self.position,'default15',0,self.callbacks)
        pending=vm.graphical_choice_poll(r['choice'],r['position'],{})
        self.assertFalse(pending['completed']);self.assertEqual(pending['events'],[])

    def test7f_normal_and_fallback_have_different_jump_flags(self):
        for index,expected_flag in [(0,0),(-1,1)]:
            with self.subTest(index=index):
                r=vm.graphical_choice_begin(self.record,self.position,'default15',0,self.callbacks)
                r['choice'].update(done_plus00=1,selected_plus04=index)
                actual=[]
                self.callbacks[0x10D868]=lambda old,s,l,f:actual.append((old,s,l,f)) or vm.ScriptPosition(s,456,1000)
                done=vm.graphical_choice_poll(r['choice'],r['position'],self.callbacks)
                self.assertEqual(actual[0][3],expected_flag)
                self.assertEqual(actual[0][0].cursor,len(self.data))
                self.assertEqual(done['choice']['active_plus50'],0)
                self.assertEqual(done['context'],'default15')
                self.assertEqual(done['context_return'],0)

    def test7f_special_path_appends_fallback_even_when_all_filtered(self):
        self.callbacks[0x14BCC0]=lambda i:False
        self.callbacks[0x115E58]=lambda options:0
        actual=[]
        self.callbacks[0x10D868]=lambda old,s,l,f:actual.append((l,f)) or vm.ScriptPosition(s,1,1)
        r=vm.graphical_choice_begin(self.record,self.position,'default15',1,self.callbacks)
        self.assertEqual(actual,[(b'x',0)])
        self.assertEqual(len(r['filtered_options']),1)
        self.assertEqual(r['handler_return'],0);self.assertIsNone(r['choice'])

    def test7f_missing_ui_dependency_blocks(self):
        del self.callbacks[0x135BD8]
        with self.assertRaises(vm.UnresolvedDependency):
            vm.graphical_choice_begin(self.record,self.position,'default15',0,self.callbacks)

    def test6c_setup_saves_original_and_enters_template(self):
        r=vm.choice6c_setup(self.operation,self.post,'default15',self.callbacks)
        self.assertEqual(r['choice']['saved_position'],asdict(self.post))
        self.assertEqual(r['position'].selector,32)
        self.assertEqual(r['handler_return'],0)
        marks=[e for e in r['events'] if e['address']=='0x0010eca0']
        self.assertEqual(marks[0]['arguments'],[123,1,0])

    def test6c_nonordinary_paths_are_explicitly_blocked(self):
        for override in [{'manager_mode':True},{'control_plus10':1},{'manager_plus808':1}]:
            with self.assertRaises(vm.UnresolvedDependency):
                vm.choice6c_setup(self.operation,self.post,'default15',self.callbacks,**override)
        self.operation['mode']=2
        with self.assertRaises(vm.UnresolvedDependency):
            vm.choice6c_setup(self.operation,self.post,'default15',self.callbacks)

    def prepared(self):
        begin=vm.choice6c_setup(self.operation,self.post,'default15',self.callbacks)
        render=dict(x=40,y=60,main_start=0,main_end=3,secondary_start=0,secondary_end=-1)
        ready=vm.choice6c_preview_ready(begin['choice'],[render,render],self.callbacks)
        return ready

    def test6c_preview_must_be_complete_then_restores_original(self):
        begin=vm.choice6c_setup(self.operation,self.post,'default15',self.callbacks)
        with self.assertRaises(ValueError):vm.choice6c_preview_ready(begin['choice'],[],self.callbacks)
        ready=self.prepared()
        self.assertEqual(ready['position'],self.post)
        self.assertEqual(ready['choice']['phase'],'interactive')

    def test6c_unconfirmed_input_cannot_commit(self):
        ready=self.prepared()
        with self.assertRaises(vm.UnresolvedDependency):
            vm.choice6c_commit(ready['choice'],ready['position'],0,self.callbacks)

    def test6c_commit_waits_font_transition(self):
        ready=self.prepared();ready['choice']['phase']='confirming'
        self.callbacks[0x16BA10]=lambda:True
        r=vm.choice6c_commit(ready['choice'],ready['position'],0,self.callbacks)
        self.assertFalse(r['committed'])
        self.assertEqual(len(r['events']),1)

    def test6c_commit_sees_original_selector_and_keeps_history_gate(self):
        ready=self.prepared();ready['choice']['phase']='confirming'
        observed=[]
        self.callbacks[0x10D868]=lambda old,s,l,f:observed.append((old,s,l,f)) or vm.ScriptPosition(s,222,500)
        r=vm.choice6c_commit(ready['choice'],ready['position'],1,self.callbacks)
        self.assertEqual(observed,[(self.post,13,b'b',0)])
        self.assertTrue(r['ordinary_history_gate'])
        self.assertEqual(r['manager_plus28_object_plus14'],1)
        addresses=[e['address'] for e in r['events']]
        self.assertLess(addresses.index('0x001114f0'),addresses.index('0x0010d868'))

    def test6c_runtime_template_is_not_a_valid_commit_checkpoint(self):
        ready=self.prepared();ready['choice']['phase']='confirming'
        with self.assertRaises(ValueError):
            vm.choice6c_commit(ready['choice'],vm.ScriptPosition(32,123,0),0,self.callbacks)


@unittest.skipUnless((ROOT/'local/extracted/SLPM_664.52').is_file(),'Local source absent')
class OriginalEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
        cls.script=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.image=vm.Image(cls.elf)
        cls.report=vm.analyze(cls.image,cls.script)

    def test_source_identity_rejected(self):
        with self.assertRaises(ValueError):vm.Image(self.elf+b'bad')
        with self.assertRaises(ValueError):vm.analyze(self.image,self.script+b'bad')

    def test_opening_literal_names(self):
        self.assertEqual([s['token_ascii'] for s in self.report['script_samples']],
            ['pr0000','pr0000_00','pr0000_10','pr5011m','pr1011','pr5011m_00'])

    def test_samples_match_original_bytes(self):
        for r in self.report['script_samples']:
            raw=self.script[r['offset']:r['end_exclusive']]
            self.assertEqual(raw.hex(),r['raw_hex'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),r['raw_sha256'])

    def test_instruction_ranges_match_original_bytes(self):
        for r in self.report['evidence_regions'].values():
            off=r['file_offset'];size=int(r['end_exclusive'],16)-int(r['start'],16)
            self.assertEqual(hashlib.sha256(self.elf[off:off+size]).hexdigest(),r['raw_sha256'])

    def test_contexts_retained_without_collapsing_defaults(self):
        for c in self.report['handler_classes']:self.assertEqual(len(c['all_context_slots']),25)

    def test7f_exact_real_five_targets(self):
        sample=self.report['graphical_choice_sample']
        self.assertEqual(sample['option_count'],5)
        self.assertEqual([x['label_ascii'] for x in sample['options']],
            ['top00_1200','top00_1300','top00_1400','top00_1500','top00_1600'])
        self.assertEqual(sample['fallback']['label_ascii'],'top00_1200')
        self.assertTrue(sample['declared_matches_payload'])
        self.assertTrue(all(x['block_selector']==17 for x in sample['options']))

    def test6c_known_operand_contract(self):
        op=self.report['text_choice_sample']['operands']
        self.assertEqual((op['mode'],op['option_count'],op['extra_byte_count']),(1,2,0))
        self.assertEqual([o['raw_flag'] for o in op['options']],[0,0])


if __name__=='__main__':unittest.main()
