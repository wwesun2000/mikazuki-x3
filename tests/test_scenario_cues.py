import copy
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from scenario_resources import ResourceIndex
from scenario_cues import CallbackScheduler, parse_program, plan_cue, UnresolvedCue, build_report, CueEndState, execute_end


class CueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = ResourceIndex.from_project(ROOT)

    def test_first_scene_actual_sound_and_file(self):
        plan = plan_cue(self.index, 'pr5011m_00')
        self.assertEqual([e['name'] for e in plan['events']], ['BGM_STOP','SE_PLAY','MOVIE_LOOP_PLAY'])
        self.assertEqual(plan['events'][1]['arguments'], [537002,80,0,0,0,0])
        self.assertEqual(plan['events'][2]['filename'], 'pr5011m.mmv')
        # Original passes zero to the movie callback; filename isn't invented as an arg.
        self.assertEqual(plan['events'][2]['arguments'], [0])
        self.assertTrue(all(e['delay_ticks'] == 0 for e in plan['events']))

    def test_cafe_negative_pan_and_stop(self):
        plan = plan_cue(self.index, 'pr1034_00')
        self.assertEqual([e['name'] for e in plan['events']], ['BGM_STOP','SE_PLAY','SE_CHANGE_PAN','SE_STOP','MOVIE_LOOP_PLAY'])
        self.assertEqual(plan['events'][1]['arguments'], [532019,15,0,0,0,0])
        self.assertEqual(plan['events'][2]['arguments'], [532019,-30,0,0])
        self.assertEqual(plan['events'][3]['arguments'], [101039,5,0])
        self.assertEqual(plan['events'][4]['filename'], 'pr1034.ipu')

    def test_transition_parameter_not_relabelled_as_delay(self):
        plan = plan_cue(self.index, 'pr0000_10')
        self.assertEqual(plan['events'][0]['arguments'], [537002,80,240,0,0,0])
        self.assertEqual(plan['events'][0]['delay_ticks'], 0)

    def test_unknown_command_and_attribute_block(self):
        with self.assertRaises(UnresolvedCue):
            parse_program(b'\x24\0\x01\0')
        with self.assertRaises(UnresolvedCue):
            parse_program(b'\x07\0\x29\0\0\0\0\0\x01\0')

    def test_truncation_missing_end_and_post_end_data_block(self):
        for data in [b'\x07', b'\x07\0\x27\0abc', b'\x0c\0\x29\0\xff', b'\x15\0', b'\x01\0\0\0']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_program(data)

    def test_original_diagnostic_strings_are_checked(self):
        report = build_report(ROOT)
        self.assertEqual(len(report['priority_plans']), 4)
        self.assertEqual(report['scheduler']['usable_capacity'], 7)
        self.assertIn('SE_PLAY', [s['name'] for s in report['diagnostic_strings']])

    def test_effect_payload_is_big_endian_inside_little_endian_cue(self):
        a=plan_cue(self.index,'pr5011m_10')['events']
        self.assertEqual([(e['name'],e['arguments']) for e in a],
                         [('SE_STOP',[537002,150,0]),('EFFECT_ON',[9,120,0,0,0]),('EFFECT_WAIT',[9])])
        b=plan_cue(self.index,'pr1011_00')['events']
        self.assertEqual(b[0]['arguments'],[9,0,0,0,0])
        self.assertEqual(b[1]['arguments'],[9])
        self.assertEqual(b[1]['name'],'EFFECT_OFF')


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = CallbackScheduler()
        self.seen = []
        self.callbacks = {1:lambda value:self.seen.append(value), 2:lambda:self.seen.append('complete')}

    def call(self, delay, value='x', completion=None):
        return dict(delay_ticks=delay, callback_address=1, arguments=[value], completion_callback=completion)

    def test_zero_delay_is_immediate(self):
        self.scheduler.schedule(self.call(0), self.callbacks)
        self.assertEqual(self.seen, ['x'])
        self.assertEqual(self.scheduler.head, self.scheduler.tail)

    def test_exact_expiry_and_completion_order(self):
        self.scheduler.schedule(self.call(3, completion=2), self.callbacks)
        self.scheduler.advance_ticks(2,self.callbacks)
        self.assertEqual(self.seen, [])
        self.scheduler.advance_ticks(1,self.callbacks)
        self.assertEqual(self.seen, ['x','complete'])

    def test_later_entry_can_expire_before_ring_head(self):
        self.scheduler.schedule(self.call(5,'first'), self.callbacks)
        self.scheduler.schedule(self.call(2,'second'), self.callbacks)
        self.scheduler.advance_ticks(2,self.callbacks)
        self.assertEqual(self.seen, ['second'])
        self.assertEqual(self.scheduler.head, 0)
        self.scheduler.advance_ticks(3,self.callbacks)
        self.assertEqual(self.seen, ['second','first'])
        self.assertEqual(self.scheduler.head, self.scheduler.tail)

    def test_capacity_and_wraparound(self):
        for x in range(7):self.scheduler.schedule(self.call(1,x),self.callbacks)
        before = copy.deepcopy(self.scheduler)
        with self.assertRaises(ValueError):self.scheduler.schedule(self.call(1,8),self.callbacks)
        self.assertEqual(self.scheduler,before)
        self.scheduler.advance_ticks(1,self.callbacks)
        self.scheduler.schedule(self.call(1,8),self.callbacks)
        self.scheduler.advance_ticks(1,self.callbacks)
        self.assertEqual(self.seen,list(range(7))+[8])

    def test_missing_callbacks_do_not_advance_clock(self):
        self.scheduler.schedule(self.call(3,completion=2),self.callbacks)
        before=copy.deepcopy(self.scheduler)
        with self.assertRaises(ValueError):self.scheduler.advance_ticks(2,{1:self.callbacks[1]})
        self.assertEqual(self.scheduler,before)

    def test_invalid_delta_and_bypass(self):
        for value in [-1,1.5,True]:
            with self.assertRaises(ValueError):self.scheduler.advance_ticks(value,self.callbacks)
        self.scheduler.schedule(self.call(65535),self.callbacks,bypass_delay=True)
        self.assertEqual(self.seen,['x'])


class EndTests(unittest.TestCase):
    def test_end_preserves_cue_sound_and_stops_unlisted(self):
        calls=[]
        callbacks={0x139550:lambda x:calls.append(('movie',x)),
                   0x10c7c0:lambda:calls.append(('record',)),
                   0x140988:lambda *a:calls.append(('bgm_stop',*a)),
                   0x140bb0:lambda:calls.append(('se_sync',)),
                   0x1b2350:lambda:[101039,532019,537002],
                   0x140540:lambda *a:calls.append(('se_stop',*a))}
        state=CueEndState(fallback_media=True,record_marker=True,
                          retained_sound_ids=[532019],current_program=0x1234)
        execute_end(state,callbacks)
        self.assertEqual(calls,[('movie',0),('record',),('bgm_stop',0,0),('se_sync',),
                                ('se_stop',101039,0,0),('se_stop',537002,0,0)])
        self.assertTrue(state.cleanup_done)
        self.assertIsNone(state.current_program)

    def test_explicit_sound_handling_suppresses_default_cleanup(self):
        state=CueEndState(bgm_handled=True,se_handled=True,current_program=7)
        execute_end(state,{})
        self.assertTrue(state.cleanup_done)

    def test_cleanup_done_prevents_second_sound_cleanup(self):
        state=CueEndState(cleanup_done=True,current_program=7)
        execute_end(state,{})
        self.assertIsNone(state.current_program)

    def test_missing_callback_blocks_before_state_changes(self):
        state=CueEndState(current_program=7)
        original=copy.deepcopy(state)
        with self.assertRaises(ValueError):execute_end(state,{})
        self.assertEqual(state,original)


class MediaBindingTests(unittest.TestCase):
    def test_static_prepared_media_and_decode_provenance(self):
        from scenario_media_binding import prepared_media
        binding=prepared_media(ResourceIndex.from_project(ROOT),'pr1034',ROOT,'pr1034_00')
        self.assertEqual(binding['original_type']['index'],6)
        self.assertEqual(binding['primary_asset']['name'],'pr1034.ipu')
        self.assertFalse(binding['preload_changes_display'])
        self.assertEqual(binding['decoded'][0]['decoded_frame_count'],1)

    def test_wrong_scene_cue_binding_rejected(self):
        from scenario_media_binding import prepared_media
        with self.assertRaises(ValueError):
            prepared_media(ResourceIndex.from_project(ROOT),'pr1034',ROOT,'pr5011m_00')

    def test_movie_sequence_remains_explicitly_unresolved(self):
        from scenario_media_binding import prepared_media
        binding=prepared_media(ResourceIndex.from_project(ROOT),'pr5011m',ROOT,'pr5011m_00')
        self.assertEqual(len(binding['decoded']),2)
        self.assertEqual(binding['native_binding_status'],'decoded-video-members-sequencing-and-playback-backend-required')

    def test_tampered_decoded_image_is_rejected(self):
        from unittest.mock import patch
        from scenario_media_binding import prepared_media
        real_read=Path.read_bytes
        def read(path):
            if path.name=='pr1034.ipu.ffmpeg.ipu.first.png':return b'changed'
            return real_read(path)
        with patch.object(Path,'read_bytes',read),self.assertRaises(ValueError):
            prepared_media(ResourceIndex.from_project(ROOT),'pr1034',ROOT,'pr1034_00')


if __name__ == '__main__':
    unittest.main()
