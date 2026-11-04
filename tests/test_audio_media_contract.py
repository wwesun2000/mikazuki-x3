from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audio_media_contract import (ROOT, LinearRamp, MmvPlayback, change_contract,
                                 channel_registers, f32, legacy_pitch_factor,
                                 pan_index, pitch_register, play_contract, report,
                                 voice_layout, volume_factor, volume_register)
from se_bank import parse_bank


class AudioContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {r['name']: r for r in parse_bank(
            (ROOT / 'local/assets/SOUND/SSDVDAT/se.dat').read_bytes())}

    def test_percent_and_hardware_register_units(self):
        self.assertEqual(volume_factor(100), 1)
        self.assertEqual(volume_register(16000, volume_factor(80)), 12800)
        self.assertEqual(volume_register(16000, volume_factor(15)), 2400)
        self.assertEqual(volume_register(16000, 2), 16383)
        self.assertEqual(volume_register(16000, .8, .5), 6400)

    def test_pan_quantization_and_sign(self):
        self.assertEqual([pan_index(x) for x in [-100,-30,0,30,100]], [0,6,8,10,16])
        # Regression: the raw pantable stores R,L, not L,R.
        self.assertEqual(channel_registers(2400, 6, True, False), [[1950,150],[150,1500]])
        self.assertEqual(channel_registers(16000, 0, True, True), [[16000,0],[16000,0]])

    def test_532019_uses_first_stream_twice_and_keeps_delay(self):
        r = play_contract(self.rows['532019'], [532019,15,0,-30,0,0], stereo_output=True)
        self.assertEqual(r['source_streams'], [0,0])
        self.assertEqual(r['key_on_update_numbers'], [1,3])
        self.assertEqual(r['relative_start_ticks'], [0,2])
        self.assertFalse(r['paired_start'])
        self.assertEqual(self.rows['532019']['stored_stream_count'], 2)

    def test_loop_duplicate_does_not_restart_or_change_parameters(self):
        r = play_contract(self.rows['537002'], [537002,80,0,0,12,1], stereo_output=True,
                          active_loop_ids=[537002])
        self.assertEqual(r['action'], 'no-op-existing-loop')
        self.assertFalse(r['restart'])
        self.assertFalse(r['alter_existing_parameters'])
        self.assertEqual(r['completion_wait_ticks'], 0)

    def test_play_pitch_argument_is_not_consumed(self):
        a = play_contract(self.rows['537002'], [537002,80,240,0,1200,1], stereo_output=True)
        self.assertEqual(a['pitch_register'], 2048)
        self.assertFalse(a['consumed_raw_pitch'])
        self.assertEqual(a['completion_wait_ticks'], 241)
        self.assertEqual(a['volume_initial_factor'], 0)

    def test_legacy_pitch_is_not_equal_tempered_cents(self):
        self.assertEqual(legacy_pitch_factor(100), f32(1.0833))
        self.assertEqual(legacy_pitch_factor(-100), f32(.91667))
        self.assertEqual(legacy_pitch_factor(1200), 2)
        self.assertEqual(legacy_pitch_factor(-1200), .5)
        self.assertEqual(pitch_register(2048, legacy_pitch_factor(1200)), 4095)
        self.assertEqual(pitch_register(2048, legacy_pitch_factor(-1200)), 1024)

    def test_ramp_stop_and_parameter_changes(self):
        r = LinearRamp.begin(1,0,4)
        self.assertEqual([r.tick() for _ in range(5)], [.75,.5,.25,0,0])
        stop = change_contract('SE_STOP',[101039,5,1],1)
        self.assertEqual(stop['completion_wait_ticks'],6)
        self.assertTrue(stop['key_off_at_zero'])
        self.assertTrue(stop['remove_active_loop_bookkeeping_immediately'])
        self.assertEqual(change_contract('SE_CHANGE_PAN',[532019,-30,0,0],0)['target'],f32(f32(-30)*f32(.01)))

    def test_zero_fade_and_prequeued_suppression(self):
        following = [dict(command='SE_CHANGE_VOLUME',args=[537002,0,8,0])]
        r = play_contract(self.rows['537002'],[537002,80,0,0,0,0],stereo_output=True,
                          following_queue=following)
        self.assertEqual(r['volume_initial_factor'],0)
        self.assertEqual(LinearRamp.begin(.8,0,0).current,0)

    def test_output_mono_and_source_stereo_are_separate(self):
        self.assertEqual(channel_registers(2400,6,False,False),[[1920,1920],[1920,1920]])
        row = dict(self.rows['532019'], raw_playback_flags=0x90)
        self.assertEqual(voice_layout(row)['source_streams'],[0,1])
        self.assertEqual(voice_layout(row)['raw_delay_ticks'],[0,0])
        with self.assertRaises(ValueError):
            voice_layout(dict(row,stored_stream_count=1))

    def test_original_iop_and_executable_identity(self):
        r = report()
        self.assertEqual(r['examples']['532019']['target_output_registers'],[[1950,150],[150,1500]])
        self.assertEqual(r['examples']['537002']['target_output_registers'],[[9600,800],[800,9600]])
        self.assertEqual(len(r['pan_table']),17)


class MmvContractTests(unittest.TestCase):
    def test_intro_once_tail_forever(self):
        p = MmvPlayback(True)
        self.assertEqual([p.member]+[p.end_member() for _ in range(4)],[0,1,1,1,1])
        self.assertEqual(p.tail_iterations,3)

    def test_nonloop_completes_after_second_member(self):
        p = MmvPlayback(False)
        self.assertEqual(p.end_member(),1)
        self.assertIsNone(p.end_member())
        self.assertEqual(p.state,'completed-awaiting-drain')
        with self.assertRaises(ValueError):
            p.end_member()

    def test_explicit_stop_does_not_restart(self):
        p = MmvPlayback(True)
        p.end_member()
        p.stop()
        with self.assertRaises(ValueError):
            p.end_member()


if __name__ == '__main__':
    unittest.main()
