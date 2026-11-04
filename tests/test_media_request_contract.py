import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from media_request_contract import descriptor_bytes, bind_descriptor, build_contract, cue_events
from scenario_resources import ResourceIndex, sha


class MediaRequestContractTests(unittest.TestCase):
    def test_descriptor_count_names_and_boundaries(self):
        names = ['my0000.ipu', '532011']
        raw = descriptor_bytes(names)
        memory = b'canary!' + raw + b'tail'
        bound = bind_descriptor(memory, 7, names)
        self.assertEqual(bytes.fromhex(bound['raw_hex']), raw)
        self.assertEqual(bound['sha256'], sha(raw))
        for address in (-1, 0, 8, len(memory)):
            with self.assertRaises(ValueError):
                bind_descriptor(memory, address, names)
        changed = bytearray(memory)
        changed[7] ^= 1
        with self.assertRaises(ValueError):
            bind_descriptor(changed, 7, names)
        changed = bytearray(memory)
        changed[10] ^= 1
        with self.assertRaises(ValueError):
            bind_descriptor(changed, 7, names)
        with self.assertRaises(ValueError):
            descriptor_bytes(['bad\0name'])

    def test_actual_snapshot_descriptor_and_raw_cues(self):
        report = json.loads((ROOT / 'analysis/native-core/media-request-slot4.json').read_text(encoding='utf-8'))
        self.assertEqual(report['token'], 'tr1143b')
        self.assertTrue(report['guest_binding']['source_group_matches'])
        self.assertEqual(report['guest_binding']['raw_hex'], report['descriptor']['raw_hex'])
        self.assertEqual(report['guest_binding']['address'], '0x01c27e11')
        self.assertEqual(report['dependencies'][0]['original_name'], 'my0000.ipu')
        self.assertFalse(report['active_request']['changes_display'])
        events = report['cues'][0]['events']
        self.assertEqual([e['command'] for e in events], ['BGM_STOP', 'SE_STOP', 'MOVIE_LOOP_PLAY', 'END'])
        self.assertEqual(events[1]['original_sound_id'], 532011)
        self.assertEqual(events[1]['arguments'], [532011, 60, 0])
        self.assertEqual(events[2]['arguments'], [0])
        self.assertIn('not an implicit NOP', events[3]['requires'])
        self.assertEqual(sha(bytes.fromhex(report['cues'][0]['raw_hex'])), report['cues'][0]['source_sha256'])

    def test_generic_other_scene_and_unknown_cue_block(self):
        result = build_contract('pr5011m')
        self.assertEqual(result['token'], 'pr5011m')
        self.assertFalse(result['active_request']['changes_display'])
        self.assertTrue(any(d['asset'].get('extension') == '.mmv' for d in result['dependencies']))
        self.assertTrue(all(c['status'] == 'parsed-source-events-not-executed' for c in result['cues']))
        index = ResourceIndex.from_project()
        cue = index.resolve(0x74, 'pr5011m_00')['selected_cue'].copy()
        cue['raw_hex'] = 'ffff0100'
        blocked = cue_events(index, cue)
        self.assertEqual(blocked['status'], 'blocked-unresolved-cue')
        self.assertNotIn('events', blocked)
        with self.assertRaises(ValueError):
            build_contract('not_an_original_scene')


if __name__ == '__main__':
    unittest.main()
