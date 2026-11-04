"""Validate the compact OBS-001 archive inspection, not a save-state loader."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from inspect_pcsx2_states import bounded, cpu_prefix, elf_sections, source_instruction


class Pcsx2StateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = ROOT/'analysis/observations/OBS-001/state-analysis'
        if not (cls.base/'report.json').exists():
            raise unittest.SkipTest('Local observation evidence not generated')
        cls.report = json.loads((cls.base/'report.json').read_text(encoding='utf-8'))

    def test_exact_archive_identity_and_small_source_bound_slices(self):
        for state in self.report['states']:
            raw = (ROOT/state['archive']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), state['archive_sha256'])
            path = ROOT/state['fixture']['path']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), state['fixture']['sha256'])
            fixture = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(fixture['archive_sha256'], state['archive_sha256'])
            self.assertTrue(fixture['incomplete_guest_memory'])
            self.assertEqual(fixture['elf_sha256'], self.report['source_elf_sha256'])
            for item in fixture['memory']:
                raw = bytes.fromhex(item['hex'])
                self.assertEqual(len(raw), item['size'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item['sha256'])
                self.assertLessEqual(int(item['address'], 16)+len(raw), 32*1024*1024)
        self.assertLess(self.report['exported_guest_bytes'], 64*1024)

    def test_all_game_text_and_loaded_scr_bindings(self):
        elf = (ROOT/'local/extracted/SLPM_664.52').read_bytes()
        self.assertEqual(hashlib.sha256(elf).hexdigest(), self.report['source_elf_sha256'])
        sections = elf_sections(elf)
        section = next(s for s in sections if s['name'] == '.text')
        expected = hashlib.sha256(elf[section['offset']:section['offset']+section['size']]).hexdigest()
        self.assertEqual(self.report['state_count'], 7)
        for state in self.report['states']:
            self.assertEqual(state['executable_binding']['sha256'], expected)
            self.assertTrue(state['executable_binding']['original_elf_identical'])
            self.assertEqual(len(state['all_loaded_code_bindings']), 30)
            self.assertTrue(all(x['original_code_identical'] for x in state['all_loaded_code_bindings']))
        actual = source_instruction(elf, sections, 0x10fb3c)
        self.assertEqual(actual['raw_hex'], '5083828f')
        self.assertEqual(self.report['binding']['singleton_address'], '0x00235e40')

    def test_slot_seven_is_post_operand_choice_with_three_source_targets(self):
        state = next(s for s in self.report['states'] if s['slot'] == 7)
        self.assertEqual(state['current_location']['selector'], 18)
        self.assertEqual(state['current_location']['label'], 'rx01_0461')
        self.assertEqual(state['current_location']['main_source_offset'], 0xb6393)
        self.assertEqual(state['current_location']['lexical_previous'][-1]['opcode'], 0x6c)
        self.assertEqual(state['current_location']['lexical_previous'][-1]['end_exclusive'], 0xb6393)
        self.assertEqual(state['context']['vtable'], '0x0022379c')
        self.assertEqual([(o['selector'],o['label']) for o in state['choice_state']['options']],
                         [(19,'rxb01_0410'),(18,'rx01_0462'),(19,'rxb01_0470')])
        self.assertEqual(state['choice_state']['fields']['0x00000008'], '0x00000002')
        self.assertIn('+8 is not assumed to be focus', state['choice_state']['interpretation'])

    def test_bounds_and_ambiguous_cpu_tags_are_rejected(self):
        for address, length in [(-1, 1), (0, -1), (3, 2), (1.5, 1)]:
            with self.assertRaises(ValueError):
                bounded(b'1234', address, length)
        self.assertEqual(bounded(b'1234',4,0), b'')
        with self.assertRaises(ValueError):
            cpu_prefix(bytes(1024))
        tag = b'cpuRegs'+b'\0'*25
        with self.assertRaises(ValueError):
            cpu_prefix(tag+bytes(704)+tag+bytes(704))


if __name__ == '__main__':
    unittest.main()
