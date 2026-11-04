import copy
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from scenario import parse_link
from scenario_resources import ResourceIndex, parse_scene_pack, parse_mmv, lookup_se, build_report, normalize_single_frame_ipu, extract_mmv_member


class SceneResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = ResourceIndex.from_project(ROOT)
        cls.spk = (ROOT / 'local/assets/SCENARIO/sn4g.spk').read_bytes()
        block = parse_link(cls.spk)[14]
        cls.pack = cls.spk[block['offset']:block['offset'] + block['size']]
        cls.mmv = (ROOT / 'local/assets/GRA/PR/pr5011m.mmv').read_bytes()
        cls.se = (ROOT / 'local/assets/SOUND/SSDVDAT/se.dat').read_bytes()

    def test_all_real_scene_pack_regions_are_consistent(self):
        self.assertEqual(len(self.index.blocks), 29)
        self.assertEqual(self.index.blocks[14]['scene_count'], 119)
        self.assertGreater(sum(x['scene_count'] for x in self.index.blocks), 4000)

    def test_scene_dependency_is_not_a_filename_guess(self):
        result = self.index.resolve(0x73, 'pr1011')
        self.assertEqual([d['name'] for d in result['scene']['dependencies']], ['599012', 'my0000.ipu'])
        self.assertEqual(result['spk_block'], 14)

    def test_cue_resolves_parent_and_raw_program(self):
        result = self.index.resolve(0x74, 'pr5011m_00')
        self.assertEqual(result['scene']['name'], 'pr5011m')
        self.assertEqual(result['selected_cue']['program_offset'], 0x2823 + 0x3d)
        self.assertEqual(result['selected_cue']['program_end_upper_bound'], 0x2823 + 0x79)
        self.assertEqual(len(result['selected_cue']['raw_hex']), 60 * 2)

    def test_cross_pack_reference_uses_exact_index(self):
        result = self.index.resolve(0x72, 'pk1042')
        self.assertEqual(result['spk_block'], 12)
        self.assertIn('pr1042.ipu', [x['name'] for x in result['assets']])
        with self.assertRaises(ValueError):
            self.index.resolve(0x72, 'pk1042', block_index=14)

    def test_unknown_and_wrong_opcode_are_rejected(self):
        for opcode, token in [(0x72, 'nonexistent'), (0x74, 'pr5011m'), (0x73, 'pr5011m_00'), (0x71, 'pr5011m')]:
            with self.subTest(opcode=opcode, token=token), self.assertRaises(ValueError):
                self.index.resolve(opcode, token)

    def test_ambiguous_pack_name_is_not_silently_selected(self):
        index = ResourceIndex(self.spk)
        index.blocks.append(copy.deepcopy(index.blocks[14]))
        with self.assertRaises(ValueError):
            index.resolve(0x73, 'pr5011m')

    def test_truncated_pack_rejected(self):
        for end in [0, 31, 0x42f, 0xd17, 0x2823]:
            with self.subTest(end=end), self.assertRaises(ValueError):
                parse_scene_pack(self.pack[:end])

    def test_bad_bucket_and_region_pointer_rejected(self):
        for at, value in [(0x2c, 0x42f), (0x420, len(self.pack) + 1), (0x424, 0x800)]:
            mutated = bytearray(self.pack)
            struct.pack_into('<I', mutated, at, value)
            with self.subTest(at=at), self.assertRaises(ValueError):
                parse_scene_pack(mutated)

    def test_bad_cue_target_rejected(self):
        mutated = bytearray(self.pack)
        struct.pack_into('<I', mutated, 0xd27, len(self.pack))
        with self.assertRaises(ValueError):
            parse_scene_pack(mutated)

    def test_mmv_embedded_second_movie_is_identical_to_fad_movie(self):
        members = parse_mmv(self.mmv)
        self.assertEqual(len(members), 2)
        self.assertEqual(members[1]['offset'], 732 * 2048)
        row = members[1]
        self.assertEqual(self.mmv[row['offset']:row['offset'] + row['size']],
                         (ROOT / 'local/assets/GRA/PR/pr5011m.m2v').read_bytes())

    def test_mmv_corrupt_bounds_and_overlap_rejected(self):
        for at, value in [(60, 0), (124, 1), (56, len(self.mmv)), (124, len(self.mmv))]:
            mutated = bytearray(self.mmv)
            struct.pack_into('<I', mutated, at, value)
            with self.subTest(at=at, value=value), self.assertRaises(ValueError):
                parse_mmv(mutated)
        with self.assertRaises(ValueError):
            parse_mmv(self.mmv[:-2048])

    def test_mmv_extraction_is_exact(self):
        data, record = extract_mmv_member(self.mmv, 1)
        self.assertEqual(data, (ROOT / 'local/assets/GRA/PR/pr5011m.m2v').read_bytes())
        self.assertEqual(record['sector'], 732)
        for index in [-1, 2, True]:
            with self.assertRaises(ValueError):
                extract_mmv_member(self.mmv, index)

    def test_ipu_normalization_preserves_compressed_image(self):
        source = (ROOT / 'local/assets/GRA/PR/pr1031.ipu').read_bytes()
        derived, record = normalize_single_frame_ipu(source)
        self.assertEqual(derived[:4], source[:4])
        self.assertEqual(derived[8:], source[8:-4])
        self.assertEqual(struct.unpack_from('<I', derived, 4)[0], len(derived)-8)
        self.assertEqual(record['removed_tail_hex'], '000001b1')

    def test_ipu_bad_length_multiframe_and_terminators_rejected(self):
        source = (ROOT / 'local/assets/GRA/PR/pr1031.ipu').read_bytes()
        for at, value in [(4, len(source)), (12, 2), (8, 0)]:
            data = bytearray(source)
            struct.pack_into('<I', data, at, value)
            with self.subTest(at=at), self.assertRaises(ValueError):
                normalize_single_frame_ipu(data)
        for data in [source[:-1], source[:-4], source[:-4] + b'junk']:
            with self.assertRaises(ValueError):
                normalize_single_frame_ipu(data)

    def test_sound_named_allocation_has_real_bytes(self):
        row = lookup_se(self.se, '537002')
        self.assertEqual(row['record_offset'], 45136)
        self.assertEqual(row['offset'], 18656 * 2048)
        self.assertEqual(row['allocation_size'], 44 * 2048)
        with self.assertRaises(ValueError):
            lookup_se(self.se, 'not-a-sound')
        with self.assertRaises(ValueError):
            lookup_se(self.se, '999999')

    def test_sound_bad_allocation_rejected(self):
        data = bytearray(self.se)
        struct.pack_into('<I', data, 45136 + 4, len(data))
        with self.assertRaises(ValueError):
            lookup_se(data, '537002')

    def test_report_covers_exact_static_window(self):
        report = build_report(ROOT)
        self.assertEqual(report['scope']['start'], 0xa18c4)
        self.assertEqual(report['scope']['end_exclusive'], 0xa28b9)
        self.assertEqual(report['scope']['instruction_count'], 425)
        self.assertEqual(len(report['references']), 69)
        self.assertEqual(len(report['resources']), 61)
        self.assertIn('72:pk1042', report['resources'])


if __name__ == '__main__':
    unittest.main()
