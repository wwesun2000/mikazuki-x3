import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('scenario', Path(__file__).resolve().parents[1] / 'tools' / 'scenario.py')
scenario = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scenario)


def scr_fixture():
    name = b'top00_0000'
    code = b'\x85' + bytes([len(name) + 2, 0]) + name + b'\0\x22'
    code += b'\x02' + '\u3000\u79c1\u306f'.encode('cp932') + b'\x03\x0d\x02' + '\u3002'.encode('cp932') + b'\x03\0'
    symbol = struct.pack('<HHI', 0, 0x6f4e, len(name) + 4) + name + b'\0'
    symbol += bytes((-len(symbol)) % 4)
    header = bytearray(0x434)
    header[:len(scenario.SCR_MAGIC)] = scenario.SCR_MAGIC
    struct.pack_into('<I', header, 0x30, 0x434)
    struct.pack_into('<I', header, 0x430, 0x434 + len(symbol))
    return bytes(header) + symbol + code


def link_fixture():
    block = scr_fixture()
    header = bytearray(0xac)
    header[:16] = scenario.LINK_MAGIC
    header[16:32] = scenario.LINK_VERSION
    struct.pack_into('<III', header, 0xa0, 1, 0xac, len(block))
    return bytes(header) + block


def font_fixture():
    data = bytearray(scenario.FONT_MAGIC)
    data += struct.pack('<3I', 33, 23, 1)
    data += struct.pack('<5I', 0, 33, 3, 1, 0)
    data += struct.pack('<III', 0x8141, 0x000c140d, 60)
    data += b'\x12\x34'
    return bytes(data)


class ScenarioTests(unittest.TestCase):
    def test_link_block_identity(self):
        result = scenario.parse_link(link_fixture())
        self.assertEqual(result[0]['offset'], 0xac)
        self.assertEqual(result[0]['kind'], 'SCR-file')

    def test_link_rejects_truncation_and_overlap(self):
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_link(link_fixture()[:-1])
        data = bytearray(link_fixture())
        struct.pack_into('<I', data, 0xa4, 0xa0)
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_link(bytes(data))

    def test_label_anchor_and_text_offsets(self):
        data = scr_fixture()
        result = scenario.parse_scr(data)
        self.assertEqual(result['label_count'], 1)
        candidates, rejected = scenario.text_candidates(data, result['code_offset'], result['symbols'])
        self.assertEqual(rejected, 0)
        self.assertEqual([c['text'] for c in candidates], ['\u3000\u79c1\u306f', '\u3002'])
        self.assertEqual(candidates[0]['nearest_preceding_label'], 'top00_0000')
        for row in candidates:
            self.assertEqual(data[row['text_offset']:row['end_delimiter_offset']].hex(), row['raw_hex'])
            self.assertEqual(bytes.fromhex(row['raw_hex']).decode('cp932'), row['text'])

    def test_rejects_bad_code_boundary(self):
        data = bytearray(scr_fixture())
        struct.pack_into('<I', data, 0x430, 0xffffffff)
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_scr(bytes(data))

    def test_rejects_mismatched_label_anchor(self):
        data = bytearray(scr_fixture())
        struct.pack_into('<I', data, 0x438, 0)
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_scr(bytes(data))

    def test_invalid_cp932_and_controls_not_text(self):
        candidates, rejected = scenario.text_candidates(b'\x02\x81\x03\x02\x80\x03', 0, [])
        self.assertEqual(candidates, [])
        self.assertEqual(rejected, 2)

    def test_delimiters_do_not_cross_control_bytes(self):
        candidates, _ = scenario.text_candidates(b'\x02abc\x0ddef\x03', 0, [])
        self.assertEqual(candidates, [])

    def test_font_mapping(self):
        result = scenario.parse_font(font_fixture())
        glyph = result['groups'][0]['glyphs'][0]
        self.assertEqual(glyph['character'], '\u3001')
        self.assertEqual(glyph['payload_offset'], 60)
        self.assertEqual(glyph['payload_size'], 2)

    def test_font_rejects_outside_payload(self):
        data = bytearray(font_fixture())
        struct.pack_into('<I', data, 56, 0xffffffff)
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_font(bytes(data))

    def test_font_rejects_bad_descriptor_chain(self):
        data = bytearray(font_fixture())
        struct.pack_into('<I', data, 44, 60)
        with self.assertRaises(scenario.ScenarioError):
            scenario.parse_font(bytes(data))


if __name__ == '__main__':
    unittest.main()
