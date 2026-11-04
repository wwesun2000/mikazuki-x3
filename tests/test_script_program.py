import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from build_script_program import build_program, canonical


class ProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.envelope, cls.report = build_program(cls.source)
        cls.program = json.loads(cls.envelope['payload'])

    def test_all_code_bytes_and_labels_preserved(self):
        self.assertEqual(self.report['blocks'], 30)
        self.assertEqual(self.report['instructions'], 135040)
        self.assertEqual(self.report['labels'], 8004)
        self.assertEqual(self.report['unresolved_static_targets'], [])
        for b in self.program['blocks']:
            raw = b''.join(bytes.fromhex(r['raw_hex']) for r in b['instructions'])
            self.assertEqual(raw, self.source[b['code_start']:b['code_end']])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), b['code_sha256'])
            self.assertTrue(set(b['labels'].values()) <= {r['offset'] for r in b['instructions']})

    def test_bound_source_identity(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            build_program(self.source[:-1] + bytes([self.source[-1] ^ 1]))

    def test_payload_is_canonical_and_hash_bound(self):
        self.assertEqual(self.envelope['payload'], canonical(self.program))
        self.assertEqual(self.envelope['sha256'], hashlib.sha256(self.envelope['payload'].encode()).hexdigest())

    def test_real_conditional_choice_and_targets_are_not_linearized(self):
        b = next(b for b in self.program['blocks'] if b['selector'] == 15)
        rows = {r['offset']:r for r in b['instructions']}
        self.assertEqual(rows[0xA226D]['operands']['variable_id'], 0x17d)
        self.assertEqual(rows[0xA259C]['operands']['option_count'], 2)
        self.assertEqual([(x['block_selector'], x['label']) for x in rows[0xA259C]['operands']['options']],
                         [(15, 'pr01_0115'), (13, 'pk01_0010')])
        self.assertEqual(rows[b['labels']['pr01_0020']]['op'], 0x22)

    def test_text_has_source_location_and_raw_units(self):
        texts = []
        for b in self.program['blocks']:
            for r in b['instructions']:
                texts += [r['text']] if 'text' in r else r.get('ruby', [])
        self.assertEqual(len(texts), 32255)
        self.assertEqual(len({t['id'] for t in texts}), len(texts))
        for t in texts:
            self.assertEqual(bytes.fromhex(t['raw_hex']).decode('cp932'), t['text'])
        self.assertFalse(self.report['complete_execution'])


if __name__ == '__main__':
    unittest.main()
