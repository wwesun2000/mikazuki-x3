import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import opening_instructions as opening


class FramingTests(unittest.TestCase):
    def test_fixed_width_does_not_dispatch_payload_bytes(self):
        data=bytes.fromhex('461b4005570000003c')
        rows=opening.frame_window(data,0,len(data))
        self.assertEqual([r['opcode'] for r in rows],[0x46,0x40,0x57])
        self.assertEqual([r['unsigned_big_endian'] for r in rows],[27,5,60])

    def test_extended_length_big_endian(self):
        data=bytes.fromhex('68000003616263')
        row=opening.frame_one(data,0,len(data))
        self.assertEqual(row['payload_size'],3)
        self.assertEqual(row['length_header_bytes'],3)
        self.assertEqual(row['payload_hex'],'616263')

    def test_auxiliary_block_consumes_delimiters(self):
        data=bytes.fromhex('060282dd82a9030282c382ab0307')
        rows=opening.frame_window(data,0,len(data))
        self.assertEqual(len(rows),1)
        self.assertEqual([t['decoded_cp932'] for t in rows[0]['auxiliary_texts']],['みか','づき'])
        self.assertFalse(rows[0]['nested_tokens_are_top_level_dispatch'])

    def test_truncation_and_unknown_are_rejected(self):
        for raw in ['57000000','68000004aabb','028254','060282dd03','03','07','ff','060007']:
            data=bytes.fromhex(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                opening.frame_window(data,0,len(data))

    def test_fp_decode(self):
        self.assertEqual(opening.decode_fp(0x46010303),'div.s f12,f0,f1')
        self.assertEqual(opening.decode_fp(0x46800860),'cvt.s.w f1,f1')
        self.assertEqual(opening.decode_fp(0x0002800B),'movn r16,r0,r2')

    @unittest.skipUnless((ROOT/'local/assets/SCENARIO/sn4g.sn4').exists(),'Local script absent')
    def test_actual_slice_coverage_labels_and_ruby(self):
        data=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),opening.SCRIPT_SHA)
        rows=opening.frame_window(data,opening.START,opening.END)
        self.assertEqual(b''.join(bytes.fromhex(r['raw_hex']) for r in rows),data[opening.START:opening.END])
        self.assertIn(0xA19AF,[r['offset'] for r in rows])
        ruby=next(r for r in rows if r['opcode']==6)
        self.assertEqual(ruby['offset'],0xA194F)
        self.assertEqual(ruby['end_exclusive'],0xA1963)
        self.assertEqual([t['decoded_cp932'] for t in ruby['auxiliary_texts']],['みか','づき','じま'])
        self.assertEqual([r['unsigned_big_endian'] for r in rows if r['opcode']==0x57],[60,60])
        self.assertNotIn(3,[r['opcode'] for r in rows])
        self.assertNotIn(7,[r['opcode'] for r in rows])


if __name__=='__main__':unittest.main()
