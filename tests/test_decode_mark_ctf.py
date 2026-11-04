"""Regression checks for the actual, hash-bound atlas0 conversion."""
import hashlib
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from decode_mark_ctf import ROOT, decode


class Atlas0Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'local/assets/EFFECT/mark.ctf').read_bytes()

    def test_changed_source_is_rejected(self):
        altered = bytearray(self.source)
        altered[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA'):
            decode(altered)

    def test_png_pixels_and_transparency_match_original_index_data(self):
        png, metadata = decode(self.source)
        self.assertEqual(hashlib.sha256(png).hexdigest(),
                         '066e19dc11ee68cff27d57587734b3947a3ca548a2d2e7b8c92cf670ded9e0cd')
        position = 8
        compressed = bytearray()
        while position < len(png):
            size = struct.unpack_from('>I', png, position)[0]
            kind = png[position+4:position+8]
            body = png[position+8:position+8+size]
            expected = struct.unpack_from('>I', png, position+8+size)[0]
            self.assertEqual(zlib.crc32(kind+body), expected)
            if kind == b'IDAT':
                compressed.extend(body)
            position += 12+size
        scanlines = zlib.decompress(compressed)
        self.assertEqual(len(scanlines), 128*(1+128*4))
        self.assertEqual(sum(metadata['index_histogram']), 128*128)
        # Verify all decoded pixels against original packed indices, including
        # transparent pixels, instead of only trusting the resulting PNG hash.
        for y in range(128):
            row = scanlines[y*513:(y+1)*513]
            self.assertEqual(row[0], 0)
            for x in range(128):
                packed = self.source[0xc0+y*64+x//2]
                index = packed & 15 if x % 2 == 0 else packed >> 4
                r, g, b, a = self.source[0x80+index*4:0x84+index*4]
                self.assertEqual(row[1+x*4:5+x*4], bytes((r,g,b,a*255//128)))


if __name__ == '__main__':
    unittest.main()
