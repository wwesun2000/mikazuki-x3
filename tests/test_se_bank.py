import io
import json
from pathlib import Path
import struct
import sys
import unittest
import wave

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from se_bank import (ROOT, DEFAULT_IDS, inspect_stream, parse_bank, pcm_wave,
                     vag_container, sha)


def block(flag=0, header=12):
    return bytes([header, flag]) + bytes(14)


class StreamTests(unittest.TestCase):
    def test_loop_boundaries_are_samples_and_exclusive(self):
        r = inspect_stream(block() + block(6) + block(3), True)
        self.assertEqual(r['sample_count'], 84)
        self.assertEqual(r['loop']['start_sample'], 28)
        self.assertEqual(r['loop']['end_sample_exclusive'], 84)

    def test_one_shot_sentinel_retained_but_not_played(self):
        r = inspect_stream(block() + block(1) + b'\0\x07' + b'\x77' * 14, False)
        self.assertEqual(r['sample_count'], 56)
        self.assertEqual(r['retained_post_end_bytes'], 16)
        self.assertFalse(r['loop']['enabled'])

    def test_truncated_or_invalid_blocks_rejected(self):
        for data in [block(1)[:-1], block(1, 0x50), block(1, 0x0d), block(0x81)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                inspect_stream(data, False)

    def test_loop_conflicts_and_missing_boundaries_rejected(self):
        for data, loop in [(block(), False), (block(1), True),
                           (block(3), True), (block(6) + block(6) + block(3), True),
                           (block(6) + block(3), False)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                inspect_stream(data, loop)

    def test_unexplained_bytes_after_end_rejected(self):
        for data, loop in [(block(1) + block(), False),
                           (block(6) + block(3) + block(), True)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                inspect_stream(data, loop)

    def test_vag_wrapper_preserves_exact_compressed_bytes(self):
        data = block(1)
        wrapped = vag_container(data, 24000, '537002')
        self.assertEqual(wrapped[48:], data)
        self.assertEqual(struct.unpack_from('>II', wrapped, 12), (16, 24000))

    def test_wav_sample_rate_channels_and_smpl(self):
        loop = dict(enabled=True, start_sample=2, end_sample_exclusive=8)
        data = pcm_wave(bytes(32), 24000, 2, loop)
        with wave.open(io.BytesIO(data)) as r:
            self.assertEqual((r.getframerate(), r.getnchannels(), r.getnframes()), (24000, 2, 8))
        at = data.index(b'smpl') + 8
        self.assertEqual(struct.unpack_from('<II', data, at + 44), (2, 7))
        self.assertEqual(struct.unpack_from('<I', data, 4)[0], len(data) - 8)

    def test_wav_bad_loop_rejected(self):
        with self.assertRaises(ValueError):
            pcm_wave(bytes(8), 24000, 1, dict(enabled=True, start_sample=0, end_sample_exclusive=5))


class OriginalBankTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'local/assets/SOUND/SSDVDAT/se.dat').read_bytes()
        cls.rows = parse_bank(cls.data)
        cls.by_name = {r['name']: r for r in cls.rows}

    def test_original_count_and_encoded_streams(self):
        self.assertEqual(len(self.rows), 942)
        self.assertEqual(sum(r['stored_stream_count'] == 2 for r in self.rows), 73)
        self.assertEqual(self.by_name['532019']['stored_stream_count'], 2)
        self.assertFalse(self.by_name['532019']['raw_stereo_flag'])
        self.assertEqual(self.by_name['532019']['routing_status'],
                         'two-stored-streams-playback-routing-unverified')

    def test_actual_priority_loops(self):
        for name, samples, start in [('537002', 156604, 22484),
                                     ('532019', 256032, 6188),
                                     ('101039', 61712, 9044)]:
            r = self.by_name[name]
            self.assertEqual(r['base_sample_rate'], dict(numerator=24000, denominator=1))
            for c in range(r['stored_stream_count']):
                at = r['offset'] + c * r['stored_stream_bytes']
                s = inspect_stream(self.data[at:at+r['stored_stream_bytes']], r['raw_loop_flag'])
                self.assertEqual((s['sample_count'], s['loop']['start_sample']), (samples, start))

    def test_duplicate_identifier_rejected(self):
        data = bytearray(self.data)
        data[56 + 40:56 + 47] = data[40:47]
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            parse_bank(data)

    def test_overlapping_allocations_rejected(self):
        data = bytearray(self.data)
        data[60:68] = data[4:12]
        with self.assertRaises(ValueError):
            parse_bank(data)

    def test_out_of_bounds_sector_and_bad_padding_rejected(self):
        data = bytearray(self.data)
        struct.pack_into('<I', data, 4, len(data))
        with self.assertRaises(ValueError):
            parse_bank(data)
        data = bytearray(self.data)
        row = self.by_name['537002']
        data[row['offset'] + row['stored_stream_bytes']] = 0
        with self.assertRaisesRegex(ValueError, 'padding'):
            parse_bank(data)

    def test_all_opening_exports_exist_match_hash_and_have_signal(self):
        report = json.loads((ROOT / 'analysis/se_bank.json').read_text(encoding='utf-8'))
        self.assertEqual(report['source_sha256'], sha(self.data))
        self.assertEqual(set(report['entries']), set(DEFAULT_IDS))
        for row in report['entries'].values():
            for s in row['streams']:
                with self.subTest(name=row['name'], stream=s['stored_stream_index']):
                    p = ROOT / s['wav_path']
                    self.assertEqual(sha(p.read_bytes()), s['wav_sha256'])
                    self.assertEqual((s['decode_exit_code'], s['decode_stderr']), (0, ''))
                    self.assertGreater(s['nonzero_samples'], 0)
                    with wave.open(str(p)) as w:
                        self.assertEqual((w.getnchannels(), w.getframerate(), w.getnframes()),
                                         (1, s['sample_rate'], s['sample_count']))
            if row['stored_stream_count'] == 2:
                p = ROOT / row['two_channel_preservation_wav']['path']
                self.assertEqual(sha(p.read_bytes()), row['two_channel_preservation_wav']['sha256'])
                with wave.open(str(p)) as w:
                    self.assertEqual(w.getnchannels(), 2)
                    # Stored streams remain distinct, never averaged to mono.
                    pcm = w.readframes(w.getnframes())
                    self.assertTrue(any(pcm[i:i+2] != pcm[i+2:i+4] for i in range(0, len(pcm), 4)))


if __name__ == '__main__':
    unittest.main()
