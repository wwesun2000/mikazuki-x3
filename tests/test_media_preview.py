import json
from pathlib import Path
import tempfile
import unittest
from tools.media_preview import audit


class DecodeEvidenceTests(unittest.TestCase):
    def test_zero_exit_does_not_hide_decoder_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'analysis').mkdir()
            (root / 'sample.png').write_bytes(b'not-an-accepted-image')
            (root / 'sample.log').write_text('Error submitting packet to decoder: Invalid data found when processing input')
            (root / 'analysis/media_decode_report.json').write_text(json.dumps({'results': [
                {'name': 'sample', 'output': 'sample.png', 'log': 'sample.log', 'returncode': 0, 'success': True}]}))
            item = audit(root)['results'][0]
            self.assertTrue(item['artifact_produced'])
            self.assertFalse(item['success'])
            self.assertEqual(item['status'], 'needs-decoder-investigation')

    def test_missing_output_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'analysis').mkdir()
            (root / 'sample.log').write_text('frame=0')
            (root / 'analysis/media_decode_report.json').write_text(json.dumps({'results': [
                {'name': 'sample', 'output': 'missing.png', 'log': 'sample.log', 'returncode': 0}]}))
            self.assertFalse(audit(root)['results'][0]['success'])


if __name__ == '__main__':
    unittest.main()
