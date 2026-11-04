import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from vm_opening_controls import copy_packet,build_report


class OpeningEvidenceTests(unittest.TestCase):
    def test_selected_buffer_packet_keeps_other_fields(self):
        a=copy_packet(0);b=copy_packet(1)
        self.assertEqual(a['registers']['0x50'],0x000a1f40000a0000)
        self.assertEqual(b['registers']['0x50'],0x000a1f40000a08c0)
        self.assertEqual(a['registers']['0x52'],0x000000e000000280)
        self.assertEqual(copy_packet(0x200),a)
        self.assertEqual(copy_packet(0x1ff),b)

    def test_source_bytes_are_bound(self):
        r=build_report()
        self.assertTrue(r['source_slice']['raw_hex'].startswith('5a0000003c3c04040404'))
        self.assertEqual(len(r['evidence_regions']),24)


if __name__=='__main__':unittest.main()
