"""Static evidence integrity tests. No PS2 instructions are executed."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import vm_handlers as vm


class RejectionTests(unittest.TestCase):
    def test_wrong_source_refused(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            vm.Image(b'not the verified ELF')

    def test_segment_mapping_rejects_memory_only_tail_and_crossing(self):
        image = vm.Image.__new__(vm.Image)
        image.segments = [dict(virtual_address=0x1000, file_offset=16,
                               file_size=16, memory_size=32)]
        self.assertEqual(image.offset(0x100C), 28)
        for address, size in [(0x1010,4), (0x100C,8), (0xFFF,4), (0x1000,0)]:
            with self.assertRaises(ValueError):
                image.offset(address,size)

    def test_ambiguous_segment_rejected(self):
        image = vm.Image.__new__(vm.Image)
        segment = dict(virtual_address=0x1000,file_offset=0,file_size=16,memory_size=16)
        image.segments = [segment,segment.copy()]
        with self.assertRaises(ValueError):
            image.offset(0x1000)

    def test_output_cannot_overwrite_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)/'source.elf'
            source.write_bytes(b'preserve source')
            with self.assertRaisesRegex(ValueError, 'distinct'):
                vm.write_outputs({},source,source,Path(temp)/'doc.md')
            self.assertEqual(source.read_bytes(),b'preserve source')


@unittest.skipUnless((ROOT/'local/extracted/SLPM_664.52').is_file(),'Local ELF fixture absent')
class ActualBuildEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT/'local/extracted/SLPM_664.52'
        cls.data = cls.path.read_bytes()
        cls.image = vm.Image(cls.data)
        cls.report = vm.build_report(cls.image,cls.path)
        cls.entries = cls.report['opcode_entries']

    def test_single_byte_mutation_rejected(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            vm.Image(bytes(changed))

    def test_all_factory_entries_match_raw_elf(self):
        self.assertEqual([e['opcode'] for e in self.entries],list(range(135)))
        for entry in self.entries:
            record = entry['factory_table_word']
            raw = self.data[record['file_offset']:record['file_offset']+4]
            self.assertEqual(raw.hex(),record['raw_hex'])
            self.assertEqual(struct.unpack('<I',raw)[0],int(entry['factory_case'],16))

    def test_137_slot_boundary_and_nulls(self):
        self.assertEqual(self.image.word(0x10FD48),0x2E2F0087)
        self.assertEqual(self.image.word(0x10FD88),0x2A2F0089)
        self.assertEqual(self.report['counts']['null_table_entries'],20)
        self.assertEqual(self.report['counts']['constructed_classes'],72)
        self.assertEqual([e['opcode'] for e in self.report['correction_to_previous_report']['out_of_table_slots']],[135,136])
        self.assertIsNone(self.entries[0]['default_context_entry'])

    def test_text_handler_pointer_chain(self):
        e = self.entries[2]
        self.assertEqual((e['constructor'],e['vtable'],e['default_context_entry']),
                         ('0x00122be0','0x00223da8','0x00122da0'))
        c = next(c for c in self.report['handler_classes'] if c['id']==e['class_id'])
        self.assertFalse(c['parameter_reader_windows'])
        self.assertIn('0x00122bf0',[e['target'] for e in c['default_context_direct_edges']])

    def test_label_shared_class_and_parameter_reads(self):
        self.assertEqual(len({self.entries[o]['class_id'] for o in (0x6A,0x6B,0x85)}),1)
        e = self.entries[0x6A]
        self.assertEqual(e['default_context_entry'],'0x001253e8')
        c = next(c for c in self.report['handler_classes'] if c['id']==e['class_id'])
        window = next(w for w in c['parameter_reader_windows'] if w['entry']=='0x00124d48')
        self.assertTrue(window['default_context_direct_edge_reachable'])
        self.assertTrue({'0x0010d638','0x0010d5d8','0x0010d680'} <= {e['target'] for e in window['reader_calls']})
        byte_call = next(e for e in window['reader_calls'] if e['target']=='0x0010d5d8')
        self.assertEqual(byte_call['a1_literal_candidate']['value'],1)
        self.assertEqual(byte_call['a1_literal_candidate']['status'],'executed-call-delay-slot')

    def test_inline_slice_and_auxiliary_dispatch(self):
        detail = self.report['inline_text_detail']
        self.assertEqual(detail['instruction_count'],391)
        self.assertEqual(detail['raw_sha256'],'3a4fc1d0ef2c040e36437dc10ab9673b712c6ae772b8969b72423d207f554fbe')
        self.assertEqual(detail['direct_call_count'],63)
        self.assertEqual(len(detail['unique_direct_targets']),31)
        self.assertEqual(detail['lookahead_switch']['groups']['0x00112c84'],[0x0D,0x0E,0x0F,0x10,0x11,0x42,0x43,0x4C])

    def test_every_evidence_region_matches_source_and_keeps_unknowns(self):
        unknown = 0
        for region in self.report['evidence_regions'].values():
            start,end = int(region['start'],16),int(region['end_exclusive'],16)
            offset = region['file_offset']
            self.assertEqual(region['raw_sha256'],hashlib.sha256(self.data[offset:offset+end-start]).hexdigest())
            for instruction in region['instructions']:
                raw = self.data[instruction['file_offset']:instruction['file_offset']+4]
                self.assertEqual(raw.hex(),instruction['raw_hex'])
                unknown += instruction['decoded']=='uninterpreted by subset decoder'
        self.assertGreater(unknown,0)


if __name__=='__main__':
    unittest.main()
