import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import vm_progress_callbacks as progress


class BoundariesTests(unittest.TestCase):
    def test_reader_rejects_range_and_missing_second_nul(self):
        for data in (b'abc',b'abc\0x'):
            with self.assertRaises(ValueError):progress.Reader(data).double_nul_string()
        with self.assertRaises(ValueError):progress.Reader(b'a').take(2)

    def test_label_slot_requires_terminator_ascii_and_padding(self):
        for raw in (b'x'*14,b'x\0'+b'y'*12,b'\xff\0'+b'\0'*12,b'x\0'):
            with self.assertRaises(ValueError):progress.fixed_label_record(raw,0,1)

    def test_source_identity_is_enforced(self):
        with self.assertRaises(ValueError):progress.parse_timechart(b'wrong')
        with self.assertRaises(ValueError):progress.parse_chapter_table(b'wrong',0)

    def test_binding_game1_uses_timechart_not_end_or_chapter(self):
        b=progress.binding_for_game(1,startup_flag_11=False)
        self.assertEqual((b['resource_slot'],b['resource_path'],b['slot0']),
                         (6,'CHART/sn4g_tim.dat','0x001ac598'))
        for i in (0,2):
            b=progress.binding_for_game(i,startup_flag_11=False)
            self.assertEqual((b['resource_slot'],b['slot0']),(7,'0x001af188'))

    def test_disabled_and_unknown_startup_states_are_explicit(self):
        self.assertFalse(progress.binding_for_game(1,startup_flag_11=True)['enabled'])
        with self.assertRaises(progress.UnknownControlState):progress.binding_for_game(1,startup_flag_11=None)
        with self.assertRaises(ValueError):progress.binding_for_game(3,startup_flag_11=False)

    def test_chapter_callback_group_replacement_and_nonzero_a1(self):
        table={'entries':[dict(index=0,group=1,label='a'),dict(index=1,group=1,label='b'),
                          dict(index=2,group=2,label='c'),dict(index=3,group=0,label='ignored')]}
        state=progress.initial_chapter_state()
        a=progress.chapter_callback(table,state,'a',second_argument=0)['state']
        c=progress.chapter_callback(table,a,'c',second_argument=0)['state']
        b=progress.chapter_callback(table,c,'b',second_argument=0)['state']
        self.assertEqual(bytes.fromhex(b['selected_bitmap_hex'])[0],6)
        self.assertEqual(bytes.fromhex(state['selected_bitmap_hex'])[0],0)
        self.assertEqual(progress.chapter_callback(table,b,'a',second_argument=1)['state'],b)
        self.assertEqual(progress.chapter_callback(table,b,'absent',second_argument=0)['state'],b)
        self.assertEqual(progress.chapter_callback(table,b,'ignored',second_argument=0)['state'],b)

    def test_chapter_bitmap_length_and_a1_required(self):
        with self.assertRaises(ValueError):progress.chapter_callback({'entries':[]},{'selected_bitmap_hex':'00'},'a',second_argument=0)
        with self.assertRaises(progress.UnknownControlState):
            progress.chapter_callback({'entries':[]},progress.initial_chapter_state(),'a',second_argument=None)


@unittest.skipUnless((ROOT/'local/assets/CHART/sn4g_tim.dat').is_file(),'Local fixture absent')
class ActualBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'local/assets/CHART/sn4g_tim.dat').read_bytes()
        cls.table=progress.parse_timechart(cls.data)
        cls.chapter_data={i:(ROOT/'local/assets/CHART'/name).read_bytes()
                          for i,name in ((0,'sn4_chap.dat'),(2,'sn2_chap.dat'))}
        cls.chapters={i:progress.parse_chapter_table(b,i) for i,b in cls.chapter_data.items()}

    def test_source_mutation_rejected(self):
        with self.assertRaises(ValueError):progress.parse_timechart(self.data[:-1]+bytes((self.data[-1]^1,)))

    def test_exact_original_tables_and_preserved_tail(self):
        self.assertEqual((self.table['time_table']['count'],len(self.table['strings']),
                          self.table['record16_table']['count']),(101,192,34))
        self.assertEqual((self.table['seen_labels']['offset'],self.table['seen_labels']['count']),(0xCCA,302))
        self.assertEqual((self.table['checkpoint_labels']['offset'],self.table['checkpoint_labels']['count']),(0x1D50,301))
        self.assertEqual(self.table['parsed_prefix_end'],0x2DC6)
        tail=self.table['unparsed_tail']
        self.assertEqual(hashlib.sha256(self.data[tail['offset']:]).hexdigest(),tail['sha256'])

    def test_first_page_marks_only_source_index1(self):
        state=progress.initial_timechart_state(self.table)
        result=progress.timechart_callback(self.table,state,'pr01_0020')
        bitmap=bytes.fromhex(result['state']['seen_bitmap_hex'])
        self.assertEqual(bitmap,b'\x02'+bytes(37))
        self.assertEqual(result['state']['checkpoint_index'],1)
        self.assertEqual(result['matches'],{'seen_index':1,'checkpoint_index':1})
        self.assertEqual(bytes.fromhex(state['seen_bitmap_hex']),bytes(38))

    def test_entering_later_page_keeps_earlier_progress(self):
        first=progress.timechart_callback(self.table,progress.initial_timechart_state(self.table),'pr01_0020')['state']
        second=progress.timechart_callback(self.table,first,'pr01_0800')['state']
        self.assertEqual(bytes.fromhex(second['seen_bitmap_hex'])[0],6)
        self.assertEqual(second['checkpoint_index'],2)
        self.assertFalse(progress.timechart_callback(self.table,second,'pr01_0800')['changed'])

    def test_unmatched_and_reserved_empty_labels_do_not_unlock(self):
        state=progress.initial_timechart_state(self.table)
        for label in ('','top00_0000','absent'):
            self.assertEqual(progress.timechart_callback(self.table,state,label)['state'],state)

    def test_invalid_progress_state_rejected(self):
        with self.assertRaises(ValueError):
            progress.timechart_callback(self.table,{'seen_bitmap_hex':'00','checkpoint_index':0},'pr01_0020')
        state=progress.initial_timechart_state(self.table)
        with self.assertRaises(ValueError):
            progress.timechart_callback(self.table,dict(state,checkpoint_index=301),'pr01_0020')

    def test_each_label_record_raw_matches_source(self):
        for name in ('seen_labels','checkpoint_labels'):
            for row in self.table[name]['entries']:
                raw=self.data[row['offset']:row['offset']+14]
                self.assertEqual(raw.hex(),row['raw_hex'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(),row['raw_sha256'])

    def test_chapter_payloads_have_exact_preserved_duplicate(self):
        self.assertEqual({i:t['count'] for i,t in self.chapters.items()},{0:32,2:36})
        for i,t in self.chapters.items():
            tail=t['duplicate_payload_tail'];b=self.chapter_data[i]
            self.assertEqual(b[2:tail['offset']],b[tail['offset']:])
            self.assertFalse(tail['used_by_1af010'])
            for row in t['entries']:
                self.assertEqual(b[row['offset']:row['end_exclusive']].hex(),row['raw_hex'])


if __name__=='__main__':unittest.main()
