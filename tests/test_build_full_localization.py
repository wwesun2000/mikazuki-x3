from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_full_localization as b
import localization as loc


def fixture(text='検証',offset=0,label='pr01_test',kind='primary_text'):
    raw=b'\x02'+text.encode('cp932')+b'\x03'
    entry=dict(entry_id=f'test:00:{offset:08x}',original=text,source_hash=loc.text_hash(text),
        context=f'{kind}; synthetic fixture',tokens=[],record_kind=kind,program='test',selector=0,
        public_label_context=dict(labels=[label],offset=0,relationship='synthetic'),decode_status='strict-cp932',
        location=dict(path='synthetic.sn4',offset=offset,length=len(raw),raw_hex=raw.hex(),
            raw_sha256=b.sha(raw),script_sha256='b'*64))
    return b.make_pair([entry],'synthetic test only')


class FullLocalization(unittest.TestCase):
    def test_empty_untranslated_targets(self):
        baseline,catalog=fixture()
        self.assertTrue(loc.validate(catalog,baseline)['ok'])
        self.assertEqual(catalog['entries'][0]['targets']['zh-Hans'],dict(text='',status='untranslated'))
        self.assertFalse(loc.validate(catalog,baseline,release=True)['ok'])

    def test_existing_targets_and_notes_preserved(self):
        baseline,catalog=fixture();catalog['entries'][0]['translator_note']='context important'
        catalog['entries'][0]['targets']['zh-Hans']=dict(text='验证',status='draft',notes=['retain me'])
        catalog['custom_metadata']={'owner':'human'}
        merged=b.merge_existing(baseline,fixture()[1],deepcopy(baseline),catalog)
        self.assertEqual(merged,catalog)
        merged['entries'][0]['targets']['zh-Hans']['text']='new'
        self.assertEqual(catalog['entries'][0]['targets']['zh-Hans']['text'],'验证')

    def test_source_change_aborts(self):
        oldb,oldc=fixture();newb,newc=fixture('変更')
        with self.assertRaisesRegex(ValueError,'Source baseline changed'):
            b.merge_existing(newb,newc,oldb,oldc)

    def test_removed_id_aborts(self):
        oldb,oldc=fixture();newb,newc=b.make_pair([],'synthetic test only')
        with self.assertRaises(ValueError):b.merge_existing(newb,newc,oldb,oldc)

    def test_missing_pair_aborts(self):
        baseline,catalog=fixture()
        with self.assertRaisesRegex(ValueError,'Incomplete'):b.merge_existing(baseline,catalog,baseline,None)

    def test_provenance_change_aborts(self):
        baseline,catalog=fixture();catalog['entries'][0]['record_kind']='ruby'
        with self.assertRaisesRegex(ValueError,'provenance'):b.merge_existing(baseline,catalog,baseline,catalog)

    def test_partial_scope_cannot_release_even_with_line_reviews(self):
        baseline,catalog=fixture()
        for target in catalog['entries'][0]['targets'].values():
            target.update(text='Test',status='reviewed',reviewed_source_hash=baseline['entries'][0]['source_hash'],
                reviewed_text_hash=loc.text_hash('Test'),reviewed_by='synthetic',reviewed_at='2026-10-30T01:00:00Z')
        result,_=b.gate([baseline],[catalog],{},release=True)
        self.assertFalse(result['ok'])
        self.assertTrue(any('complete extraction coverage' in e for e in result['errors']))
        self.assertTrue(any('holistic review' in e for e in result['errors']))

    def test_record_bytes_include_21_marker(self):
        raw=b'\x02\x21'+ '検証'.encode('cp932')+b'\x03'
        group=dict(id='test:00:00000000',offset=0,raw_hex='検証'.encode('cp932').hex(),text='検証',skip_21_offsets=[1])
        block=dict(selector=0,code_start=0,code_end=len(raw),code_sha256=b.sha(raw),labels={'test':0},
            label_metadata={'test':dict(internal=False,id=0)},instructions=[dict(offset=0,next=len(raw),op=2,raw_hex=raw.hex(),text=group)])
        records=b.extract_block(dict(source=dict(path='SCENARIO/test.sn4',sha256='c'*64)),'d'*64,raw,block)
        self.assertEqual(records[0]['location']['raw_hex'],raw.hex())
        self.assertEqual(records[0]['location']['skip_21_offsets'],[1])
        self.assertEqual(records[0]['tokens'],[])

    def test_tampered_program_record_rejected(self):
        raw=b'\x02'+ '検証'.encode('cp932')+b'\x03'
        block=dict(selector=0,code_start=0,code_end=len(raw),code_sha256=b.sha(raw),labels={},label_metadata={},
            instructions=[dict(offset=0,next=len(raw),op=2,raw_hex=raw.hex(),text=dict(id='wrong',offset=0))])
        with self.assertRaises(ValueError):b.extract_block(dict(source=dict(path='SCENARIO/test.sn4',sha256='c'*64)),'d'*64,raw,block)

    def test_concurrent_edit_detected_before_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'catalog.json';path.write_text('{}',encoding='utf8');old=b.sha(path.read_bytes())
            path.write_text('{"translator":"changed"}',encoding='utf8')
            with self.assertRaisesRegex(ValueError,'Concurrent edit'):b.write_batch({path:{'new':1}},{path:old})
            self.assertEqual(json.loads(path.read_text()),{'translator':'changed'})

    def test_identical_rebuild_keeps_user_formatting(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'catalog.json';raw=b'{"note":"keep custom formatting"}\n';path.write_bytes(raw)
            changed=b.write_batch({path:{'note':'keep custom formatting'}},{path:b.sha(raw)})
            self.assertEqual(changed,[]);self.assertEqual(path.read_bytes(),raw)

    def test_write_new_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'catalog.json'
            self.assertEqual(len(b.write_batch({path:{'value':1}},{path:None})),1)
            self.assertEqual(b.write_batch({path:{'value':1}},{path:b.sha(path.read_bytes())}),[])

if __name__=='__main__':unittest.main()
