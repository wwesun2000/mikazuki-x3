"""Hash-bound 34/35 record scope recovery. Pure state, never executes ELF."""
from copy import deepcopy
import json
from vm_handlers import ROOT, Image
from vm_presentation_semantics import extended_decode
from opening_instructions import SCRIPT_SHA


def initial_scope():
    #10CA74..7C initializes14C,150,15C;154/158/160/164 are not initialized.
    return dict(back_selector=None,back_label=None,restore_valid=False,
                restore_selector=None,restore_label=None,global_flag=None)


def execute(state,opcode):
    if opcode not in (0x34,0x35):raise ValueError('Unsupported opcode')
    out=deepcopy(state);scope=out['presentation']['record_scope']
    out['presentation']['manager']['plus32c']=int(opcode==0x34)
    if opcode==0x34:
        label=out['current_label_id']
        if not 0<=label<len(out['history']):raise ValueError('Current label has no history record')
        out['history'][label][0]|=0x20000000
        if not out['host']['script_0150']:
            words=out['history'][label]
            scope['back_selector']=words[1]&31
            scope['back_label']=words[0]&0x3fff
            rt=out['script_runtime']
            valid=rt['forward_snapshot_valid'] and rt['forward_snapshot_label']==scope['back_label']
            scope['restore_valid']=bool(valid)
            if valid:
                scope['restore_selector']=rt['forward_snapshot_selector']
                scope['restore_label']=rt['forward_snapshot_target']
        out['host']['script_014c']=True
        out['host']['script_0150']=False
        out['script_runtime']['pending_edge']=False
        scope['global_flag']=1
    else:
        out['host']['script_014c']=False
        out['host']['script_0150']=True
        out['script_runtime']['pending_edge']=True
        scope['global_flag']=0
    return out


REGIONS=[(0x132A08,0x132A68),(0x114AA0,0x114B30),(0x10F318,0x10F4E0),
         (0x10D748,0x10D750),(0x10EEA0,0x10EED0),(0x10E8D8,0x10EAA8),
         (0x10E708,0x10E748),(0x10E658,0x10E708),(0x10D978,0x10DAC0),
         (0x10CA5C,0x10CA80),(0x1061C0,0x1061DC)]


def build_report():
    image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    regions=[]
    for start,end in REGIONS:
        row=image.region(start,end)
        for instruction in row['instructions']:
            instruction['extended_decode']=extended_decode(int(instruction['raw_word'],16),int(instruction['address'],16))
        regions.append(row)
    return dict(evidence_id='VM-RECORD-SCOPE-001',authority='local static analysis, not PS2 runtime trace',
        elf_sha256=image.sha256,script_sha256=SCRIPT_SHA,
        first_native_block={'selector':15,'offset':0xA1834,'opcode':0x34,'source':'root native execution observation'},
        op34=['manager32C=1','current history.word0 bit29=1',
            'if script150==0: capture backward fields to154/158; matching forward snapshot copied to15C/160/164',
            'script14C=1,script150=0','global gp-7FB4=1'],
        op35=['manager32C=0','10F3C8(a1=1):script14C=0,script150=1; no link restoration',
              'global gp-7FB4=0'],
        transfer=['ordinary forward+snapshot and visit','script14C marks old record bit29',
            '6B returns before reverse links and pending-edge handling',
            'ordinary reverse link/media association',
            'if script150: clear it; replace new backward link with154/158; replace saved back-label forward link withnew target, snapshotting that prior link'],
        storage={'presentation.record_scope':initial_scope(),
                 'host.script_014c':'script+14C','host.script_0150':'script+150',
                 'script_runtime.pending_edge':'alias ofscript150',
                 'back_selector':'script154','back_label':'script158','restore_valid':'script15C',
                 'restore_label':'script160','restore_selector':'script164','global_flag':'gp-7FB4'},
        record_pool='manager330 ten-record pool is untouched by34/35; manager32C is a distinct adjacent scope flag',
        limitations=['10F3C8(a1=0) abort restoration is retained as evidence but not exposed as35 semantics',
            'Original helpers do not validate packed backlink sentinels; native rejects out-of-table pending edges before commit',
            'Uninitialized154/158/160/164 and not-yet-written global flag remainnull; no guessed heap defaults',
            'manager740,recorder744 and non-null tracker slot8 retain explicit external dependency blocks'],
        evidence_regions=regions)


def main():
    report=build_report()
    (ROOT/'analysis/vm_record_scope.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence_regions':len(report['evidence_regions']),'output':'analysis/vm_record_scope.json'}))


if __name__=='__main__':main()
