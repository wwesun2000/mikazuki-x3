"""Use the original slot 7 bank and section descriptors as inputs to the retail save writers."""
import hashlib
import argparse
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]


def main():
    opts=argparse.ArgumentParser()
    opts.add_argument('--full',action='store_true')
    full=opts.parse_args().full
    plan=json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_bytes())
    data=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=plan['ram_sha256']:raise ValueError('RAM fixture identity changed')
    word=lambda a:struct.unpack_from('<I',data,a)[0]
    dest=word(0x235b28)
    cases=[]
    def patch(address,value):
        return dict(address=hex(address),hex=struct.pack('<I',value).hex(),reason='Declared source writer input')
    def case(label,entry,a0,a1,edits=()):
        cases.append(dict(id=label,function_address=hex(entry),return_defined=True,input=dict(
            registers=dict(a0=hex(a0),a1=hex(a1),a2='0',a3='0'),memory=list(edits))))
    sections=[(1,0x10bd50,0x140),(2,0x101080,0x150),(3,0x19ce48,0x550),
              (4,0x1abfa0,0x580),(5,0x1adab0,0x5a0),(6,0x1af4b0,0x5b0),(7,0x106690,0x5d0)]
    for i,entry,offset in sections:
        row=0x239e30+i*16
        extra=dest+word(row+12) if word(row+8) else 0
        case('case-'+hex(entry),entry,dest+offset,extra)
    for entry,offset,ptr in [(0x1abfa0,0x580,0x2381a4),(0x1adab0,0x5a0,0x2381b8)]:
        case('no-table-'+hex(entry),entry,dest+offset,0,[patch(ptr,0)])
    case('scope-disallows-record',0x104e10,0,0,[patch(0x235b3c,1)])
    case('pending-card-request',0x104e10,0,0,[patch(0x235b3c,0),patch(0x239fa4,2)])
    if full:
        cases.clear()
        case('actual-card-header',0x106338,dest,0)
        case('original-two-bank-write',0x104e10,0,0,[patch(0x235b3c,0),patch(0x239fa4,0)])
        case('already-in-refresh-mode',0x104e10,0,0,[patch(0x235b3c,0),patch(0x239fa4,1),patch(0x235b5c,5)])
        plan['isolated_platform']='card-single-owner-slot7-kernel-v1'
    plan['cases']=cases
    plan['case_kind']='Original save writers before memory-card submission, with two actual source admission guards'
    plan['observed_regions']=[dict(name='raw-PS2-save-bank',address=hex(dest),size=word(0x239e20))]
    if full:
        plan['case_kind']='Original header, pending update and complete eight-section card writes, with isolated kernel calls'
        plan['observed_regions'] += [dict(name='second-PS2-save-bank',address=hex(word(0x235b2c)),size=word(0x239e20)),
                                     dict(name='source-card-globals',address='0x239e00',size=512)]
    out=ROOT/'analysis/ghidra'/('oracle-scenario-record-full-plan.json' if full else 'oracle-scenario-record-plan.json')
    out.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    print(len(cases),out)


if __name__=='__main__':main()
