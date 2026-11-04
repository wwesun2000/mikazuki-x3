"""Prepare independent original R5900 calls for the hero panel's persistent fields."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]
def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_bytes())
    mem=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(mem).hexdigest()!=plan['ram_sha256']:raise ValueError('Wrong original snapshot')
    word=lambda p:struct.unpack_from('<I',mem,p)[0]
    half=lambda p:struct.unpack_from('<H',mem,p)[0]
    manager=word(0x235e40);obj=word(manager+28);cases=[]
    def store(p,n,size=4):
        return dict(address=hex(p),hex=n.to_bytes(size,'little').hex(),reason='Explicit original hero choice argument or progress input')
    def case(name,addr,args,patches,defined=False):
        regs={reg:hex(value) for reg,value in zip(('a0','a1','a2','a3'),[*args,*[0]*4])}
        cases.append(dict(id=name,function_address=hex(addr),return_defined=defined,
                          input=dict(registers=regs,memory=patches)))
    for progress in range(10):
        patches=[store(0x238af8,progress,2)]
        if progress==7:
            patches += [store(0x238af0+2*half(0x236720+2*i),i%2,2) for i in range(4)]
        case(f'portraits-{progress}',0x14b120,[],patches)
    for actor,phase in ((0,0),(1,0),(1,1),(2,2),(3,3),(3,7),(4,8),(0xffffffff,8)):
        case(f'eligibility-{actor}-{phase}',0x14bd18,[actor],[store(0x238af8,phase,2)],True)
    for n in (0,3,7):
        case(f'chart-prepare-phase-{n}',0x1ac690,[],[store(0x238af8,n,2)])
    case('waiting-actor-object',0x119b60,[obj],[store(obj,0)],True)
    script=word(manager+56);selector=word(script+0xd0);label=word(script+0xd4)
    target=word(word(script+0xcc)+4*label)+8;offset=word(script+0xd8)-word(word(script+8+4*selector)+0x430)
    for selected in (0,0xffffffff):
        # A complete owner frame on the original captured heap. Target here is
        # the captured scene's real label; the process test covers another
        # selector, the original first card and its actual following chapter.
        patches=[store(obj,1),store(obj+4,selected),store(obj+8,word(0x235f3c)),
                 store(obj+12,selector),store(obj+16,target),store(obj+60,selector),store(obj+64,target),
                 store(obj+68,selector),store(obj+72,label),store(obj+76,offset),store(obj+80,1),
                 store(manager+64,word(0x235f54)),store(word(manager+0x2a0)+4,1)]
        case(f'owner-return-{selected:x}',0x119b60,[obj],patches,True)
    case('finish-caption-return-to-picker',0x1324e8,[],[],True)
    case('caption-page-font-and-readback',0x12f9a8,[],[],True)
    plan.update(cases=cases,case_kind='Original constructed slot 7 and declared progression / selector arguments',
                observed_regions=[dict(name=name,address=hex(p),size=length) for name,p,length in
                                  [('panel-global-state',0x2366c0,0x50),('panel-card-textures',0x23e988,16),
                                   ('panel-highlights',0x23e8b0,16),('panel-async-state',0x2387a8,36),
                                   ('chart-read-matrix',word(0x2381c8),(word(0x238960)+1)*88),
                                   ('source-manager',manager,0x858),('actor-object',obj,0x54)]])
    (ROOT/'analysis/ghidra/oracle-actor-choice-return-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases))

if __name__=='__main__':main()
