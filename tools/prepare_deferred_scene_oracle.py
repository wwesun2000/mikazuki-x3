"""Prepare source-instruction tests for the two-phase scene selector and its wait predicates."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-font-pointer-v1/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:
        raise ValueError('Original observation changed')
    def read(addr):
        return struct.unpack_from('<I',ram,addr)[0]
    manager=read(0x235e40)
    provider=read(0x235efc)
    script=read(manager+0x38)
    selector=17
    block=read(script+8+selector*4)
    code=read(block+0x430)
    at=ram.index(b'\x73\x08top0000\0\x74\x0btop0000_00\0',code,code+0x10000)
    def patch(addr,value):
        return dict(address=hex(addr),hex=struct.pack('<I',value).hex(),
                    reason='Declared input condition for the original scene selector')
    common=[patch(script+0xd0,selector),patch(script+0xd8,at+1),patch(manager+0x71c,0x777),
            patch(0x206250,0),patch(0x20680c,0),patch(0x2070f0,0),patch(0x2070f4,0)]
    cases=[]
    def add(name,func,regs,patches):
        cases.append(dict(id=name,function_address=hex(func),return_defined=True,
                          input=dict(registers={k:hex(v) for k,v in zip(('a0','a1','a2','a3'),regs)},
                                     memory=common+patches)))
    for state,loader,producer,consumer in [(0,0,0,0),(2,0,0,0),(0,4,0,0),(2,8,1,0),
                                           (1,5,0,0),(1,8,1,0),(3,0,0,0),(0xffffffff,0,0,0)]:
        add(f'select-phase-{state:x}-{loader}-{producer}',0x127e10,
            [read(manager+0x5c+0x73*4),0,at-code,0],
            [patch(provider+8,state),patch(0x206250,loader),patch(0x2070f0,producer),patch(0x2070f4,consumer)])
    for state,producer,consumer in [(0,0,0),(3,0,0),(8,1,0),(8,4,4)]:
        add(f'complete-predicate-{state}-{producer}',0x135618,[0,0,0,0],
            [patch(0x206250,state),patch(0x2070f0,producer),patch(0x2070f4,consumer)])
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in (
        ('provider',provider,0x20),('loader',0x206250,0xeb4),('cursor',script+0xd0,16),
        ('manager-scene-action',manager+0x71c,4))]
    plan['cases']=cases
    dest=ROOT/'analysis/ghidra/oracle-deferred-scene-plan.json'
    dest.write_text(json.dumps(plan,indent=2)+'\n')
    print('Prepared',len(cases),'cases from original script at',hex(at))


if __name__=='__main__':main()
