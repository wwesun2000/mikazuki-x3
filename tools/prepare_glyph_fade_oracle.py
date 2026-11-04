"""Select occupied original glyph pools and controlled operands for the R5900 fade handlers."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-font-pointer-v1/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('Unexpected original RAM')
    def u(address):return struct.unpack_from('<I',ram,address)[0]
    def put(address,data):return dict(address=hex(address),hex=data.hex(),reason='Declared glyph transition input')
    def word(address,value):return put(address,struct.pack('<I',value&0xffffffff))
    manager=u(0x235e40);font=u(manager+0x3c);script=u(manager+0x38);cursor=u(script+0xd8)
    pools=[u(u(font+i)) for i in (8,12)]
    regions=[('font',font,0x38),('ranges',manager+0x2f0,24),('script-cursor',script+0xd8,4)]
    for lane,pool in enumerate(pools):
        regions.extend([(f'iterator-{lane}',u(pool+12),16),(f'atlas-{lane}',u(font+8+4*lane),0x30)])
        if u(pool+4):regions.append((f'glyphs-{lane}',u(pool+8),u(pool+4)*56))
    cases=[]
    def add(name,entry,arg,patches):
        cases.append(dict(id=name,function_address=hex(entry),return_defined=True,
                          input=dict(registers=dict(a0='0x0',a1=hex(arg),f20='0x0',fcsr='0x0'),memory=patches)))
    for op in [0x2f,0x30,0x57,0x58]:
        for value in ([0,15,-4] if op>=0x57 else [0]):
            add(f'defaults-{op:x}-{value}',0x12b690,op,[put(cursor,struct.pack('>i',value))])
    for op in [0x59,0x5a,0x5b,0x5c]:
        for value in ([4,15,-4] if op<0x5b else [0,4,15,-4]):
            add(f'fade-{op:x}-{value}',0x12ba68 if op<0x5b else 0x12b300,op,
                [put(cursor,struct.pack('>i',value))])
    for op in [0x31,0x32]:
        for count in [0,6]:
            base=manager+0x2f0+(12 if op==0x32 else 0)
            add(f'apply-{op:x}-last-{count}',0x12ba68,op,
                [word(base+4*i,max(0,u(pool+4)-count)) for i,pool in enumerate(pools)]+
                [put(base+8,struct.pack('<f',-4.25 if op==0x32 else 7.75))])
    add('both-lanes-wait',0x12bdd0,0x14,[])
    first_pool=next(p for p in pools if u(p+4))
    add('pending-node-rewinds',0x12bdd0,0x14,
        [put(u(first_pool+8)+4,struct.pack('<ff',45.5,4.0))])
    for lane in [0,1]:
        patches=[word(pool+4,0) for pool in pools]
        if u(pools[lane]+4):
            patches[lane]=word(pools[lane]+4,1)
            patches.append(put(u(pools[lane]+8)+4,struct.pack('<ff',128,2.5)))
        add(f'finished-lane-{lane}',0x12bdd0,0x14,patches)
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in regions]
    plan['cases']=cases
    (ROOT/'analysis/ghidra/oracle-glyph-fade-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(f'{len(cases)} opcode, range and wait cases')


if __name__=='__main__':main()
