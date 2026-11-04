"""Audit actual pr01_0110 operands and saved choice state by running the original handlers."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-font-layout-wait-v2/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    source=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
    assert hashlib.sha256(source).hexdigest()=='f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3'
    assert hashlib.sha256(ram).hexdigest()==plan['ram_sha256']
    def u(a):return struct.unpack_from('<I',ram,a)[0]
    def patch(a,v):return dict(address=hex(a),hex=struct.pack('<I',v).hex(),reason='Declared choice phase or original script position')
    manager=u(0x235e40);script=u(manager+56);font=u(manager+60);choice=u(manager+8);control=u(manager+40)
    original=source[0xa259c:0xa259c+28]
    assert original==bytes.fromhex('6c1b010200000f707230315f3031313500000d706b30315f30303130')
    code=ram.index(original);cases=[]
    common=[patch(manager+0x40,u(0x235f3c)),patch(script+0xd0,15),patch(script+0xd4,2551),
            patch(script+0xd8,code+1),patch(manager+0x808,0),patch(control+16,0)]
    def add(name,e,self=0,a1=0,mem=(),ret=True):
        regs={f'f{i}':'0x0' for i in range(32)}
        regs.update(a0=hex(self),a1=hex(a1),fcsr='0x0')
        cases.append(dict(id=name,function_address=hex(e),return_defined=ret,input=dict(registers=regs,memory=list(mem))))
    add('source-two-options',0x125778,mem=common+[patch(script+0x148,1)])
    add('source-choice-readback-record-provider',0x125778,mem=common+[patch(u(manager+4)+4,1)])
    add('preview-color-counts',0x131930)
    add('preview-mode-color',0x131930,mem=[patch(manager+0x744,1)])
    add('preview-option-transfer',0x132070)
    posstack=u(font+52);stylestack=u(font+44)
    stacked=[patch(posstack+4,2),patch(stylestack+4,2),patch(u(posstack+8),u(font+16)),
             patch(u(posstack+8)+4,u(font+20)),patch(u(stylestack+8),0),patch(u(stylestack+8)+4,24)]
    for index in [0,u(choice+4)-1]:
        add(f'preview-finish-{index}',0x125f90,mem=stacked+[patch(choice+8,index)])
    preview=u(0x235f08);base=u(u(script+8+32*4)+0x430)
    common=[patch(manager+0x40,preview),patch(script+0xd0,32)]
    for offset in [0,5,7,8]:
        add(f'preview-dispatch-template-{offset}',0x11e9e0,preview,manager,common+[patch(script+0xd8,base+offset)])
    for simple in (0x125f38,0x1261e0):
        add('exit-'+hex(simple),simple,mem=[patch(control+20,1)],ret=simple==0x1261e0)
    pool=u(0x2388bc);task=u(manager+0x58)
    for entry in (0x17d3e0,0x17d418):
        for current,goal in ((2.0,3.0),(4.0,7.5),(10.0,1.0)):
            def f(value):return struct.unpack('<I',struct.pack('<f',value))[0]
            add(f'overlay-{entry:x}-{current}-{goal}',entry,task,
                mem=[patch(u(task+44)+16,f(current)),patch(u(task+44)+20,f(goal))],ret=False)
    regions=[('manager',manager,0x858),('choice',choice,0x1d4),('script',script,0x188),
             ('font',font,56),('primary',u(font),40),('ruby',u(font+4),40),
             ('task',task,48),('task-payload',u(task+44),32),('pointer',0x1e44378,188),
             ('slots',pool,48*37)]
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in regions]
    plan['cases']=cases
    (ROOT/'analysis/ghidra/oracle-choice-setup-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(f'{len(cases)} original setup, preview dispatcher/handler and finish cases')


if __name__=='__main__':main()
