"""Original VM-state samples for the Name keyboard and the time-chart save callback."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]
def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('Original RAM identity changed')
    u=lambda p:struct.unpack_from('<I',ram,p)[0]
    editor=u(0x235ed0);manager=u(0x235e40);script=u(manager+0x38);cases=[]
    def edit(p,v,n=4):
        return dict(address=hex(p),hex=v.to_bytes(n,'little').hex(),reason='Explicit original controller/editor input')
    def case(name,entry,args,edits,defined=False):
        a,b=args
        cases.append(dict(id=name,function_address=hex(entry),return_defined=defined,
                          input=dict(registers=dict(a0=hex(a),a1=hex(b),a2='0',a3='0'),memory=edits)))
    for held,x,y,page,repeat in [(0,0,0,0,8),(0x20,0,0,0,8),(0x80,0,0,0,8),(0x40,5,7,0,8),
                                (0x10,0,0,1,8),(0x90,7,1,1,8),(0x20,14,0,0,3)]:
        values={4:0,0x24:2,0x28:repeat,0x50:page,0x54:0,0x60:x,100:y,0x68:x}
        changes=[edit(editor+k,v) for k,v in values.items()]+[edit(0x1e41c68,held,2),edit(0x1e497e0,0)]
        case(f'cursor-{held}-{x}-{y}-{page}-{repeat}',0x11b930,(editor,0),changes)
    for n in (0,1,5,6):
        for entry in (0x11b100,0x11b1b0):
            patches=[edit(editor+8,0),edit(editor+0x2c,min(n,5)),
                     dict(address=hex(script+0xe4),hex=('82a0'*n)+'00',reason='Original-encodable character string')]
            case(f'characters-{n}-{entry:x}',entry,(editor,0x82a2),patches)
    case('card-header-original-chart',0x1ad3d8,(0x1d00000,0x1d00004),[],True)
    for opcode in (2,0x1b,9,0x50):
        cursor=u(script+0xd8)
        inputs=[dict(address=hex(cursor),hex=bytes([opcode,0,0,0,0,0]).hex(),reason='Explicit source opcode and zero operands')]
        if opcode==0x1b:
            # The original 1B returns from a template. Snapshot 7 is an
            # ordinary choice, so provide a valid source caller frame.
            inputs.extend([edit(manager+0x2c4,u(script+0xd0)),edit(manager+0x2c8,0),
                           edit(manager+0x2cc,u(0x235f3c))])
        case(f'special-context-{opcode:02x}',0x120528,(u(0x235f40),manager),inputs,True)
    plan['cases']=cases
    plan['case_kind']='Slot 7 constructed keyboard plus declared controls; raw game-variable timeline save callback'
    plan['observed_regions']=[dict(name=n,address=hex(p),size=l) for n,p,l in [
        ('name-editor',editor,0x78),('script-data',script,0x188),('name-template',u(script+0xb0),0x443),
        ('chart-save-out',0x1d00000,8),('second-chart-matrix',u(0x2381c8),(u(0x238960)+1)*88)]]
    (ROOT/'analysis/ghidra/oracle-name-editor-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases))

if __name__=='__main__':main()
