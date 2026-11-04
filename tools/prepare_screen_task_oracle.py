"""Prepare original task-update, pause, script wait and rewind differential cases."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-font-pointer-v1/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('Original RAM changed')
    def read(a):return struct.unpack_from('<I',ram,a)[0]
    def blob(a,b):return dict(address=hex(a),hex=b.hex(),reason='Controlled source screen task state')
    def word(a,w):return blob(a,struct.pack('<I',w&0xffffffff))
    manager=read(0x235e40);task=read(0x2388bc);data=0x360100;script=read(manager+0x38)
    common=[word(task,1),word(task+4,0),word(task+44,data),word(0x236104,0),word(0x236110,0),
            word(0x236100,0),word(manager+0x2d0,1),word(manager+0x2d4,task),word(manager+0x2d8,19),
            word(manager+0x2dc,7),word(0x20625c,45)]
    cases=[]
    def add(name,entry,self,patches,ret=False):
        cases.append(dict(id=name,function_address=hex(entry),return_defined=ret,
                          input=dict(registers=dict(a0=hex(self),a1='0x14',fcsr='0x0',f20='0x0'),
                                     memory=common+patches)))
    for phase,value,hold,step,extra in [(0,255,0,255,[]),(0,5,3,1,[]),(1,0,4,1,[]),(1,0,0,1,[]),
                                       (2,251,0,4,[]),(2,244,0,4,[]),(0,64,0,4,[word(0x236104,2)])]:
        add(f'fog-{phase}-{value}-{hold}',0x18e978,task,
            [blob(data,struct.pack('<iifffiii',phase,hold,value,step,step,5,130,255)),*extra])
    for value,grow,step,extra in [(128,0,4,[]),(1.5,125,1,[]),(2,127,1,[]),(64,64,1,[word(0x236110,1)])]:
        add(f'blend-{value}-{grow}',0x18ed90,task,[blob(data,struct.pack('<fff',value,grow,step)),*extra])
    for value in (0,1):add(f'wait-task-{value}',0x1266b8,0,[word(manager+0x2d0,value)],True)
    for gate,busy in [(0,0),(0,1),(1,1)]:
        add(f'command-rewinds-{gate}-{busy}',0x1269a8,0,[word(0x2062b8,gate),word(manager+0x2d0,busy)],True)
    for prior in [44,43]:add(f'capture-previous-{prior}',0x13d098,0,[word(0x236100,prior)],True)
    plan['observed_regions']=[dict(name=n,address=hex(a),size=size) for n,a,size in (
        ('task',task,48),('payload',data,32),('manager',manager+0x2d0,24),('capture',0x236100,32),
        ('capture-tick',0x236190,4),('cursor',script+0xd8,4))]
    plan['cases']=cases
    (ROOT/'analysis/ghidra/oracle-screen-task-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(f'{len(cases)} original screen task, pause and retry conditions')


if __name__=='__main__':main()
