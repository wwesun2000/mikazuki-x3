"""Original snow updates on controlled particles, including adjacent untouched bytes."""
import json
import struct
import argparse
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def main():
    options=argparse.ArgumentParser();options.add_argument('--platform',action='store_true')
    platform=options.parse_args().platform
    plan=json.loads((ROOT/'analysis/ghidra/oracle-choice-setup-v2/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    def u(a):return struct.unpack_from('<I',ram,a)[0]
    def patch(p,data):return dict(address=hex(p),hex=data.hex(),reason='Declared 1833F8 particle state')
    pool=u(0x2388bc);task=pool+13*48;data=0x1410000;cases=[]
    common=[patch(task+44,struct.pack('<I',data))]
    for name,particles,wind,target in [
            ('empty',[],2.5,3.0),('one',[(100,45,0,8,2,8,5,0.4)],3.75,5.3),
            ('negative',[(560,225,-1,-8,5,14,4,0.7)],-3.5,-7.1),
            ('edges',[(9,110,-1,-20,3,7.3,2,0.55),(130,350,3,20,4,15.0,3,0.8)],0.7,6.5),
            ('mixed',[(0,60,-14.3,8.8,0.7,7.1,6,0.41),(580,398,3.25,8.1,3.5,17.93,4.2,0.65)],7.4,-2)]:
        blob=struct.pack('<IfffI',len(particles),wind,target,10,80)+b''.join(struct.pack('<8f',*p) for p in particles)
        registers={f'f{i}':'0x0' for i in range(32)};registers.update(a0=hex(task),fcsr='0')
        cases.append(dict(id=name,function_address='0x1833f8',return_defined=False,
                   input=dict(registers=registers,memory=[*common,patch(data,blob)])))
    if platform:
        plan['isolated_platform']='particle-heap-and-EE-kernel-v1'
        kernel=[patch(0x20c7d0,struct.pack('<IIII',17,0xffffffff,0,0))]
        regs={f'f{i}':'0x0' for i in range(32)};regs.update(a0=hex(task),fcsr='0')
        for name,particle,counter in (
            ('threshold',(100,50,0,23,1,7,5,0.4),40),
            ('respawn',(110,446,2.1,19,3,17,6,0.75),1),
            ('reverse',(600,2,-3,-24,5,-1,4,0.9),150)):
            blob=struct.pack('<IfffI8f',1,3.5,-2.25,9,counter,*particle)
            cases.append(dict(id=name,function_address='0x1833f8',return_defined=False,
                input=dict(registers=regs,memory=[*kernel,*common,patch(data,blob)])))
        for count,wind in ((0,0),(1,15),(3,-9)):
            registers={**regs,'a0':hex(count),'a1':hex(wind&0xffffffffffffffff)}
            cases.append(dict(id=f'create-{count}-{wind}',function_address='0x183258',return_defined=True,
                input=dict(registers=registers,memory=[*kernel,patch(task,struct.pack('<I',0))])))
    plan['observed_regions']=[dict(name='particle-task',address=hex(task),size=48),
                              dict(name='particle-payload',address=hex(data),size=116),
                              dict(name='MT-state',address='0x1e497e8',size=4*624),dict(name='mutex',address='0x20c7d0',size=16)]
    plan['cases']=cases
    (ROOT/'analysis/ghidra/oracle-snow-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases),'particle update cases')

if __name__=='__main__':main()
