"""Original 17E288 self, including three phases and the negative-duration easing branch."""
import json
import argparse
import struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    options=argparse.ArgumentParser();options.add_argument('--factory',action='store_true')
    factory=options.parse_args().factory
    plan=json.loads((ROOT/'analysis/ghidra/oracle-choice-setup-v2/input-plan.json').read_bytes())
    mem=Path(plan['ram_input_path']).read_bytes()
    task=struct.unpack_from('<I',mem,0x2388bc)[0]+13*48
    data=0x1000400
    def patch(at,b):return dict(address=hex(at),hex=b.hex(),reason='Declared source effect_flash.c state')
    cases=[]
    for id,state,delay,value,start,end,exit_ticks in [
        ('first',0,1,255,25.5,13,20),('hit-min',0,3,66,5,10,20),
        ('no-hold',0,0,65,5,10,20),('hold',1,2,64,1,8,30),('last-hold',1,1,64,1,8,30),
        ('fade',2,0,101,5,15,17),('end',2,0,240,5,15,17),('overshoot',2,0,249,1,15,17),
        ('ease',2,0,98,5,-15,-17),('ease-end',2,0,253.99,1,-15,-17),
        ('immediate-ease',2,0,128,1,-255,-1),('other',9,1,55,1,3,85)]:
        blob=struct.pack('<IIfffiiiIi',state,delay,value,start,end,200,190,180,exit_ticks&0xffffffff,64)
        regs={f'f{i}':'0' for i in range(32)};regs.update(a0=hex(task),fcsr='0')
        row=bytearray(48);struct.pack_into('<I',row,0,1);struct.pack_into('<I',row,20,0x17e288)
        struct.pack_into('<I',row,44,data)
        cases.append(dict(id=id,function_address='0x17e288',return_defined=False,
            input=dict(registers=regs,memory=[patch(task,row),patch(data,blob)])))
    plan['cases']=cases;plan['observed_regions']=[dict(name='flash-task',address=hex(task),size=48),
        dict(name='allocation',address=hex(data),size=48)]
    path=ROOT/'analysis/ghidra/oracle-flash-plan.json'
    if factory:
        plan['isolated_platform']='single-flash-allocation-v1'
        path=ROOT/'analysis/ghidra/oracle-flash-factory-plan.json'
        cases.clear()
        for i,args in enumerate(((0,0,0,255,0,0),(4,3,10,7,8,9),(0,3,-4,12,16,255),(7,0,-16,32,128,9))):
            regs={f'f{i}':'0' for i in range(32)}
            regs.update({k:hex(v&0xffffffffffffffff) for k,v in zip(('a0','a1','a2','a3','t0','t1'),args)})
            regs['fcsr']='0'
            cases.append(dict(id=str(i),function_address='0x17e0c0',return_defined=True,
                input=dict(registers=regs,memory=[patch(task,bytes(48)),patch(data,bytes(48))])))
    path.write_text(json.dumps(plan,indent=2)+'\n')
if __name__=='__main__':main()
