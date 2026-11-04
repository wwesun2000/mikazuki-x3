"""Against original slot-7 memory, exercise the registered full-screen mesh grid and change paths."""
from pathlib import Path
import json
import argparse
import struct

ROOT=Path(__file__).resolve().parents[1]
def main():
    options=argparse.ArgumentParser();options.add_argument('--factory',action='store_true')
    factory=options.parse_args().factory
    plan=json.loads((ROOT/'analysis/ghidra/oracle-snow-platform-v1/input-plan.json').read_bytes())
    mem=Path(plan['ram_input_path']).read_bytes()
    task=struct.unpack_from('<I',mem,0x2388bc)[0]+13*48
    data=0x1410000;grid=data+128
    def patch(at,b):return dict(address=hex(at),hex=b.hex(),reason='Source 17C498 fixture, with 10x10 grid')
    cases=[]
    for index,(entry,ticks,left,factor) in enumerate([
        (0x17c498,0,3,0.01),(0x17c498,2,1,0.05),(0x17c498,9,4,0.02),
        (0x17c598,0,10,1),(0x17c598,7,1,1),(0x17c598,7,0,1)]):
        row=bytearray(48);struct.pack_into('<I',row,0,1);struct.pack_into('<I',row,20,entry)
        struct.pack_into('<I',row,44,data)
        payload=struct.pack('<II11fIfIII3fI',10,10,640/9,224/9,110,93,128,100,80,147,-4,-5,7,left,factor,10,ticks,0,0,0,0,grid)
        nodes=bytearray()
        for i in range(100):
            x,y=(i%10)*640/9,(i//10)*224/9
            nodes.extend(struct.pack('<9f',x,y,x+.25,y+.75,x+2.75,y-.75,(i-49)/16, x/1024,y/256))
        regs={f'f{i}':'0' for i in range(32)};regs.update(fcsr='0',a0=hex(task))
        cases.append(dict(id=f'update-{index}-{ticks}',function_address=hex(entry),return_defined=False,input=dict(
            registers=regs,memory=[patch(task,row),patch(data,payload),patch(grid,nodes),
                patch(0x20c7d0,struct.pack('<4I',17,0xffffffff,0,0))])))
    plan['cases']=cases;plan['observed_regions']=[dict(name='mesh-task',address=hex(task),size=48),
        dict(name='working-mesh',address=hex(data),size=3728),dict(name='MT-state',address='0x1e497e8',size=624*4)]
    target=ROOT/'analysis/ghidra/oracle-mime-plan.json'
    if factory:
        cases.clear();target=ROOT/'analysis/ghidra/oracle-mime-factory-plan.json'
        plan['isolated_platform']='mesh-heap-and-EE-kernel-v1'
        for i,args in enumerate(((0,80,80,80,700),(40,150,25,15,300))):
            regs={f'f{i}':'0' for i in range(32)};regs.update(fcsr='0')
            regs.update({k:hex(v) for k,v in zip(('a0','a1','a2','a3','t0'),args)})
            cases.append(dict(id=f'create-{i}',function_address='0x17ba58',return_defined=True,
                input=dict(registers=regs,memory=[patch(task,bytes(48)),patch(data,bytes([0xa5])*3728),
                    patch(0x20c7d0,struct.pack('<4I',17,0xffffffff,0,0))])))
    target.write_text(json.dumps(plan,indent=2)+'\n')
if __name__=='__main__':main()
