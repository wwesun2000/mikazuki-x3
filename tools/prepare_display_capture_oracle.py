"""R5900 render-pass readback into scratch GS/DMA packets, without a graphics device."""
import json
import hashlib
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-font-layout-wait-v2/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    assert hashlib.sha256(ram).hexdigest()==plan['ram_sha256']
    context=struct.unpack_from('<I',ram,0x238810)[0]
    def patch(p,value):
        return dict(address=hex(p),hex=struct.pack('<I',value).hex(),reason='Declared source readback/display register')
    cases=[]
    for mode in (0,1):
        for pending,attempts,field in [(0,0,0),(4,0,0),(2,0,0),(2,0,1),(1,1,0),(1,1,1),(2,6,0),(1,6,1)]:
            for active,pass_id in [(1,mode), (0,mode), (1,1-mode)]:
                cases.append(dict(id=f'capture-{mode}-{pending}-{attempts}-{field}-{active}-{pass_id}',
                    function_address='0x13cd20',return_defined=True,input=dict(
                        registers=dict(a0='0x360000',a1=hex(pass_id)),memory=[
                            patch(0x236104,pending),patch(0x236108,mode),patch(0x2062bc,active),
                            patch(0x23610c,attempts),patch(0x236188,6),patch(context+1416,field),
                            patch(context+1408,field)])))
    plan['cases']=cases
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in (
        ('capture',0x236104,24),('packet',0x360000,2048),
        ('dma0',0x23c210,256),('dma1',0x23c310,256))]
    (ROOT/'analysis/ghidra/oracle-display-capture-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases),'display field and GS packet cases')


if __name__=='__main__':main()
