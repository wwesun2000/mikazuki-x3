"""Run the four retail 192080 update functions with controlled page and capture states."""
import json
import hashlib
import struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-screen-task-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('Unexpected original RAM')
    word=lambda a:struct.unpack_from('<I',ram,a)[0]
    manager=word(0x235e40);task=word(0x2388bc);data=0x360100
    def patch(a,b):return dict(address=hex(a),hex=b.hex(),reason='Declared original page transition fixture')
    def w(a,v):return patch(a,struct.pack('<I',v))
    regions=[('mode-two-task',task,48),('all-eight-polygons',data,232),('manager-wait',manager+0x2d0,16),
             ('capture',0x236100,32),('capture-tick',0x236190,4)]
    cases=[]
    for typ,e in enumerate((0x1928a8,0x192cb0,0x193008,0x193558),8):
        for ix,(angle,step,capture) in enumerate(((0,.03125,0),(.5,.03125,0),(-.015625,.03125,0),(.5,.03125,2))):
            edits=[w(task,1),w(task+4,0),w(task+20,e),w(task+24,0x192258),w(task+32,0x192460),w(task+44,data),
                   w(0x236104,capture),w(0x236110,0),w(0x236100,0),w(0x20625c,45),
                   w(manager+0x2d0,1),w(manager+0x2d4,task),w(manager+0x2d8,7),w(manager+0x2dc,9),
                   patch(data,struct.pack('<2f',angle,step)+bytes([0xa5])*224)]
            cases.append(dict(id=f'page-wipe-{typ}-{ix}',function_address=hex(e),return_defined=False,
                    input=dict(registers=dict(a0=hex(task),a1='0',a2='0',a3='0',fcsr='0'),memory=edits)))
    plan.update(cases=cases,projection_vu='retail projection macros v1',case_kind='Original eight-triangle page transitions and visible business writes',
                observed_regions=[dict(name=n,address=hex(a),size=s) for n,a,s in regions])
    (ROOT/'analysis/ghidra/oracle-screen-transition-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases))
if __name__=='__main__':main()
