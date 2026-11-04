"""Feed the original 146960..146C18 code real SAB headers and guarded queue cases."""
import json
import argparse
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def main():
    options=argparse.ArgumentParser();options.add_argument('--draw',action='store_true')
    draw=options.parse_args().draw
    plan=json.loads((ROOT/'analysis/ghidra/oracle-choice-setup-v2/input-plan.json').read_bytes())
    obj=0x2062e0
    src=0x1830100
    other=0x1840100
    def patch(at,data):
        return dict(address=hex(at),hex=data.hex(),reason='Source SAB header or declared queue input')
    def w(*v): return struct.pack('<'+'I'*len(v),*v)
    def f(v): return struct.unpack('<I',struct.pack('<f',v))[0]
    base=[]
    for ptr,name in ((src,'my0034a.sab'),(other,'my0036b.sab')):
        data=(ROOT/'local/assets/SANM'/name).read_bytes();h=int.from_bytes(data[:4],'little')
        base.extend((patch(ptr,data[:32]),patch(ptr+h,data[h:])))
    cases=[]
    def case(name,entry,args=(),state=(),ret=False):
        registers={f'f{i}':'0x0' for i in range(32)}
        registers.update(fcsr='0',**{f'a{i}':hex(arg) for i,arg in enumerate(args)})
        cases.append(dict(id=name,function_address=hex(entry),return_defined=ret,input=dict(
            registers=registers,memory=[*base,patch(obj,bytes(0x90)),*[patch(obj+k,w(*v)) for k,*v in state]])))
    case('bind-one',0x146960,(obj,src));case('bind-sixty',0x146960,(obj,other))
    case('start',0x1397b0,(src,));case('enqueue',0x146b50,(obj,src,1))
    case('start-at-end',0x146b50,(obj,other,2))
    case('defer',0x146b50,(obj,src,1),[(0,other),(0x4c,1)])
    case('ended',0x146b50,(obj,src,1),[(0,other),(0x54,1)])
    case('full-ring',0x146b50,(obj,src,1),[(0x44,0,7)])
    case('wrap-consume',0x1469e0,(obj,),[(0x44,7,1),(4,other),(32,src),(0x40,2)])
    case('force-drain',0x146c18,(obj,),[(0,other),(0x44,7,1),(4,other),(32,src)])
    case('force-no-queue',0x146c18,(obj,),[(0,src),(0x78,37),(0x54,1)])
    case('force-inactive',0x146c18,(obj,))
    for n,source,active,length,pos in (('no-file',0,1,1,0),('disabled',src,0,20,0),
            ('still-playing',src,1,60,59.5),('at-end',src,1,60,60),('past-end',src,1,1,1.5)):
        case(n,0x146be0,(obj,),[(0,source),(0x4c,active),(0x64,f(pos)),(0x78,length)],True)
    plan['cases']=cases
    plan['observed_regions']=[dict(name='source-player-and-guards',address=hex(obj-16),size=0xb0)]
    path=ROOT/'analysis/ghidra/oracle-sab-plan.json'
    if draw:
        cases.clear()
        for name,index,phase in (('my0036a',0,1.5),('my0006a',1,1.5)):
            data=(ROOT/'local/assets/SANM'/(name+'.sab')).read_bytes()
            u=lambda o:int.from_bytes(data[o:o+4],'little')
            h=u(0);regs={f'f{i}':'0' for i in range(32)}
            regs.update(a0='0x1100000',a1=hex(obj),a2='0x10ff000',fcsr='0')
            state=bytearray(0x90)
            for at,val in ((0,src),(0x4c,1),(0x50,u(h+4)>>16),(0x64,f(phase)),
                (0x68,src+h),(0x6c,src),(0x74,src+h+28),(0x78,u(h+12)),(0x80,2),
                (0x84,src+u(h+16)),(0x88,src+u(h+20)),(0x8c,u(h+24))):struct.pack_into('<I',state,at,val)
            row=u(h+28+4*index)
            cases.append(dict(id=name,function_address='0x146f78',return_defined=True,input=dict(
                registers=regs,memory=[patch(obj,state),patch(src,data[:32]),patch(src+h,data[h:]),
                                       patch(src+row,data[row:row+56]),patch(0x1100000,bytes(16384))])))
        plan['observed_regions'].extend([dict(name='source-gif-chain',address='0x1100000',size=16384),
            dict(name='end-signal',address='0x10ff000',size=4)])
        path=ROOT/'analysis/ghidra/oracle-sab-draw-plan.json'
    path.write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases),'original SAB cases')
if __name__=='__main__':main()
