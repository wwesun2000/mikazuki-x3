"""Original slot7 page/wait inputs and declared branch patches only."""
import hashlib,json,struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    base=json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_text())
    ram=Path(base['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=base['ram_sha256']:raise ValueError('Source RAM changed')
    u=lambda a:struct.unpack_from('<I',ram,a)[0]
    m=u(0x235e40);s=u(m+0x38);font=u(m+0x3c);fmt=u(font);hint=u(m+0x20);obj=u(m+0x2c);helper=u(m+0x24)
    default=u(0x235f3c);wait0b=u(0x235f38);wait09=u(0x235f34);label=u(s+0xd4)
    def patch(a,value,n=4,reason='Declared source condition'):
        return dict(address=hex(a),hex=value.to_bytes(n,'little').hex(),reason=reason)
    rows=[]
    def case(name,entry,self,a1=0,a2=0,a3=0,patches=None,defined=True):
        rows.append(dict(id=name,function_address=hex(entry),return_defined=defined,input=dict(
            registers={k:hex(v) for k,v in dict(a0=self,a1=a1,a2=a2,a3=a3).items()},memory=patches or [])))
    for op in (11,12):
        for mark in (0,1):
            case(f'page-{op:02x}-mark-{mark}',0x1243e8,u(m+0x5c+op*4),default,0,op,
                 [patch(m+0x40,default),patch(m+0x2c0,mark)])
    case('page-0b-wrap-tip',0x1243e8,u(m+0x5c+11*4),default,0,11,
         [patch(m+0x40,default),patch(fmt+4,u(font+24)-8)])
    case('page-0c-redirect',0x1243e8,u(m+0x5c+12*4),default,0,12,
         [patch(m+0x40,default),patch(obj,1),patch(obj+12,18),patch(obj+16,2835)])
    case('page-0b-autoplay-reset',0x1243e8,u(m+0x5c+11*4),default,0,11,
         [patch(m+0x40,default),patch(m+0x808,1),patch(m+0x810,23),patch(m+0x814,7)])
    case('page-0b-readback-redirect',0x1243e8,u(m+0x5c+11*4),default,0,11,
         [patch(m+0x40,default),patch(hint+4,1),patch(hint+8,1),patch(hint+16,18),patch(hint+20,u(u(m+8)+0x20))])
    for recording in (0,1):case(f'visit-recording-{recording}',0x123600,0,patches=[patch(s+0x168,recording)],defined=False)
    case('clear-real-glyphs',0x1114f8,m,defined=False)
    case('clear-active-timer',0x1114f8,m,patches=[patch(m+0x2e8,1),patch(m+0x2ec,27),patch(font+32,5)],defined=False)
    for entry,ctx in [(0x120030,wait0b),(0x11fe80,wait09)]:
        for mask in (0,0x2000):
            case(f'wait-{entry:x}-edge-{mask:04x}',entry,ctx,m,patches=[patch(m+0x40,ctx),patch(0x1e41d14,0),patch(0x1e41d1c,mask,2)])
    case('wait-autoplay-final',0x120030,wait0b,m,patches=[patch(m+0x40,wait0b),patch(m+0x808,1),patch(m+0x814,1),patch(0x1e41d14,0),patch(0x1e41d1c,0,2)])
    case('wait-object24-clock',0x120030,wait0b,m,patches=[patch(m+0x40,wait0b),patch(helper,1),patch(helper+12,4),patch(helper+16,3)])
    for name,data in [('stop',b'\x04'),('first-character',bytes.fromhex('022182a0')),('pad',bytes.fromhex('46084d000a04'))]:
        case('wait09-'+name,0x123448,u(m+0x5c+9*4),default,0,9,
             [patch(m+0x40,default),dict(address=hex(u(s+0xd8)),hex=data.hex(),reason='Explicit original opcode shape for bounded prepass')])
    extra=[('hint',hint,64),('page-secondary',u(m+0x30),32),('page-redirect',obj,32),('wait-clock',helper,32),
           ('font',font,0x40),('primary-format',fmt,0x28),('ruby-format',u(font+4),0x28),
           ('history',u(s+0x138),u(s+0x134)*8),('chapter-globals',0x237f80,0x30),('chapter-names',0x1e4abb0,32)]
    for lane in [0,1]:
        channel=u(font+8+4*lane);extra.extend([(f'channel-{lane}',channel,0x30),(f'pool-{lane}',u(channel),16)])
    base['observed_regions'] += [dict(name=n,address=hex(a),size=size) for n,a,size in extra]
    base['cases']=rows;base['case_kind']='Page handlers, clear, wait context confirm and09 prepass on original slot7 plus listed branch inputs'
    out=ROOT/'analysis/ghidra/oracle-page-control-plan.json';out.write_text(json.dumps(base,indent=2)+'\n');print(out,len(rows))

if __name__=='__main__':main()
