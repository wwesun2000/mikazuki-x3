"""Select the source-resident top0000 cue and exercise its original lookup and interpreter."""
import hashlib
import json
from pathlib import Path
import struct
from scenario_resources import ResourceIndex

ROOT = Path(__file__).resolve().parents[1]


def main():
    plan = json.loads((ROOT/'analysis/ghidra/oracle-page-control-v1/input-plan.json').read_bytes())
    ram = Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest() != plan['ram_sha256']:
        raise ValueError('Original slot-7 RAM changed')
    index = ResourceIndex.from_project(ROOT)
    cue = index.resolve(0x74,'top0000_00')
    def u(a):
        return struct.unpack_from('<I',ram,a)[0]
    scene = ram.rindex(b'top0000\0')
    token = ram.rindex(b'top0000_00\0')
    group = u(scene-8)
    program = u(token+len(b'top0000_00\0'))
    raw = bytes.fromhex(cue['selected_cue']['raw_hex'])
    if ram[program:program+len(raw)] != raw or not group <= token < program:
        raise ValueError('Source-resident pointer did not resolve to original cue program')
    provider=u(0x235efc); registry=u(provider+4); script=u(u(0x235e40)+56)
    def patch(a,v):
        return dict(address=hex(a),hex=struct.pack('<I',v).hex(),reason='Declared original input condition')
    cases=[]
    def case(name,entry,args,patches=(),defined=True):
        regs={k:hex(v) for k,v in zip(('a0','a1','a2','a3'),[*args,0,0,0][:4])}
        cases.append(dict(id=name,function_address=hex(entry),return_defined=defined,input=dict(registers=regs,memory=list(patches))))
    case('find-scene-for-cue',0x101dc0,[registry,token])
    case('find-scene-missing',0x101dc0,[registry,token+2])
    case('find-program',0x101ca8,[registry,group,token])
    case('find-program-missing',0x101ca8,[registry,group,token+2])
    case('find-index',0x101928,[registry,token])
    case('find-index-cue-missing',0x101928,[registry,scene])
    case('publish-index',0x10f110,[script,token],defined=False)
    case('null-index',0x10f110,[script,0],defined=False)
    common=[patch(0x238724,program),patch(0x2062c0,0),patch(0x207100,0)]
    case('execute-source-cue',0x1397d8,[0],common,False)
    case('execute-source-cue-fallback-movie',0x1397d8,[0],common+[patch(0x2062dc,1)],False)
    case('execute-source-cue-movie-inhibited',0x1397d8,[0],common+[patch(0x23626c,1)],False)
    case('audio-stop-ring-wrap',0x140aa8,[0,0],[patch(0x23d3a0,15),patch(0x23d3a4,15)],False)
    case('audio-stop-with-fade',0x140aa8,[55,0],defined=False)
    se_name=b'pr0000_10\0'
    se_program=u(ram.rindex(se_name)+len(se_name))
    se_bytes=bytes.fromhex(index.resolve(0x74,'pr0000_10')['selected_cue']['raw_hex'])
    if ram[se_program:se_program+len(se_bytes)]!=se_bytes:raise ValueError('SE cue in RAM differs from SPK')
    # The previous 00 cue completed END cleanup. This is the following 10
    # cue's actual source program, with a declared empty retention list.
    for retained in (0,15,16):
        case(f'sound-cue-537002-retained-{retained}',0x1397d8,[0],
             [patch(0x238724,se_program),patch(0x2062c0,1),patch(0x207050,retained)],False)
    regions=[('provider',provider,0x24),('current-cue',0x23871c,12),('script-cue',script+224,4),
             ('movie-request',0x236268,16),('sound-ring',0x23d3a0,0x424),('loader',0x206250,0xeb4)]
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in regions]
    plan['cases']=cases
    plan['case_kind']='Resident source cue lookup, interpreter and playback requests; EE semaphore wrappers are outside these calls'
    path=ROOT/'analysis/ghidra/oracle-scenecue-plan.json'
    path.write_text(json.dumps(plan,indent=2)+'\n')
    print(json.dumps(dict(cases=len(cases),source_program=hex(program),source_bytes=len(raw))))


if __name__=='__main__':
    main()
