"""Submit the actual ky1035b_20 stop cue to R5900 with a short and delayed schedule."""
import hashlib
import json
from pathlib import Path
import struct
from scenario_resources import ResourceIndex

ROOT=Path(__file__).resolve().parents[1]
def main():
    base=json.loads((ROOT/'analysis/ghidra/oracle-scenecue-plan.json').read_bytes())
    ram=Path(base['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=base['ram_sha256']:raise ValueError('Original EE RAM mismatch')
    name=b'ky1035b_20\0';addr=struct.unpack_from('<I',ram,ram.rindex(name)+len(name))[0]
    raw=bytes.fromhex(ResourceIndex.from_project().resolve(0x74,'ky1035b_20')['selected_cue']['raw_hex'])
    expected=struct.pack('<HHIHHHHH',0x0d,0x29,313171,0x2e,1,0x2b,30,1)
    if expected!=raw or ram[addr:addr+len(raw)]!=raw:raise ValueError('Unmatched retail SE_STOP')
    def edit(a,b):return dict(address=hex(a),hex=b.hex(),reason='Explicit original queue configuration')
    def word(a,v):return edit(a,struct.pack('<I',v))
    common=[word(0x238724,addr),word(0x2062c0,1),word(0x206dd4,2),word(0x238730,3),
            word(0x23d3a0,0),word(0x23d3a4,0),word(0x206dd0,0),word(0x206dcc,0)]
    cases=[]
    for label,delay in [('retail-immediate',0),('declared-delay',3)]:
        changes=common.copy()
        if delay:
            changes+=[edit(0x1cf0000,raw[:-2]+struct.pack('<HHH',0x28,delay,1)),word(0x238724,0x1cf0000)]
        cases.append(dict(id=label,function_address='0x1397d8',return_defined=False,
                          input=dict(registers=dict(a0='0',a1='0',a2='0',a3='0'),memory=changes)))
    base.update(cases=cases,case_kind='Original SE_STOP with blocking fade, plus declared 3-tick delayed variant')
    base['observed_regions']+=[dict(name='audio-completion-count',address='0x238730',size=4)]
    out=ROOT/'analysis/ghidra/oracle-blocking-se-plan.json';out.write_text(json.dumps(base,indent=2)+'\n')
    print(hex(addr),raw.hex())
if __name__=='__main__':main()
