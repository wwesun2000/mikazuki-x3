"""Run the original chart matrix and handlers on an unmodified observed game-state payload."""
import hashlib
import json
from pathlib import Path
import struct


ROOT=Path(__file__).resolve().parents[1]
def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('RAM identity mismatch')
    u=lambda p: struct.unpack_from('<I',ram,p)[0]
    cases=[]
    def case(name,entry,a0=0,edits=(),defined=False):
        cases.append(dict(id=name,function_address=hex(entry),return_defined=defined,
                          input=dict(registers=dict(a0=hex(a0),a1='0',a2='0',a3='0'),memory=list(edits))))
    def patch(p,v):
        return dict(address=hex(p),hex=struct.pack('<I',v).hex(),reason='Declared chart input')
    case('prepare-visible-chart',0x1adbd8)
    case('build-current-time-and-actors',0x1ad2c0,defined=True)
    case('evaluate-first-condition-group',0x1ac860,u(0x1e4bf28))
    case('open-chart-viewer',0x1adcd0)
    case('close-chart-viewer',0x1add08,edits=[patch(0x2381d4,1)])
    case('idle-chart',0x1add40,edits=[patch(0x2381d4,1),patch(0x1e41c60+0xb4,1),
                                      patch(0x1e41c60+0xb8,0),patch(0x1e41c60+0xf0,1),
                                      patch(0x1e41c60+0x100,0)],defined=True)
    case('ready-replay-label',0x1ae388,defined=True)
    plan['cases']=cases
    plan['case_kind']='Observed original slot 7 chart buffers; open/close and zero controller inputs declared separately'
    plan['observed_regions']=[dict(name=n,address=hex(p),size=l) for n,p,l in (
        ('chart-globals',0x2381b8,44),('indexed-time-tables',0x238954,84),('variables',0x238af0,1024),
        ('chart-viewer',u(0x2381dc),32),('primary-matrix',u(0x2381c4),(u(0x238960)+1)*88),
        ('second-matrix',u(0x2381c8),(u(0x238960)+1)*88),('PS2-pad',0x1e41c60,0x130))]
    (ROOT/'analysis/ghidra/oracle-timechart-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases),hex(u(0x2381b8)),u(0x238960))


if __name__=='__main__':main()
