"""Run the source 34/35 handler and optional close path with explicit slot-7 inputs."""
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]

def main():
    plan=json.loads((ROOT/'analysis/ghidra/oracle-page-control-v1/input-plan.json').read_bytes())
    ram=Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest()!=plan['ram_sha256']:raise ValueError('Source RAM identity changed')
    u=lambda a:struct.unpack_from('<I',ram,a)[0]
    manager=u(0x235e40); script=u(manager+0x38); label=u(script+0xd4)
    table=u(script+0x138); record=table+8*label; named=table+8*12
    def patch(a,v):return dict(address=hex(a),hex=struct.pack('<I',v).hex(),reason='Declared input condition')
    cases=[]
    def case(name,entry,object_,a1,patches=(),a3=0,defined=False):
        regs=dict(a0=hex(object_),a1=hex(a1),a2='0',a3=hex(a3))
        cases.append(dict(id=name,function_address=hex(entry),return_defined=defined,
                          input=dict(registers=regs,memory=list(patches))))
    for opcode in (0x34,0x35):
        case('slot15-'+hex(opcode),0x132bd0,u(manager+0x5c+4*opcode),u(manager+0x40),a3=opcode,defined=True)
    case('ignored-opcode',0x132a08,0,99,defined=True)
    common=[patch(record,(u(record)&~0x20003fff)|12),patch(record+4,(u(record+4)&~31)|17)]
    for name,pending,valid,match in [('match',0,1,True),('mismatch',0,1,False),('invalid',0,0,True),('deferred',1,1,True)]:
        case('open-'+name,0x114aa0,manager+0x32c,0,common+[patch(script+0x150,pending),patch(script+0x170,valid),
             patch(script+0x174,12 if match else 7),patch(script+0x178,5),patch(script+0x17c,11)])
    for valid in (0,1):
        data=[patch(script+0x158,12),patch(script+0x15c,valid),patch(script+0x160,0x123),patch(script+0x164,17)]
        case(f'close-immediate-{valid}',0x114ae0,manager+0x32c,0,data)
        case(f'close-deferred-{valid}',0x114ae0,manager+0x32c,1,data)
    plan['cases']=cases
    plan['observed_regions']=[dict(name=n,address=hex(a),size=s) for n,a,s in [
        ('script',script,512),('manager',manager,2144),('current-record',record,8),('named-record',named,8),('global',0x235b3c,4)]]
    plan['case_kind']='Original record scope, actual inputs and listed branch/restore mutations'
    (ROOT/'analysis/ghidra/oracle-record-scope-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases))

if __name__=='__main__':main()
