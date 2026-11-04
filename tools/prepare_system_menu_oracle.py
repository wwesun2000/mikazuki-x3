"""Declare original slot 7 inputs for menu gates, focus, ownership and normal return."""
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]


def main():
    plan = json.loads((ROOT/'analysis/ghidra/oracle-manager-input-slot7-plan.json').read_bytes())
    ram = Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest() != plan['ram_sha256']:
        raise ValueError('Original slot 7 RAM changed')
    u = lambda p: struct.unpack_from('<I', ram, p)[0]
    mgr = u(0x235e40)
    owner, obj = u(mgr+0x848), u(mgr+0x84c)
    def word(p, value, reason='Declared test input'):
        return dict(address=hex(p), hex=struct.pack('<I', value).hex(), reason=reason)
    cases = []
    def case(name, entry, a0=0, a1=0, edits=(), returns=False):
        cases.append(dict(id=name, function_address=hex(entry), return_defined=returns,
                          input=dict(registers=dict(a0=hex(a0), a1=hex(a1), a2='0', a3='0'),
                                     memory=list(edits))))
    for mode in (0, 1, 2):
        case('table-'+str(mode), 0x1a1d70, edits=[word(0x235b00,mode)], returns=True)
    for focus, operation in ((0,2),(3,1),(3,2),(2,0)):
        case(f'focus-{focus}-{operation}', 0x1a1e00, operation, edits=[word(0x238904, focus)])
    case('source-gate-no-edge',0x121e50,obj,returns=True)
    device=0x1e41c60
    case('source-gate-triangle',0x121e50,obj,edits=[
        word(device+0xb4,1),word(device+0xb8,0x1000),
        dict(address=hex(device+8),hex='0010',reason='Actual held triangle')],returns=True)
    case('store-modal-owner',0x1225b0,owner,obj,returns=True)
    case('release-modal-owner',0x1225c8,owner,obj,
         [word(owner+4,1),word(owner+8,obj)],True)
    for timer, hold in ((0,0),(3,1),(1,0)):
        case(f'wait-{timer}-{hold}',0x121878,obj,edits=[
            word(obj+4,1),word(obj+12,timer),word(obj+16,hold)])
    case('task-unpause',0x17a148)
    case('restore-story-context',0x121fc8,obj,edits=[
        word(obj+4,1),word(obj+8,u(mgr+0x40)),word(owner+4,1),word(owner+8,obj)])
    for path in sorted((ROOT/'local/assets/CHART').glob('*_end.dat')):
        data=path.read_bytes()
        case('ending-loader-'+path.stem,0x1ab330,edits=[
            dict(address='0x1d00000',hex=data.hex(),reason='Unmodified original DAT'),
            word(0x238ad0,0x1d00000),word(0x238ad4,len(data))],returns=True)
    plan.update(cases=cases, case_kind='Observed slot 7 RAM plus explicit system-menu branch inputs',
                observed_regions=[dict(name=n,address=hex(p),size=s) for n,p,s in [
                    ('manager',mgr,0x860),('menu-owner',owner,12),('menu-object',obj,20),
                    ('task-list',u(0x2388bc),37*48),('root-and-settings',0x2388cc,0x54),
                    ('mode',0x235b00,4),('input-owner',0x1e497bc,40),
                    ('ending-table-and-unlocks',0x1e4bd08,0x210),('ending-state',0x2381a0,20),
                    ('consumed-slot-5',0x238ad0,8)]])
    (ROOT/'analysis/ghidra/oracle-system-menu-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print(len(cases))


if __name__ == '__main__':
    main()
