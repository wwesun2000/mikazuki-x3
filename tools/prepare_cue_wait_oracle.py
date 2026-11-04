"""Describe operand and ring inputs for the R5900 differential. No expected output is supplied."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'analysis/ghidra/oracle-text-styles-v1/input-plan.json'


def main():
    plan = json.loads(BASE.read_bytes())
    cases = []

    def make(name, entry, args, words):
        memory = [dict(address=hex(addr), hex=(value & 0xffffffff).to_bytes(4, 'little').hex(),
                       reason='Declared input to original function') for addr, value in words.items()]
        registers = {f'a{i}': hex(value) for i, value in enumerate(args)}
        cases.append(dict(id=name, function_address=hex(entry), return_defined=True,
                          input=dict(registers=registers, memory=memory)))

    for op in [0x5d, 0x5f, 0x61, 0x63, 0x52]:
        for margin in [11, 270]:
            make(f'margin-{op:02x}-{margin}', 0x12a268, [0, op], {0x1e10e18: 0x1f80000, 0x1f80000: margin})

    rings = [0x23d3a0, 0x23d7c4]
    for worker, base in enumerate(rings):
        for target in [0x140360, 0x1403c0, 0x140478, 0x1405d8, 0x140680, 0x140728, 0x140540]:
            writes = {addr+offset: 0 for addr in rings for offset in [0, 4]}
            writes.update({base: 15, base+4: 1, base+8+15*4: 0x140aa8, base+8: target})
            make(f'worker-{worker}-wrap-{target:x}', 0x140118, [], writes)

    for mask, callback, flags in [(1,0x140478,1), (4,0x140478,1), (1,0,1), (4,0x1397b0,4)]:
        make(f'delay-{mask}-{callback:x}-{flags}', 0x1390a8, [mask], {
            0x206dcc: 1, 0x206dd0: 7, 0x206ddc+7*52: 0, 0x206ddc: callback, 0x206de8: flags})
    make('no-last-oneshot', 0x1b1f80, [], {0x2389d8: 0xffffffff, 0x2389dc: 17})
    plan['cases'] = cases
    plan['case_kind'] = 'Slot 7 isolated active font area, both wrapped worker rings and delayed callback flags'
    plan['observed_regions'] += [dict(name=name,address=hex(address),size=size) for name,address,size in [
        ('sound-rings', rings[0], 2*0x424), ('cue-delay-ring',0x206dc8,16+8*52), ('one-shot-status',0x2389d8,8)]]
    path = ROOT / 'analysis/ghidra/oracle-cue-wait-font-plan.json'
    path.write_text(json.dumps(plan, indent=2)+'\n',encoding='utf-8')
    print(path)


if __name__ == '__main__':
    main()
