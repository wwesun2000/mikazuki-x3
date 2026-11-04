"""Translate the retail page wipe's four updates and four triangle assembly functions."""
import hashlib
import json
import re
from generate_timechart_source import ROOT,SHA,line,operation,translate,reg

UPDATES=(0x1928a8,0x192cb0,0x193008,0x193558)
GEOMETRY=(0x1929c8,0x192da0,0x193130,0x193670)
LEAVES={0x1925f8,0x192810,0x13d098,0x17a198,0x17a1a8,0x179c80,0x10c368}
def freg(name):
    if not re.fullmatch(r'f([012]?[0-9]|3[01])',name):raise ValueError(name)
    return 'r.f['+name[1:]+']'
def fp_op(ins):
    op,p=line(ins)
    if op in ('lwc1','swc1'):
        offset,base=re.fullmatch(r'(-?0x[0-9a-f]+)\(([a-z][a-z0-9]+)\)',p[1]).groups()
        addr=f'u32({reg(base)} + ({int(offset,0)}))'
        return ([f'{freg(p[0])} = std::bit_cast<float>(u32(r.lw({addr})));'] if op=='lwc1'
                else [f'r.sw({addr},std::bit_cast<u32>({freg(p[0])}));'])
    if op=='clear' and p[0].startswith('f'):return [f'{freg(p[0])} = 0.0f;']
    if op=='mov.S':return [f'{freg(p[0])} = {freg(p[1])};']
    if op in ('add.S','sub.S'):
        return [f'{freg(p[0])} = {freg(p[1])} {"+" if op=="add.S" else "-"} {freg(p[2])};']
    if op in ('c.eq.S','c.lt.S','c.le.S'):
        operator={'c.eq.S':'==','c.lt.S':'<','c.le.S':'<='}[op]
        return [f'r.condition = {freg(p[0])} {operator} {freg(p[1])};']
    return operation(ins)
def main():
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=SHA:raise ValueError('Unexpected retail ELF')
    entries=UPDATES+GEOMETRY
    out=['// Generated from the original R5900 instructions by tools/generate_transition_source.py.','']
    out += [f'static void transition_{a:06x}(TransitionRegisters&);' for a in entries]
    for a in entries:
        folder='screen-transition-192080-v2' if a in UPDATES else 'screen-transition-geometry-v1'
        path=ROOT/'analysis/ghidra'/folder/'functions'/f'{a:08x}.json'
        units=json.loads(path.read_bytes())['disassembly']['units']
        for u in units:
            f=u['canonical_elf_file_offset']
            if not u['matches_original_elf'] or elf[f:f+4].hex()!=u['raw_hex']:raise ValueError(u['address'])
        out.extend(['']+translate(a,units,entries,LEAVES,'transition','TransitionRegisters',operations=fp_op))
    (ROOT/'port/core/screen_transition_blocks.hpp').write_text('\n'.join(out)+'\n')
if __name__=='__main__':main()
