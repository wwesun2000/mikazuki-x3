"""Statically translate the closed, scalar SN4G time-chart functions from signed Ghidra dossiers."""
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
ENTRIES = [0x1ac690,0x1ac7c0,0x1ac860,0x1aca08,0x1ad2c0,0x1ad3d8,0x1ad758,0x1ad768,0x1ad8d8,0x1ad930,
           0x1ad970,0x1ad9c0,0x1ada28,0x1ada40,0x1adbd8,0x1adcd0,0x1add08,0x1add40,0x1ae388]
LEAVES = {0x100ec8,0x100ee0,0x10c898,0x14bd18,0x15f528,0x15fde0,0x15fe30,0x15ff88,0x175f78,
          0x19cf38,0x1b15f0,0x1fc490,0x1fda0c}


def reg(value):
    if value == 'zero': return '0u'
    if not re.fullmatch(r'(?:[vaskt][0-9]|ra|sp|gp|at|lo1|hi1)',value):
        raise ValueError('Unknown source register '+value)
    return 'r.'+value


def immediate(value):
    return str(int(value,0))


def line(text):
    op,*tail=text.lstrip('_').split(' ',1)
    return op,tail[0].split(',') if tail else []


def operation(text):
    op,p=line(text)
    if op=='nop':return []
    dest=reg(p[0])
    if op in ('lb','lbu','lhu','lw','ld','sb','sh','sw','sd'):
        z=re.fullmatch(r'(-?0x[0-9a-f]+)\(([a-z][a-z0-9]+)\)',p[1])
        if not z:raise ValueError(text)
        displacement,base=z.groups()
        address=f'u32({reg(base)} + ({immediate(displacement)}))'
        if op in ('sb','sh','sw','sd'):return [f'r.{op}({address}, {dest});']
        expr=f'r.{op}({address})'
    elif op in ('movz','movn'):
        sense='==' if op=='movz' else '!='
        return [f'if ({reg(p[2])} {sense} 0) {dest} = {reg(p[1])};']
    elif op in ('mtlo1','mthi1'):return [f'r.{op[2:]} = {dest};']
    elif op in ('mflo1','mfhi1'):expr='r.'+op[2:]
    elif op=='move':expr=reg(p[1])
    elif op=='li':expr=f'sx32({immediate(p[1])})'
    elif op=='lui':expr=f'sx32(u32({immediate(p[1])}) << 16)'
    elif op in ('srl','sra','sll','srav','sllv'):
        amount=immediate(p[2]) if op not in ('srav','sllv') else f'({reg(p[2])} & 31)'
        v=f's32({reg(p[1])})' if op in ('sra','srav') else f'u32({reg(p[1])})'
        expr=f'sx32({v} {"<<" if op in ("sll","sllv") else ">>"} {amount})'
    elif op in ('addiu','addu','subu','and','or','andi','xori','slt','slti','sltu','sltiu','ori','xor'):
        right=immediate(p[2]) if op in ('addiu','andi','xori','slti','sltiu','ori') else reg(p[2])
        left=reg(p[1])
        if op in ('slt','slti'):
            expr=f's64({left}) < s64({right})'
        elif op in ('sltu','sltiu'):
            expr=f'u64({left}) < u64({right})'
        else:
            symbol={'addiu':'+','addu':'+','subu':'-','and':'&','or':'|','ori':'|','andi':'&','xori':'^','xor':'^'}[op]
            expr=f'{left} {symbol} ({right})'
            if op in ('addiu','addu','subu'):expr=f'sx32({expr})'
    elif op in ('mult','madd'):
        if len(p)==2:return [f'(void)r.product({reg(p[0])}, {reg(p[1])}, {"true" if op=="madd" else "false"});']
        expr=f'r.product({reg(p[1])}, {reg(p[2])}, {"true" if op=="madd" else "false"})'
    else:raise ValueError('Unsupported chart instruction '+text)
    if dest=='0u':raise ValueError('Unexpected discard '+text)
    return [f'{dest} = {expr};']


def translate(entry,units,entries=ENTRIES,leaves=LEAVES,prefix='chart',registers='ChartRegisters',jump_tables=None,
              operations=operation):
    asm={int(u['address'].split(':')[-1],16):u['disassembly'] for u in units}
    labels={entry}
    slots=set()
    jump_tables=jump_tables or {}
    def branch(op):return op.startswith('b') or op in ('j','jr','jal')
    for addr,text in asm.items():
        op,p=line(text)
        if not branch(op):continue
        slots.add(addr+4)
        if op.startswith('b'):labels.add(int(p[-1],0))
        if addr in jump_tables:labels.update(jump_tables[addr])
    if labels-set(asm):raise ValueError('Branch outside recovered function')
    code=[f'static void {prefix}_{entry:06x}({registers}& r) {{']
    for addr in sorted(asm):
        if addr in labels:code.append(f'block_{addr:06x}:')
        if addr in slots:
            if addr in labels:raise ValueError('Source branch targets another instruction delay slot')
            continue
        op,p=line(asm[addr])
        if not branch(op):code.extend('    '+s for s in operations(asm[addr]));continue
        delay=operations(asm[addr+4])
        if op=='jr':
            if p==['ra']:items=delay+['return;']
            elif addr in jump_tables and not delay:
                items=[f'switch (u32({reg(p[0])})) {{']
                items += [f'case 0x{v:x}: goto block_{v:06x};' for v in sorted(set(jump_tables[addr]))]
                items += ['default: throw std::runtime_error("Invalid original direction table target");','}']
            else:raise ValueError(asm[addr])
        elif op in ('j','jal'):
            target=int(p[0],0)
            if target not in leaves and target not in entries:raise ValueError(f'0x{target:x}')
            callee=f'{prefix}_{target:06x}(r);' if target in entries else f'r.leaf(0x{target:06x});'
            items=([f'r.ra = 0x{addr+8:06x};'] if op=='jal' else [])+delay+[callee]
            if op=='j':items.append('return;')
        elif op=='b':items=delay+[f'goto block_{int(p[-1],0):06x};']
        else:
            likely=op.endswith('l')
            name=op[:-1] if likely else op
            if name in ('bc1f','bc1t'):
                cond='r.condition' if name=='bc1t' else '!r.condition'
            elif name in ('beq','bne'):
                cond=f'{reg(p[0])} {"==" if name=="beq" else "!="} {reg(p[1])}'
            else:
                rel={'bltz':'<','blez':'<=','bgez':'>=','bgtz':'>'}[name]
                cond=f's64({reg(p[0])}) {rel} 0'
            jump=f'goto block_{int(p[-1],0):06x};'
            if likely:items=[f'if ({cond}) {{']+['    '+s for s in delay+[jump]]+['}']
            elif delay:items=['{',f'    const bool taken = {cond};']+['    '+s for s in delay]+[f'    if (taken) {jump}','}']
            else:items=[f'if ({cond}) {jump}']
        code.extend('    '+s for s in items)
    code.append('}')
    return code


def main():
    source=ROOT/'analysis/ghidra/pc-timechart-native-v1'
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=SHA:raise ValueError('Retail ELF identity changed')
    manifest=json.loads((source/'manifest.json').read_bytes())
    if manifest['source_sha256']!=SHA or manifest['status']!='export_completed':raise ValueError('Incomplete dossier')
    out=['// Generated from the retail SLPM_664.52 by tools/generate_timechart_source.py.',
         '// Each source delay slot precedes its branch transfer, including annulled likely branches.','']
    out.extend(f'static void chart_{a:06x}(ChartRegisters&);' for a in ENTRIES)
    for a in ENTRIES:
        dossier=(ROOT/'analysis/ghidra/pc-chart-save-v1') if a==0x1ad3d8 else source
        if a==0x1ac690:dossier=ROOT/'analysis/ghidra/pc-special-choice-v1'
        units=json.loads((dossier/'functions'/f'{a:08x}.json').read_bytes())['disassembly']['units']
        for u in units:
            f=u['canonical_elf_file_offset']
            if not u['matches_original_elf'] or elf[f:f+4].hex()!=u['raw_hex']:raise ValueError(u['address'])
        out.extend(['']+translate(a,units))
    (ROOT/'port/core/timechart_blocks.hpp').write_text('\n'.join(out)+'\n',encoding='utf-8')


if __name__=='__main__':main()
