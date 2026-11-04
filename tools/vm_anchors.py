"""Bounded ELF/MIPS static anchors. No execution, decompiler, or REA provider."""
from pathlib import Path
import hashlib
import json
import re
import struct

REG = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']


def decode(word, address):
    op, rs, rt, rd, sh, fn = word >> 26, (word >> 21)&31, (word >> 16)&31, (word >> 11)&31, (word >> 6)&31, word&63
    imm = word & 65535
    signed = imm if imm < 32768 else imm - 65536
    if word == 0: return 'nop'
    if op == 15: return f'lui {REG[rt]},0x{imm:x}'
    if op in (9, 25, 13, 12, 11):
        name = {9:'addiu',25:'daddiu',13:'ori',12:'andi',11:'sltiu'}[op]
        return f'{name} {REG[rt]},{REG[rs]},{signed if op in (9,25) else hex(imm)}'
    if op in (32,33,35,36,37,39,40,41,43,55,63):
        name={32:'lb',33:'lh',35:'lw',36:'lbu',37:'lhu',39:'lwu',40:'sb',41:'sh',43:'sw',55:'ld',63:'sd'}[op]
        return f'{name} {REG[rt]},{signed}({REG[rs]})'
    if op in (2,3): return ('j' if op==2 else 'jal') + f' 0x{((address+4)&0xf0000000)|((word&0x3ffffff)<<2):08x}'
    if op in (4,5,20,21): return {4:'beq',5:'bne',20:'beql',21:'bnel'}[op]+f' {REG[rs]},{REG[rt]},0x{address+4+signed*4:08x}'
    if op==0:
        if fn in (8,9):return ('jr' if fn==8 else 'jalr')+f' {REG[rs]}'
        if fn in (0,2,3):return {0:'sll',2:'srl',3:'sra'}[fn]+f' {REG[rd]},{REG[rt]},{sh}'
        if fn in (33,35,37,43,45):return {33:'addu',35:'subu',37:'or',43:'sltu',45:'daddu'}[fn]+f' {REG[rd]},{REG[rs]},{REG[rt]}'
    return 'uninterpreted by subset decoder'


def analyze(path, out):
    data=path.read_bytes()
    if data[:7]!=b'\x7fELF\x01\x01\x01':raise ValueError('Expected ELF32 little endian')
    h=struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    if h[2]!=8 or h[11]!=40:raise ValueError('Expected MIPS ELF and 40-byte section records')
    raw=[struct.unpack_from('<10I',data,h[6]+i*h[11]) for i in range(h[12])]
    n=raw[h[13]]; names=data[n[4]:n[4]+n[5]]
    sections=[]
    for index,row in enumerate(raw):
        name=names[row[0]:].split(b'\0')[0].decode('ascii')
        sections.append(dict(index=index,name=name,type=row[1],flags=row[2],virtual_address=row[3],file_offset=row[4],size=row[5]))
    def location(offset):
        for s in sections:
            if s['type']!=8 and s['virtual_address'] and s['file_offset']<=offset<s['file_offset']+s['size']:
                return dict(file_offset=offset,virtual_address=s['virtual_address']+offset-s['file_offset'],section=s['name'])
        return dict(file_offset=offset,virtual_address=None,section=None)
    text=next(s for s in sections if s['name']=='.text')
    begin,end=text['file_offset'],text['file_offset']+text['size']
    va_delta=text['virtual_address']-begin
    words=[struct.unpack_from('<I',data,p)[0] for p in range(begin,end,4)]
    def context(index,before=6,after=6):
        return [dict(address=f'0x{begin+j*4+va_delta:08x}',file_offset=begin+j*4,
                     raw=f'{words[j]:08x}',decoded=decode(words[j],begin+j*4+va_delta))
                for j in range(max(0,index-before),min(len(words),index+after+1))]
    def prologue(index):
        for j in range(index,max(-1,index-256),-1):
            word=words[j]
            if word>>26 in (9,25) and (word>>21)&31==29 and (word>>16)&31==29 and word&0x8000:
                return dict(address=f'0x{begin+j*4+va_delta:08x}',file_offset=begin+j*4,
                            stack_delta=(word&65535)-65536,
                            status='nearest-lexical-stack-allocation-not-proven-function-start')
        return None
    wanted=['script/ScriptData.cc','script/Analyzer.cc','script/StructStack.cc','script/Readback.cc',
            'script/NameInputNormal.cc','font/Stack.cc','main/scenepack.c','ScriptMemory','FontMemory',
            'SCENARIO/sn4.sn4','SCENARIO/sn4.spk','SCENARIO/sn4.fnt']
    anchors=[]
    for value in wanted:
        needle=value.encode()+b'\0';cursor=0
        while True:
            offset=data.find(needle,cursor)
            if offset<0:break
            cursor=offset+1
            anchor=dict(string=value,**location(offset),address_construction_candidates=[],literal_pointer_locations=[])
            address=anchor['virtual_address']
            if address is None:continue
            for i,word in enumerate(words):
                if word>>26!=15:continue
                register=(word>>16)&31; high=(word&65535)<<16
                for j in range(i+1,min(len(words),i+17)):
                    second=words[j];op=second>>26;rs=(second>>21)&31
                    if op not in (9,25,13) or rs!=register:continue
                    low=second&65535
                    value2=high|low if op==13 else (high+(low if low<32768 else low-65536))&0xffffffff
                    if value2==address:
                        anchor['address_construction_candidates'].append(dict(
                            lui_address=f'0x{begin+i*4+va_delta:08x}',consumer_address=f'0x{begin+j*4+va_delta:08x}',
                            word_distance=j-i,register=REG[register],
                            status='syntactic-pair; intervening-register-liveness-and-CFG-unproven',
                            nearest_stack_allocation=prologue(i),instructions=context(i,3,(j-i)+5)))
            needle2=struct.pack('<I',address)
            for s in sections:
                if s['type']==8 or s['name'] in ('.text',''):continue
                for off in range(s['file_offset'],s['file_offset']+s['size']-3,4):
                    if data[off:off+4]==needle2:anchor['literal_pointer_locations'].append(location(off))
            anchors.append(anchor)
    indirect=[]
    for i,w in enumerate(words):
        if w>>26==0 and w&63==8 and (w>>21)&31 not in (0,31):
            region=words[max(0,i-16):i]
            shift2=any(x>>26==0 and x&63==0 and (x>>6)&31==2 for x in region)
            load=any(x>>26 in (35,39) for x in region)
            bounds=[x&65535 for x in region if x>>26==11 and 1<=x&65535<=256]
            if shift2 and load:
                indirect.append(dict(address=f'0x{begin+i*4+va_delta:08x}',file_offset=begin+i*4,
                                     possible_case_counts=bounds,status='generic-switch-candidate-not-attributed-to-script-VM',
                                     nearest_stack_allocation=prologue(i),instructions=context(i,16,2)))
    tables=[]
    for s in sections:
        if s['name'] not in ('.rodata','.data'):continue
        run=[]
        for off in range(s['file_offset'],s['file_offset']+s['size']+4,4):
            value=struct.unpack_from('<I',data,off)[0] if off<s['file_offset']+s['size'] else 0
            if text['virtual_address']<=value<text['virtual_address']+text['size'] and value%4==0:
                run.append((off,value))
            else:
                if len(run)>=16:
                    tables.append(dict(**location(run[0][0]),entry_count=len(run),unique_target_count=len(set(v for _,v in run)),
                                       first_targets=[f'0x{v:08x}' for _,v in run[:12]],
                                       status='contiguous-code-pointer-run; dispatch/vtable meaning unproven'))
                run=[]
    report=dict(schema_version=1,evidence_id='VM-STATIC-001',authority='local-static-analysis-not-REA',
                source=dict(path=str(path),size=len(data),sha256=hashlib.sha256(data).hexdigest()),
                elf=dict(format='ELF32 little-endian MIPS',machine=h[2],flags=f'0x{h[7]:08x}',entry_point=f'0x{h[4]:08x}',sections=sections),
                string_anchors=anchors,generic_switch_candidates=indirect,code_pointer_runs=tables,
                limitations=['No target execution, emulation, Ghidra import or REA provider was used.',
                             'Only a small MIPS instruction subset is rendered; R5900/MMI/VU instructions remain uninterpreted.',
                             'LUI+consumer pairs search at most 16 following instructions; control flow and intervening register writes are not proven.',
                             'String references often point to diagnostics, not subsystem entry points.',
                             'Nearest stack allocation is a lexical hint, not a proven function boundary.',
                             'No VM dispatch function or opcode semantics have been confirmed.'])
    if report['source']['sha256']=='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160':
        def at(va,before=0,after=24):return context((va-text['virtual_address'])//4,before,after)
        report['focused_byte_reader']={
            'address':'0x0010d5d8','status':'derived-from-instruction-sequence; runtime-unobserved',
            'interpretation':'Reads a1 bytes through the pointer at a0+0xD8, shifting accumulated result by eight and advancing the pointer. With a1=1 it reads one unsigned byte.',
            'instructions':at(0x10d5d8,0,13),
            'related_cursor_routine':{'address':'0x0010d610','instructions':at(0x10d610,0,9),
                'interpretation':'Adjusts cursor at +0xD8; accesses selected block via +0xD0 and reads block field +0x430, matching the independently parsed SCR code boundary.'}}
        report['focused_134_case_consumers']=[]
        for jump,base,start in [(0x117658,0x22a204,0x117580),(0x122f9c,0x22a6b0,0x122ef8)]:
            entries=[struct.unpack_from('<I',data,base-va_delta+i*4)[0] for i in range(134)]
            report['focused_134_case_consumers'].append(dict(
                jump_address=f'0x{jump:08x}',table_address=f'0x{base:08x}',candidate_function=f'0x{start:08x}',
                status='script-byte-consumer-candidate; main-VM-vs-scan/layout role unresolved',
                case_count=134,case_targets=[f'0x{v:08x}' for v in entries],instructions=at(jump,12,2)))
        report['focused_text_case']={'case_value':'0x02','address':'0x00123064',
            'status':'derived-call-sequence; text-rendering-vs-layout role unresolved',
            'interpretation':'Reads through 0x10D5D8, backs cursor by one via 0x10D610, reads two bytes and passes the value to 0x16B910. Correlates with CP932 candidates; does not prove complete text opcode semantics.',
            'instructions':at(0x123064,0,17)}
    out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(anchors=len(anchors),address_pairs=sum(len(a['address_construction_candidates']) for a in anchors),switch_candidates=len(indirect),pointer_runs=len(tables))))


if __name__=='__main__':
    analyze(Path('local/extracted/SLPM_664.52'),Path('analysis/vm_anchors.json'))
