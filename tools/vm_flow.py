"""Build-specific bounded static VM flow evidence; never executes PS2 code."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from scenario import parse_link, parse_scr
from vm_anchors import decode as subset_decode, REG

EXPECTED_SHA256 = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
DELTA = 0xff000


def decode(word, address):
    op, rs, rt, rd, fn = word >> 26, (word >> 21)&31, (word >> 16)&31, (word >> 11)&31, word&63
    imm=word&65535
    signed=imm if imm<32768 else imm-65536
    if op==10:return f'slti {REG[rt]},{REG[rs]},{signed}'
    if op==14:return f'xori {REG[rt]},{REG[rs]},0x{imm:x}'
    if op==0 and fn in (4,6,7):return {4:'sllv',6:'srlv',7:'srav'}[fn]+f' {REG[rd]},{REG[rt]},{REG[rs]}'
    if op==0 and fn in (36,38,39,42):return {36:'and',38:'xor',39:'nor',42:'slt'}[fn]+f' {REG[rd]},{REG[rs]},{REG[rt]}'
    if op in (6,7,22,23):return {6:'blez',7:'bgtz',22:'blezl',23:'bgtzl'}[op]+f' {REG[rs]},0x{address+4+signed*4:08x}'
    if op==1 and rt in (0,1,2,3):return {0:'bltz',1:'bgez',2:'bltzl',3:'bgezl'}[rt]+f' {REG[rs]},0x{address+4+signed*4:08x}'
    return subset_decode(word,address)


def main():
    path=Path('local/extracted/SLPM_664.52');data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED_SHA256:raise ValueError('Build identity mismatch; fixed-address analysis refused')
    def word(va):
        off=va-DELTA
        if not 0<=off<=len(data)-4:raise ValueError('Address outside file-backed segment')
        return struct.unpack_from('<I',data,off)[0]
    def instructions(start,end):
        return [dict(address=f'0x{a:08x}',file_offset=a-DELTA,raw_word=f'{word(a):08x}',decoded=decode(word(a),a))
                for a in range(start,end,4)]
    def direct_edges(start,end):
        return [dict(site=f'0x{a:08x}',file_offset=a-DELTA,kind='jal' if word(a)>>26==3 else 'j',
                     target=f'0x{((a+4)&0xf0000000)|((word(a)&0x3ffffff)<<2):08x}')
                for a in range(start,end,4) if word(a)>>26 in (2,3)]
    def callers(target):
        return [dict(site=f'0x{a:08x}',file_offset=a-DELTA,kind='jal' if word(a)>>26==3 else 'j')
                for a in range(0x100000,0x204b38,4) if word(a)>>26 in (2,3) and ((word(a)&0x3ffffff)<<2)==target]
    regions=[
        ('manager_initial_context',0x11075c,0x110778),
        ('manager_tick',0x113148,0x113260),
        ('default_context_constructor',0x120230,0x120240),
        ('default_context_singleton',0x120280,0x1202c4),
        ('default_context_opcode_step',0x120308,0x1203e0),
        ('default_context_handler_delegate',0x1203e0,0x120410),
        ('opcode_handler_lookup',0x1133a8,0x1133d0),
        ('handler_factory_loop',0x10fd28,0x10fdb0),
        ('readback_scan',0x117580,0x117840),
        ('readback_scan_caller',0x116ea8,0x116f68),
        ('font_prepass',0x122ef8,0x1231c0),
        ('font_prepass_caller',0x1231c0,0x123258),
        ('glyph_metric_lookup',0x16b910,0x16b980),
        ('font_limit_and_line_operation',0x16a998,0x16a9d8),
        ('label_handler_constructor',0x124d38,0x124d48),
        ('label_operand_parser',0x124d48,0x124e38),
        ('label_transfer',0x124e38,0x124ea8),
        ('label_default_context_method',0x1253e8,0x125440),
        ('selector_and_label_transfer',0x10d868,0x10d968),
        ('label_lookup_and_cursor_set',0x10db48,0x10dbd4),
        ('variable_length_header_and_cstring',0x10d638,0x10d6c8),
        ('text_handler_constructor',0x122be0,0x122c20),
        ('text_default_context_method',0x122da0,0x122dd0),
        ('inline_text_driver_start',0x1126e0,0x1127d0),
    ]
    evidence={name:dict(start=f'0x{a:08x}',end_exclusive=f'0x{b:08x}',instructions=instructions(a,b),direct_calls_and_tail_jumps=direct_edges(a,b))
              for name,a,b in regions}
    context_vtable=[word(0x2239f0+i*4) for i in range(6)]
    factory_targets=[word(0x229784+i*4) for i in range(135)]
    allowed=[word(0x206010+i*4) for i in range(113)]
    constructor_cases=[]
    for opcode in [0x02,0x04,0x0d,0x22,0x6a,0x6b,0x85,0x86]:
        target=factory_targets[opcode]
        constructor_cases.append(dict(opcode=f'0x{opcode:02x}',factory_case=f'0x{target:08x}',instructions=instructions(target,target+28)))
    label_methods=[word(0x223ef8+i*4) for i in range(20)]
    # Cross-check only bounded, lexical selector+label patterns against independently parsed symbol tables.
    script_results=[]
    for script_path in sorted(Path('local/assets/SCENARIO').glob('*.sn4')):
        binary=script_path.read_bytes();blocks=parse_link(binary)
        parsed=[parse_scr(binary[b['offset']:b['offset']+b['size']]) for b in blocks]
        by_name=[{s['name']:s for s in p['symbols']} for p in parsed]
        counts=Counter();samples=[];unresolved=[]
        for block,parsed_block in zip(blocks,parsed):
            payload=binary[block['offset']:block['offset']+block['size']]
            for match in re.finditer(rb'([\x6a\x6b])([\x03-\x7f])([\x00-\x1f])([A-Za-z_][A-Za-z0-9_]*)\x00',payload[parsed_block['code_offset']:]):
                opcode,length,selector,name=match.group(1)[0],match.group(2)[0],match.group(3)[0],match.group(4).decode('ascii')
                if length!=len(name)+2:continue
                offset=block['offset']+parsed_block['code_offset']+match.start()
                target=by_name[selector].get(name) if selector<len(by_name) else None
                counts[f'0x{opcode:02x}_patterns']+=1
                if target:counts[f'0x{opcode:02x}_resolved_symbols']+=1
                row=dict(file_offset=offset,source_block=block['index'],opcode=f'0x{opcode:02x}',raw_hex=match.group().hex(),
                         length_byte=length,target_selector=selector,target_name=name,
                         target_symbol_tag=target['tag'] if target else None,
                         target_file_offset=blocks[selector]['offset']+target['destination_offset'] if target else None,
                         status=('lexical-pattern-with-symbol-match' if target else 'unresolved-lexical-pattern')+'; VM instruction boundary not proven')
                if len(samples)<12 or opcode==0x6b and sum(s['opcode']=='0x6b' for s in samples)<6:samples.append(row)
                if not target and len(unresolved)<12:unresolved.append(row)
        script_results.append(dict(name=script_path.name,sha256=hashlib.sha256(binary).hexdigest(),counts=dict(counts),samples=samples,unresolved_samples=unresolved))
    claims=[
        dict(id='FLOW-01',confidence='high-static',classification='observed-instructions-and-derived-role',
             statement='0x117580 saves active block/cursor, temporarily selects another location, scans opcodes, then restores saved location and flags. Caller 0x116EA8 lies in the Readback-associated region. This is a scan/preparation helper, not evidence for the sole gameplay VM loop.',
             evidence=['readback_scan','readback_scan_caller']),
        dict(id='FLOW-02',confidence='high-static-for-restoration-and-width-check; medium-for-exact-layout-role',classification='observed-instructions-and-inference',
             statement='0x122EF8 saves the script cursor and font state, reads CP932-sized units and obtains a glyph metric via 0x16B910 (returns byte +4 of the glyph record). It restores cursor/font state, compares font object+0x18 with another metric plus glyph width, and conditionally calls 0x16A998, which increments font object+0x20. Text-width lookahead/line-wrap check is the best role inference. Saved font parameters are not proven to be coordinates; exact dimension semantics remain unconfirmed.',
             evidence=['font_prepass','font_prepass_caller','glyph_metric_lookup','font_limit_and_line_operation']),
        dict(id='FLOW-03',confidence='high-static',classification='derived-control-chain',
             statement='Manager tick candidate 0x113148 calls context vtable slot 0, then either inline-text driver 0x1126E0 when manager+0x2B4 is set or context slot 1. Initialization installs context singleton 0x120280 at manager+0x40. Its vtable 0x2239F0 slot 1 is 0x120308, which reads an opcode, admits it through a 113-value table, looks up manager+0x5C+4*opcode, and invokes context slot 2. Slot 2 at 0x1203E0 delegates to handler vtable+0x3C.',
             evidence=['manager_initial_context','manager_tick','default_context_constructor','default_context_singleton','default_context_opcode_step','default_context_handler_delegate','opcode_handler_lookup']),
        dict(id='FLOW-04',confidence='high-static-for-operand-chain; medium-for-jump-name',classification='control-flow-opcode-candidate',
             statement='Opcodes 0x6A, 0x6B and 0x85 share factory case 0x110548 and constructor 0x124D38 (vtable 0x223EF8). The parser consumes a length header, one-byte selector and NUL-terminated label. Default-context method 0x1253E8 delegates to 0x124E38; it calls 0x10D868(selector,label,flag), with flag 1 for 0x6B and 0 otherwise. That path changes script selection/cursor using label lookup. 0x6A is a strong label-transfer/jump candidate; 0x6B is a flag variant, not yet proven to be call/return.',
             evidence=['label_handler_constructor','label_operand_parser','label_default_context_method','label_transfer','selector_and_label_transfer','label_lookup_and_cursor_set','variable_length_header_and_cstring']),
    ]
    report=dict(schema_version=1,evidence_id='VM-FLOW-001',authority='local-static-analysis-not-REA',
                source=dict(path=str(path),sha256=digest,size=len(data)),method='Python standard library; fixed source hash; finite byte/range inspection',
                claims=claims,evidence_regions=evidence,
                tables=dict(default_context_vtable=dict(address='0x002239f0',file_offset=0x2239f0-DELTA,entries=[f'0x{x:08x}' for x in context_vtable]),
                            opcode_allowlist=dict(address='0x00206010',file_offset=0x206010-DELTA,count=len(allowed),values=allowed),
                            opcode_factory=dict(address='0x00229784',count=135,targets=[f'0x{x:08x}' for x in factory_targets],selected_cases=constructor_cases),
                            label_handler_vtable=dict(address='0x00223ef8',entries=[f'0x{x:08x}' for x in label_methods],default_context_slot=15)),
                direct_callers={f'0x{a:08x}':callers(a) for a in [0x113148,0x120308,0x117580,0x122ef8,0x124d38,0x124d48,0x124e38,0x10d868]},
                script_operand_crosschecks=script_results,
                unknowns=['No controlled execution; default-context installation does not prove which context is active at a particular game screen.',
                          'Vtable classes and functions have analyst labels, not recovered source symbol names.',
                          '0x6B extra flag meaning, 0x85 label side effects, underscore-symbol semantics and call/return stack semantics remain unresolved.',
                          'Selection UI and conditional expression VM not recovered in this pass.',
                          'All R5900/MMI/VU semantics, full CFG, indirect caller coverage and branch reachability remain incomplete.',
                          'Lexical script samples are not a complete instruction-boundary decode; counts are bounded pattern counts.',
                          '134-case scanners cover opcode values below 0x86; manager constructor has 135 entries and default allowlist includes 0x86. Scanners cannot define the complete VM opcode set.'])
    Path('analysis/vm_flow.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'evidence_id':report['evidence_id'],'claims':len(claims),'regions':len(regions),'script_pattern_counts':[{k:s[k] for k in ('name','counts')} for s in script_results]}))


if __name__=='__main__':main()
