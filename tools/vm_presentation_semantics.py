"""Hash-bound presentation/control evidence plus bounded executable reference models.

These models translate specified MIPS paths. They are not a game VM: unresolved
external calls block explicitly, and no ELF code is executed.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import struct

from vm_handlers import Image, ROOT, build_report, direct_edges, hx
from vm_flow import decode
from opening_instructions import SCRIPT_SHA, START, END, decode_fp, frame_one, frame_window

TARGETS = (0x22, 0x04, 0x0B, 0x15, 0x34, 0x35, 0x57)
STOP_TRUE = (0x12,0x13,0x14,0x2E,0x34,0x3A,0x3D,0x7A,0x7E,0x7F,0x81,0x82,0x83,0x84)
STOP_FALSE = (0x0B,0x0C,0x1A,0x6C)
LABEL_CASE = (0x1B,0x6A,0x6B,0x85)
DELEGATES = (0x6A,0x70,0x71)


class UnresolvedDependency(RuntimeError):
    """A caller must supply semantics; unknown behavior is never a no-op."""


def s32(n):
    n &= 0xFFFFFFFF
    return n if n < 0x80000000 else n - 0x100000000


def f32(n):
    return struct.unpack('<f',struct.pack('<f',n))[0]


def op57_values(raw_u32, setting18=False):
    """12B690/16B7B0/16B7F0: two font channels receive the same pair.

    Signed cvt.s.w matters. This uses host IEEE float32 rounding as a numeric
    reference, not bit-exact R5900 FPU emulation. Input is BE32 operand bits.
    Physical time units are deliberately not assigned.
"""
    if not isinstance(raw_u32,int) or not 0 <= raw_u32 <= 0xFFFFFFFF:
        raise ValueError('Expected unsigned 32-bit operand bits')
    n = 0 if setting18 else s32(raw_u32)
    return {'operand_signed':n,'channel_plus_08':0.0 if n else 128.0,
            'channel_plus_0c':f32(128.0/f32(n)) if n else 0.0,
            'handler_return':0,'arithmetic_status':'host-float32-reference; not bit-exact R5900'}


def font_transition_pending(channels):
    """16BA10 + 168C60, for materialized iterator nodes and finite floats.

Each node supplies float +4 (current) and +8 (step). Iterator construction and
updates are external dependencies. This does not animate or consume frames.
"""
    if len(channels) != 2:
        raise ValueError('16BA10 checks exactly two channels')
    for nodes in channels:
        for current,step in nodes:
            if not math.isfinite(current) or not math.isfinite(step):
                raise UnresolvedDependency('R5900 nonfinite comparison semantics not modeled')
            if step != 0 and current != (128.0 if step > 0 else 0.0):
                return True
    return False


def op15_decision(opcode_relative_offset, channels):
    pending = font_transition_pending(channels)
    return {'handler_return':int(pending),
            'set_main_cursor_relative':opcode_relative_offset if pending else None,
            'reason':'font-transition-pending' if pending else 'font-transition-complete'}


def wait_predicate(state, input_mask):
    """Exact finite integer path of 120160, 11A1C0 and 115C58.

State keys name raw offsets, not inferred game concepts. Returns a copied state
and acceptance. All required keys are explicit; missing state raises KeyError.
1160D0 is a constant-zero function in this build.
"""
    out = copy.deepcopy(state)
    if out['object24_plus00'] != 0:
        value = s32(out['object24_plus10'] + 1)
        ready = value >= s32(out['object24_plus0c'])
        out['object24_plus10'] = 0 if ready else value
        return out,ready,'object24-counter; input-and-timer-not-queried'
    if out['manager_plus808'] != 0:
        remaining = s32(out['manager_plus814'])
        if out['global_gp_minus7f9c'] != 0:  # lw gp-32668 at 104E00
            queried = remaining
        elif out['setting1'] != 0:
            queried = 0  # 115CA4 branch does not store into timer
        else:
            queried = max(s32(remaining - 1),0)
            out['manager_plus814'] = queried
        if queried <= 0:
            return out,True,'timer-result-nonpositive'
    return out,bool(input_mask & 0x2100),'input-mask-0x2100'


def wait_context_step(state, input_mask, override18=None):
    """120030 outer wait context, with 1195B0 supplied explicitly when enabled.

override18 must return (new_object18_plus00, ready). It represents a separate
input-sequence helper whose randomness/global side effects are not simulated.
Completion still requires the 16CBC8 callback listed in events.
"""
    out = copy.deepcopy(state)
    events = []
    if out['object18_plus00'] != 0:
        if override18 is None:
            raise UnresolvedDependency('0x1195B0 enabled input-sequence helper required')
        out['object18_plus00'],ready = override18(out['object18_plus00'],input_mask)
        events.append('0x1195B0')
        if ready:
            input_mask |= 0x2100
    out,accepted,reason = wait_predicate(out,input_mask)
    if accepted:
        if out['object18_plus00'] != 0:
            out['object18_plus00'] = 0
        out['context_vtable'] = 0x2239F0
        events.append('0x16CBC8 unresolved external completion action')
    return {'state':out,'context_return':0 if accepted else 1,
            'accepted':accepted,'reason':reason,'events':events,
            'complete_runtime_semantics':False}


def line_advance(font, base, virtual_slot2_result):
    """04 core: 16A998 -> 1682D8/168568/168388/168308.

virtual_slot2_result is an explicitly supplied metric, not assumed pixels.
Caller must additionally apply conditional 119EB0 state propagation.
"""
    f,b = dict(font),dict(base)
    b[0x04] = f[0x10]
    b[0x08] = s32(b[0x08] + s32(virtual_slot2_result+b[0x18]))
    f[0x20] = s32(f[0x20]+1)
    return f,b


def op34_35(state, opcode, begin_record=None):
    """34 and 35 shared 132A08 path, with unresolved 10F318 blocking 34."""
    if opcode not in (0x34,0x35):
        raise ValueError('Only 34/35')
    out = copy.deepcopy(state)
    out['manager_plus32c'] = int(opcode == 0x34)
    if opcode == 0x34:
        if begin_record is None:
            raise UnresolvedDependency('0x10F318 record setup must be implemented')
        out = begin_record(out)
        out['global_gp_minus7fb4'] = 1
    else:
        # 114AE0 passes a1=1, so 10F3C8 takes its early nonzero branch.
        out['script_plus14c'] = 0
        out['script_plus150'] = 1
        out['global_gp_minus7fb4'] = 0
    return out,0


def scan22(data, cursor, limit, max_steps=4096):
    """12F3C0 narrow, non-delegating path; preserves absolute slice cursor.

Label cases and delegated handlers raise, because original code can change the
selected block. The original restores only relative offset, not block selector.
"""
    saved=cursor
    visited=[]
    for _ in range(max_steps):
        if not 0 <= cursor < min(limit,len(data)):
            raise ValueError('22 scan reaches truncated/out-of-range input')
        opcode=data[cursor]
        visited.append({'offset':cursor,'opcode':opcode})
        if opcode in STOP_TRUE or opcode in STOP_FALSE:
            return {'result':int(opcode in STOP_TRUE),'restored_cursor':saved,
                    'stop_offset':cursor,'stop_opcode':opcode,'visited':visited,
                    'scope':'non-delegating static path; not runtime execution'}
        if opcode in LABEL_CASE or opcode in DELEGATES:
            raise UnresolvedDependency(f'22 scan opcode {opcode:#x} needs label/context semantics')
        cursor=frame_one(data,cursor,limit)['end_exclusive']
    raise ValueError('22 scan step bound reached')


OP22_SEQUENCE = [
    (0x114A50,'manager+0x330: +0x3E8=1, +0x3EC=0, +0x3F0=0'),
    (0x12F308,'gate: manager+32C OR object28+10 OR object30+00 bypasses scan; otherwise scan, and result0 calls1050B8'),
    (0x114470,'ten manager+330 records at stride100: nonzero +0 sets +0xC=1; R5900 MULT rd evidence retained'),
    (0x12F1D0,'font state reset, preference application, 128/0 channel values, conditional manager+2A4'),
    (0x12F598,'object20/object28/object08/object30 conditions, optional1114F8, then object08+0C=1'),
    (0x12F6C0,'font setter16AA98 ->16A9F0 with128,128,128,0,0,0'),
    (0x12F1A8,'manager pointed object+04: +00=1 through1165B8'),
    (0x12F6E8,'manager+29C=manager+31C; manager+294=0; setting18 forces+29C=0'),
    (0x12F2C8,'script-selected object passed to19C868 with flag0; unresolved external callback'),
]


def opcode22_plan():
    return {'ordered_calls':[{'address':hx(a),'effect':s} for a,s in OP22_SEQUENCE],
            'last_mutation':'manager+0x2C0=0','handler_return':0,
            'status':'partial; external and indirect dependencies required'}


def execute22_callbacks(callbacks):
    """Execute the verified call order only when every helper is supplied.

This is a dependency contract, not an implementation of missing effects.
Preflight prevents partially applying a prefix when a helper is absent.
"""
    missing=[hx(a) for a,_ in OP22_SEQUENCE if a not in callbacks]
    if missing:
        raise UnresolvedDependency('opcode22 unresolved callbacks: '+','.join(missing))
    for address,_ in OP22_SEQUENCE:
        callbacks[address]()
    return {'manager_plus2c0':0,'handler_return':0}


def extended_decode(word,address):
    op,rs,rt,fs,fd,fn=word>>26,(word>>21)&31,(word>>16)&31,(word>>11)&31,(word>>6)&31,word&63
    if op==17 and rs==16 and fn in (0x32,0x34):
        return f'COP1 compare cond={fn&15} f{fs},f{rt}; eq / ordered-lt interpretation'
    if op==17 and rs==8 and rt in (0,1,2,3):
        imm=word&65535;imm=imm if imm<32768 else imm-65536
        return ['bc1f','bc1t','bc1fl','bc1tl'][rt]+f' {hx(address+4+imm*4)}'
    if op==0 and fn==24 and fs:
        return f'R5900 mult rd=r{fs},rs=r{rs},rt=r{rt}; target-specific rd output'
    return decode_fp(word) or decode(word,address)


EXTRA_REGIONS = [
    (0x120308,0x120410),(0x11FF60,0x120220),(0x115C58,0x115CE4),
    (0x1160D0,0x1160D8),(0x104E00,0x104E30),(0x11A188,0x11A21C),
    (0x1195A8,0x1196B8),(0x168C60,0x168D08),(0x16BA10,0x16BA64),
    (0x16A998,0x16A9D8),(0x1682D8,0x168314),(0x168388,0x168390),(0x168568,0x1685B4),
    (0x16B7B0,0x16B830),(0x169B08,0x169B18),(0x111550,0x111560),
    (0x114A50,0x114B30),(0x10F318,0x10F4F8),(0x1061C0,0x1061DC),
    (0x113460,0x1134D0),(0x119DE8,0x119F80),(0x123558,0x12366C),
    (0x1165B8,0x1165C8),(0x16AA98,0x16AAC8),(0x16A740,0x16A758),
    (0x113B30,0x113C40),(0x114470,0x1144A8),(0x11A650,0x11A658),
    (0x117D00,0x117D08),(0x117D58,0x117D60),(0x1050B8,0x1050E0),
    (0x10EDC0,0x10EDEC),(0x11A3C8,0x11A3D0),(0x1126C0,0x1126E0),
]


def analyze(image,script):
    if hashlib.sha256(script).hexdigest()!=SCRIPT_SHA:
        raise ValueError('Script SHA-256 mismatch')
    base=build_report(image,ROOT/'local/extracted/SLPM_664.52')
    classes=[c for c in base['handler_classes'] if set(c['opcodes'])&set(TARGETS)]
    regions={}
    for c in classes:
        methods=[int(v['target'],16) for v in c['vtable_entries'][:25]]
        # Capture every slot body; final body bounded by last return+delay only
        # through next constructor, known from all 72 constructor addresses.
        ctor=int(c['constructor'],16)
        following=min(int(x['constructor'],16) for x in base['handler_classes'] if int(x['constructor'],16)>ctor)
        regions[f'{ctor:08x}-{following:08x}']=image.region(ctor,following)
        c['context_method_direct_edges']=[{'slot':i,'entry':hx(a),
            'region':f'{ctor:08x}-{following:08x}',
            'edges':direct_edges(image,a,min([v for v in methods if v>a]+[following]))}
            for i,a in enumerate(methods)]
    for start,end in EXTRA_REGIONS:
        regions[f'{start:08x}-{end:08x}']=image.region(start,end)
    for region in regions.values():
        for row in region['instructions']:
            row['extended_decode']=extended_decode(int(row['raw_word'],16),int(row['address'],16))
    table=[image.word(0x22A8DC+i*4) for i in range(123)]
    assert [i+11 for i,v in enumerate(table) if v==0x12F450]==list(STOP_TRUE)
    assert [i+11 for i,v in enumerate(table) if v==0x12F538]==list(STOP_FALSE)
    assert [i+11 for i,v in enumerate(table) if v==0x12F540]==list(LABEL_CASE)
    assert [image.word(0x206210+i*4) for i in range(3)]==list(DELEGATES)
    assert image.word(0x235F80)==0x43000000 and image.word(0x235F84)==0xC3000000
    framed=frame_window(script,START,END)
    samples=[r for r in framed if r['opcode'] in TARGETS]
    scans=[scan22(script,o+1,END) for o in [START,0xA19AF]]
    waits=[]
    fixture={'object24_plus00':0,'object24_plus10':0,'object24_plus0c':2,
             'manager_plus808':0,'manager_plus814':3,'global_gp_minus7f9c':0,
             'setting1':0,'object18_plus00':0,'context_vtable':0x2239D0}
    for mask in [0,0x2000,0x100,0x800,0x2100]:
        waits.append({'mask':hex(mask),'result':wait_context_step(fixture,mask)})
    return {'schema_version':1,'evidence_id':'VM-PRESENTATION-001',
        'authority':'local-static-analysis-not-REA-or-runtime',
        'source':{'elf_path':'local/extracted/SLPM_664.52','elf_size_bytes':len(image.data),
                  'elf_sha256':image.sha256,'script_path':'local/assets/SCENARIO/sn4g.sn4',
                  'script_size_bytes':len(script),'script_sha256':SCRIPT_SHA},
        'scope':'22,04,0B,15,34,35,57; executable bounded reference contracts, incomplete external effects',
        'handler_classes':classes,'evidence_regions':regions,
        'context_variants':{
            '04_15_34_35_57':'All25 observed slots tail-delegate to the same class helper; 15 forwards a2,34/35/57 forward a3. This does not establish all context-level policies.',
            '0B':'slots8/9 use11F3C0 context path; slot15 uniquely includes10EDC0/123600 record operations; other slots share the smaller direct-call sequence ending123558.',
            '22_constant_zero_slots':[i for i in range(25)
                if image.word(image.word(0x225318+4*i))==0x03E00008
                and image.word(image.word(0x225318+4*i)+4)==0x0000102D],
            '22_other_slots':{'1,4':'12F1A8 only','8,9':'reset+12F680+record flag1 or0+1114F8',
                '10':'scan gate+reset+12F6C0+12F1A8+1114F8','16,23':'12F6C0+12F1A8+12F6E8',
                '18':'12F6C0+12F1A8','21':'12F1D0+12F6C0+12F1A8'},
            'warning':'Same direct call sequence alone does not prove same arguments or side effects; raw bodies retained.'},
        'opcode22':{'plan':opcode22_plan(),'scan_table':{'address':'0x0022a8dc','first_opcode':11,
            'entries':[dict(opcode=i+11,target=hx(v),**image.record(0x22A8DC+i*4,False)) for i,v in enumerate(table)]},
            'stop_true':list(STOP_TRUE),'stop_false':list(STOP_FALSE),'label_cases':list(LABEL_CASE),
            'delegated':list(DELEGATES),'opening_scans':scans,
            'critical_limit':'12F3C0 saves relative cursor only, not selector; delegated6A/70/71 may mutate block/context. Do not promise rollback.',
            'scan_gate':'manager+32C !=0 OR object28+10 !=0 OR object30+00 !=0 bypasses scan; otherwise scan. If scan returns0, call1050B8 (setting30 gates104E10).'},
        'semantics':{
            '04':{'operand_bytes':0,'core':'base+4=font+10; base+8 += base.vtable.slot2(base)+base+18; font+20++',
                  'additional':'If pointed object20+4 !=0, call119EB0(object20,font+20), ignore result; return0.',
                  'blockers':['base virtual metric implementation','119EB0 may change cursor/context-related fields; it is not a no-op']},
            '15':{'operand_bytes':0,'core':'If either font channel has a pending node, rewind to opcode offset (a2) and return1, else return0.',
                  'node_test':'step(+8)!=0 and current(+4)!=(step>0 ?128:0); iterate both channels',
                  'blockers':['iterator and per-tick update semantics','R5900 nonfinite FP edge cases']},
            '34_35':{'operand_bytes':0,'34':'manager+32C=1;10F318(script);gp-7FB4=1;return0',
                '35':'manager+32C=0;script+14C=0;script+150=1;gp-7FB4=0;return0',
                'blockers':['34 script record setup10F318 has unresolved record helpers']},
            '57':{'operand_bytes':4,'read':'BE32 -> signed cvt.s.w','setting18_override':'n=0',
                'nonzero':'both font channel control+8=0, +C=float32(128/float32(n))',
                'zero':'both control+8=128, +C=0','handler_return':0,
                'opening_values':[op57_values(60)],'blockers':['per-tick propagation into glyph nodes and physical timing units','bit-exact R5900 FPU arithmetic']},
            '0B':{'operand_bytes':0,'default_slot15':'0x001243e8',
                'path':['if manager+2C0:10EDC0 marks selected script record bit31',
                    'if object20+4 and119EB0(object20,5)!=0:return0',
                    'if object30+0:11A5C8(object30);return0',
                    'if manager+808:manager+814=manager+810 through115CD8',
                    '123600:10ECA0(script,script+D4,setting30?1:0,0)',
                    'if object2C+0:10DAF0(script,object2C+C,object2C+10);return1',
                    'otherwise install11FFB0 singleton(vtable2239D0),call16CB40;return1'],
                'blockers':['selected record lookup and10ECA0 marking','special branch10DAF0','16CB40 external presentation action']},
        },
        'wait_context':{'vtable':hx(0x2239D0),'table_entries':[image.record(0x2239D0+i*4,False) for i in range(6)],
            'slot0':hx(0x120030),'predicate':hx(0x120160),'slot1':hx(0x1200F8),
            'input_mask':'0x2100 raw bits; physical button assignment not inferred',
            'priority':'object24 mode counter > timer or input; enabled object24 ignores input and timer',
            'object24_counter':'increment signed+10; if >= signed+0C set+10=0 and accept',
            'timer':'manager+808 enables. If gp-7F9C!=0 return remaining unchanged. Else setting1!=0 returns0 without write; else remaining=max(signed(remaining-1),0). Nonpositive accepts; otherwise mask can accept.',
            'outer':'15FE30 supplies snapshot; enabled object18 invokes1195B0 and ready ORs0x2100. On accept clear still-enabled object18, install default2239F0,call16CBC8,return0. Else return1.',
            'examples':waits,'blockers':['snapshot edge/held semantics of15FE30','1195B0 input-sequence mode/random effects when enabled','16CB40/16CBC8 external actions','timebase of timer polling']},
        'script_samples':samples,
        'unknowns':['Only default slot15 reference semantics implemented; alternate slot bodies retained and must not be equated.',
            'No PS2 execution, full CFG, renderer, input backend or save-state schema is provided.',
            'R5900 MULT rd noted explicitly; generic MIPS decoder is not proof of all target semantics.',
            'Models preserve raw field names and fail for unresolved dependencies; hooks are obligations, not implicit no-ops.']}


def write_report(report,out,source_paths):
    if out.resolve() in {p.resolve() for p in source_paths}:
        raise ValueError('Report output must be distinct from source artifacts')
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    parser.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    parser.add_argument('--out',type=Path,default=ROOT/'analysis/vm_presentation_semantics.json')
    args=parser.parse_args()
    image=Image(args.elf.read_bytes())
    report=analyze(image,args.script.read_bytes())
    write_report(report,args.out,[args.elf,args.script])
    print(json.dumps({'evidence_id':report['evidence_id'],'classes':len(report['handler_classes']),
        'regions':len(report['evidence_regions']),'script_samples':len(report['script_samples']),
        'opening_scan_stops':[(r['stop_offset'],r['result']) for r in report['opcode22']['opening_scans']]},ensure_ascii=False))


if __name__=='__main__':
    main()
