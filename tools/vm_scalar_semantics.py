"""Hash-bound scalar/presentation contracts. No ELF or graphics execution.

Callbacks are explicit backend obligations, never default success/no-op.
Float routines are host float32 references, not a bit-exact R5900 emulator.
"""
import argparse
import copy
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
from pathlib import Path

from vm_handlers import Image, ROOT, build_report, hx
from vm_presentation_semantics import UnresolvedDependency, extended_decode, s32, f32
from opening_instructions import SCRIPT_SHA
from choice_branch import Script

OPCODES=(0x17,0x1E,0x2F,0x40,0x46,0x50,0x5C,0x6F)
COMMANDS={0x65:(0x18ED58,1),0x67:(0x18E840,6)}
DEPENDENCIES={
    0x135760:'queue_ready() -> bool; global2062B8!=0',
    0x138FB0:'aggregate_ready() -> bool; see aggregate_ready reference',
    0x18ED58:'start65(arguments) -> task handle; includes allocator/scheduler and render state',
    0x18E840:'start67(arguments) -> task handle; includes allocator/scheduler and render state',
    0x169E68:'metrics_after_main_increment(state) -> [main_vslot0,main_vslot1,secondary_vslot2,secondary_plus24]',
}


@dataclass
class ScalarState:
    cursor:int=0
    manager_plus294:int=0
    manager_plus298:int=0
    manager_plus29c:int=0
    manager_plus2d0:int=0
    manager_plus2d4:object=0
    manager_plus2d8:int=0
    manager_plus2dc:int=0
    manager_plus2e8:int=0
    manager_plus2ec:int=0
    font_main_plus04:int=0
    font_main_plus08:int=0
    font_secondary_plus04:int=0
    font_secondary_plus08:int=0
    font_plus24:int=0
    # The caller must supply both live channels and their node state.
    font_channels:list=field(default_factory=lambda:[
        {'plus08':0.0,'plus0c':0.0,'nodes':[]},
        {'plus08':0.0,'plus0c':0.0,'nodes':[]}])


def invoke(callbacks,address,*args):
    if address not in callbacks:
        raise UnresolvedDependency(f'{hx(address)}: {DEPENDENCIES.get(address,"external backend action")}')
    return callbacks[address](*args)


def boolean(callbacks,address):
    result=invoke(callbacks,address)
    if result not in (False,True,0,1):raise ValueError('Predicate must return original boolean')
    return bool(result)


def parse_scalar(data,offset,limit=None):
    limit=min(len(data),len(data) if limit is None else limit)
    if offset<0 or offset>=limit or data[offset] not in OPCODES:
        raise ValueError('Invalid scalar opcode')
    op=data[offset];pos=offset+1;result={'opcode':op,'offset':offset}
    def take(n):
        nonlocal pos
        if n<0 or pos+n>limit:raise ValueError('Truncated scalar operands')
        raw=data[pos:pos+n];pos+=n;return raw
    if op in (0x40,0x46):result['value']=take(1)[0]
    elif op in (0x50,0x5C):
        result['raw_u32']=int.from_bytes(take(4),'big')
        result['value']=s32(result['raw_u32'])
    elif op==0x6F:
        marker=take(1)[0]
        declared=marker if marker else int.from_bytes(take(2),'big')
        payload=pos;command=int.from_bytes(take(4),'big');argc=take(1)[0]
        arguments=[int.from_bytes(take(4),'big') for _ in range(argc)]
        result.update(command_id=command,argc=argc,arguments_u32=arguments,
            arguments_s32=[s32(a) for a in arguments],declared_payload_bytes=declared,
            actual_payload_bytes=pos-payload,declared_matches_payload=declared==pos-payload)
    raw=data[offset:pos]
    result.update(end_exclusive=pos,raw_hex=raw.hex(),raw_sha256=hashlib.sha256(raw).hexdigest())
    return result


def step(data,state,callbacks,*,setting18=False,limit=None):
    """One default-slot15 invocation; no global scheduler ticks are implicit.

6F checks readiness before parsing payload, as the original does. On failure
cursor rewinds to opcode start. 50 yields once even for zero with cursor advanced.
"""
    out=copy.deepcopy(state)
    if out.cursor<0 or out.cursor>=len(data):raise ValueError('Cursor outside source')
    op=data[out.cursor];events=[]
    if op not in OPCODES:raise UnresolvedDependency(f'Unrecovered opcode {op:#x}')
    if op==0x6F:
        if not boolean(callbacks,0x135760) or out.manager_plus2d0!=0:
            return {'state':out,'handler_return':1,'retry':True,'events':[], 'operand':None}
    record=parse_scalar(data,out.cursor,limit);out.cursor=record['end_exclusive'];result=0
    if op==0x17:
        if not setting18 and out.manager_plus2d0:
            out.cursor=record['offset'];result=1
    elif op==0x1E:
        if not boolean(callbacks,0x138FB0):
            out.cursor=record['offset'];result=1
    elif op==0x40:
        out.manager_plus29c=0 if setting18 else record['value']
        out.manager_plus294=0
    elif op==0x46:
        out.font_main_plus04=s32(out.font_main_plus04+record['value'])
        metrics=invoke(callbacks,0x169E68,copy.deepcopy(out))
        if not isinstance(metrics,(tuple,list)) or len(metrics)!=4 or any(type(x) is not int for x in metrics):
            raise ValueError('Alignment callback must return four original integer results')
        x,y,metric,offset=metrics
        out.font_secondary_plus04=s32(x)
        out.font_secondary_plus08=s32(y-metric+offset)
        out.font_plus24=s32(x-16)
        events.append({'address':'0x00169e68','virtual_results':metrics})
    elif op==0x50:
        out.manager_plus2e8=0
        out.manager_plus2ec=0 if setting18 else record['value']
        result=1
    elif op==0x2F:
        for ch in out.font_channels:ch['plus08']=128.0;ch['plus0c']=0.0
    elif op==0x5C:
        n=0 if setting18 else record['value']
        current=128.0 if n else 0.0
        delta=f32(-128.0/f32(n)) if n else 0.0
        for ch in out.font_channels:
            for node in ch['nodes']:node.update(plus04=current,plus08=delta)
    elif op==0x6F:
        if not setting18:
            command=record['command_id'];argc=record['argc']
            if command not in COMMANDS or COMMANDS[command][1]!=argc:
                raise UnresolvedDependency(f'6F command {command:#x}/argc{argc} has no executable effect contract')
            out.manager_plus2d0=1;out.manager_plus2d8=0;out.manager_plus2dc=0
            address=COMMANDS[command][0]
            handle=invoke(callbacks,address,tuple(record['arguments_s32']))
            if handle is None:raise ValueError('Command must return explicit task handle; zero is allowed but remains active')
            out.manager_plus2d4=handle
            events.append({'address':hx(address),'arguments':record['arguments_s32']})
    return {'state':out,'handler_return':result,'retry':out.cursor==record['offset'],
        'operand':record,'events':events}


def aggregate_ready(gp_ac34,query138f08,query138eb8,query139078,global2062ac,status135770=None):
    """138FB0: all three query callbacks still execute in original call order.

The caller provides their results, not a guessed 'movie finished' Boolean.
135770 is queried only if global2062AC==0; only its low two bits matter.
"""
    if global2062ac==0 and status135770 is None:
        raise UnresolvedDependency('138FB0 needs135770 status when global2062AC is zero')
    ready=(gp_ac34==0 and not query138f08 and not query138eb8 and not query139078)
    return bool(ready and (global2062ac!=0 or not(status135770&3)))


def timer_tick(state,input_mask=None):
    """113818 called by manager before dispatch. Counts calls, not wall seconds."""
    out=copy.deepcopy(state);n=s32(out.manager_plus2ec)
    if n!=0 and out.manager_plus2e8:
        if input_mask is None:raise UnresolvedDependency('Cancelable timer needs15FE30 input snapshot')
        if input_mask&0x2100:n=0
    if n>=0:n=max(0,s32(n-1))
    out.manager_plus2ec=n
    return out


def text_cadence_tick(state):
    """11306C..113090 only, after manager's earlier input/skip gates."""
    out=copy.deepcopy(state);threshold=out.manager_plus29c&0xffffffff
    if threshold:
        counter=(out.manager_plus294+1)&0xffffffff
        out.manager_plus294=s32(counter)
        if counter>=threshold:
            out.manager_plus294=0;out.manager_plus298=1
    else:out.manager_plus298=1
    return out


def text_unit_gate(state,unit,*,consumed=False):
    """1127CC/112A08 narrow gate around the separate inline-text implementation.

8190-like control units and full glyph dispatch remain outside this function.
Consumed means the surrounding glyph path reached112A08, not merely read bytes.
"""
    out=copy.deepcopy(state)
    accepted=bool(out.manager_plus298 or unit==0x8140)
    if consumed:
        if not accepted:raise ValueError('Unready non-space unit cannot be consumed')
        if out.manager_plus29c:out.manager_plus298=0
    return {'state':out,'accepted':accepted,'rewind_bytes':0 if accepted else 2,
        'handler_return':0 if accepted else 1}


def glyph_tick(node):
    """1697D0 scalar part: current+step clamped at0/128, step cleared at bounds."""
    out=copy.deepcopy(node);delta=f32(out['plus08'])
    if delta!=0.0:
        value=f32(f32(out['plus04'])+delta)
        if value<=0.0:out.update(plus04=0.0,plus08=0.0)
        elif value>=128.0:out.update(plus04=128.0,plus08=0.0)
        else:out['plus04']=value
    return out


def make_effect_task(command,args,handle):
    """Pure data portion of18E840/18EC68. Allocation/scheduler are host duties."""
    if command not in COMMANDS or len(args)!=COMMANDS[command][1]:
        raise UnresolvedDependency('Unrecovered native effect command/arity')
    args=[s32(a) for a in args]
    if command==0x65:
        if args[0]==0:raise UnresolvedDependency('Original65 divide-by-zero requires R5900 FPU semantics')
        state={'plus00':128.0,'plus04':0.0,'plus08':f32(128.0/f32(args[0]))}
    else:
        d0=args[0] or 1;d2=args[2] or 1
        state={'plus00':0,'plus04':args[1],'plus08':255.0,
            'plus0c':f32(255.0/f32(d0)),'plus10':f32(255.0/f32(d2)),
            'plus14':args[3],'plus18':args[4],'plus1c':args[5]}
    return {'command_id':command,'arguments':args,'handle':handle,'data':state,
        'task_plus0c':0,'task_plus04':0,'finished':False}


def effect_tick(task,manager,*,pause_predicate):
    """Arithmetic of original task update only; emits mandatory backend actions.

pause_predicate is13D098.17A198/17A1A8 scheduler actions, draw callbacks,
destructor/memory lifetime, and update-vs-draw ordering are host obligations.
Completion explicitly mirrors10C368->111568->113680.
"""
    out=copy.deepcopy(task);state=copy.deepcopy(manager);d=out['data']
    if out['finished']:raise ValueError('Removed task must not tick again')
    if pause_predicate:
        return {'task':out,'state':state,'required_actions':['17A198(task)'],'completed':False}
    completed=False
    if out['command_id']==0x65:
        d['plus00']=f32(d['plus00']-d['plus08'])
        d['plus04']=f32(d['plus04']+d['plus08'])
        if d['plus00']<1.0:d['plus00']=0.0;completed=True
        if d['plus04']>=128.0:d['plus04']=128.0;completed=True
    elif out['command_id']==0x67:
        phase=d['plus00']
        if phase==0:
            d['plus08']=f32(d['plus08']-d['plus0c'])
            if d['plus08']<=0.0:d['plus08']=0.0;d['plus00']=1
        elif phase==1:
            d['plus04']=s32(d['plus04']-1)
            if d['plus04']<=0:d['plus00']=2
        elif phase==2:
            d['plus08']=f32(d['plus08']+d['plus10'])
            if d['plus08']>=255.0:d['plus08']=255.0;completed=True
        # Original other phases do no arithmetic; no such state constructed here.
        else:raise UnresolvedDependency('Effect67 state outside constructed0/1/2')
    else:raise UnresolvedDependency('Unknown task command')
    actions=['17A1A8(task)']
    if completed:
        actions+=['179C80(task): request removal','10C368->111568->113680: clear manager task flags']
        out['task_plus04']=1;out['finished']=True
        state.manager_plus2d0=0;state.manager_plus2d8=0;state.manager_plus2dc=0
        #113680 intentionally does not clear+4 task handle or saved+10/+14.
    return {'task':out,'state':state,'completed':completed,'required_actions':actions}


def effect_draw_contract(task):
    """Raw draw inputs, not a complete screen compositor or opacity shortcut."""
    d=task['data'];command=task['command_id']
    rectangle=[0.0,0.0,639.0,223.0]
    if command==0x67:
        fog=math.trunc(d['plus08'])
        return {'entry':'0x0018ea98','draw':'177FF8->177658',
            'geometry_xyxy':rectangle,'texture_uvuv':rectangle,'prim_template':0x170,
            'vertex_rgba':[128,128,128,128],
            'fogcolor_rgb':[d['plus14'],d['plus18'],d['plus1c']],
            'fog_integer':fog,'vertex_fog_packed_word':s32(fog<<4),
            'texture_setup':'179DE0(render,8000):current framebuffer' if d['plus00'] in (0,1)
                else '176970(render,8000):175FC0-selected surface',
            'raw_texture_base_units':8000,
            'interpretation':'Fog factor, not alpha. F=0 gives fogcolor; F=255 is255/256 source plus1/256 fogcolor.',
            'layer_order':'Scheduler/task draw ordering unresolved; do not automatically place only above backgrounds.'}
    if command==0x65:
        return {'entry':'0x0018ee78','draw':'178910->177F48->177490',
            'geometry_xyxy':rectangle,'texture_uvuv':rectangle,'prim_template':0x150,
            'vertex_rgba':[128,128,128,math.trunc(d['plus00'])],
            'texture_setup':'179DE0(render,5760):current framebuffer',
            'raw_texture_base_units':5760,
            'interpretation':'Textured rectangle with decreasing vertex alpha. Not a solid black quad.',
            'layer_order':'Scheduler/task draw ordering unresolved.'}
    raise UnresolvedDependency('Unknown task draw')


REGIONS=[
    (0x113610,0x113818),(0x113818,0x113898),(0x113D28,0x114010),
    (0x135760,0x135770),(0x138EB8,0x138F68),(0x138FB0,0x139010),
    (0x139078,0x1390A8),(0x111550,0x111580),(0x10C368,0x10C388),
    (0x1682D8,0x168318),(0x169E68,0x169F08),(0x168A60,0x168AC8),
    (0x168B60,0x168BC8),(0x169B08,0x169B18),(0x1697D0,0x1698A0),
    (0x16B7B0,0x16B8D8),(0x18E840,0x18EF38),
    (0x176F78,0x177138),(0x177138,0x177490),(0x177490,0x1777A8),
    (0x177FF8,0x178030),(0x178910,0x178A10),
    (0x179DE0,0x179E58),(0x176970,0x1769E0),(0x176C48,0x176D98),
    (0x179C40,0x179CBC),
    (0x113068,0x113094),(0x1127CC,0x1127F4),(0x1129DC,0x112A18),
    (0x179B58,0x179C40),
]


def analyze(image,script):
    if hashlib.sha256(script).hexdigest()!=SCRIPT_SHA:raise ValueError('Script SHA mismatch')
    base=build_report(image,ROOT/'local/extracted/SLPM_664.52')
    classes=[c for c in base['handler_classes'] if set(c['opcodes'])&set(OPCODES)]
    regions={}
    for c in classes:
        start=int(c['constructor'],16)
        end=min(int(x['constructor'],16) for x in base['handler_classes'] if int(x['constructor'],16)>start)
        regions[f'{start:08x}-{end:08x}']=image.region(start,end)
    for a,z in REGIONS:regions[f'{a:08x}-{z:08x}']=image.region(a,z)
    for region in regions.values():
        for row in region['instructions']:
            row['extended_decode']=extended_decode(int(row['raw_word'],16),int(row['address'],16))
    rows=Script(script).instructions(15)
    samples={hx(op):[] for op in OPCODES}
    for row in rows:
        if row['opcode'] in OPCODES and len(samples[hx(row['opcode'])])<6:
            parsed=parse_scalar(script,row['offset'])
            assert parsed['end_exclusive']==row['end_exclusive']
            samples[hx(row['opcode'])].append(parsed)
    command_table=[]
    for command,(address,count) in COMMANDS.items():
        a=0x205640+8*command
        assert image.word(a)==address and image.word(a+4)==count
        command_table.append({'command_id':command,'count_metadata':image.word(a+4),
            'target':hx(address),'table_words':[image.record(a),image.record(a+4)]})
    constants=[image.record(a) for a in (0x235F78,0x235F7C,0x235F80,0x235F84,
        0x237BA4,0x237BA8,0x237BAC,0x237BB0,0x237BB4,0x237BB8,0x237BBC,0x237BC0,0x237BC4)]
    return {'schema_version':1,'evidence_id':'VM-SCALAR-001',
        'method':'source-bound local static MIPS analysis; no target execution or REA provider output',
        'source':{'elf_sha256':image.sha256,'script_sha256':SCRIPT_SHA},
        'handler_classes':classes,'evidence_regions':regions,'samples':samples,
        'command_table':command_table,'float_constant_words':constants,
        'semantics':{
            '17':'setting18!=0 returns0. Otherwise manager+2D0!=0 rewindsopcode/return1; zero advances/return0.',
            '1E':'138FB0 false rewindsopcode/return1; true advances/return0. No setting18 bypass at handler.',
            '6F':'135760&&manager+2D0==0 required BEFORE parsing. Header skipped;BE32id/u8argc/BE32args. setting18 consumes and skips. Normal113610 sets2D0=1,2D8/2DC=0,calls113D28 dispatch205640+8id;storesreturnedtask at2D4;return0. Original argc>=10 returnsnull after reading; reference rejects unsupported rather than pretend valid.',
            '2F':'16B7B0(128),16B7F0(0):both font channels default+8=128,+C=0; existing nodes untouched.',
            '40':'u8 value ->manager29C;manager294=0. setting18 forcesvalue0. No reset of298 here.',
            'text_cadence':'11306C increments294 unsigned until>=29C then294=0/298=1;29C0 sets298=1.1127CC unready non8140 unit rewinds2 andreturns1;112A08 clears298 if29C!=0 after consumption path.',
            '46':'u8delta added main font+4; then169E68 setssecondaryx=mainvslot0,y=mainvslot1-secondaryvslot2+secondary24,font24=x-16. Virtual return dependency remains.',
            '50':'BE32signed ->manager2EC,2E8=0;setting18forces0;alwaysreturn1,neverrewind.113818 decrementspositivecount eachinvocation,zero stayszero,negative persists;113888 blocks while nonzero.',
            '5C':'BE32signed n,setting18forces0. For every existing node inbothchannels current=128 ifn!=0 else0;delta=-128/n or0. Doesnotchangechanneldefaults.',
            'completion':'65/67task ->179C80 removal request ->10C368->111568->113680 clears2D0/2D8/2DC; leaves2D4 handle.17 thenunblocks.'},
        'draw_contract':{'65':effect_draw_contract(make_effect_task(0x65,[30],'example')),
            '67':effect_draw_contract(make_effect_task(0x67,[0,0,60,0,0,0],'example')),
            'provenance':'Generated from literal instructions, not screenshot matching.'},
        'external_gs_reference':{'title':'PCSX2 official OpenGL GS shader, fog()',
            'url':'https://raw.githubusercontent.com/PCSX2/pcsx2/master/bin/resources/shaders/opengl/tfx_fs.glsl',
            'access_date':'2026-10-30','scope':'Corroborates F/256 fog interpolation; separate external hardware interpretation, not evidence from game ELF.',
            'related':'https://github.com/PCSX2/pcsx2-net-www/blob/main/blog/2026/pcsx2-2.8/index.mdx'},
        'limitations':['Host float32 is not bit-exact R5900 FPU;65 divide-by-zero is deliberately blocked.',
            'Task scheduler update/draw order, framebuffer texture lifetime, render layers and GS blending are not fully implemented.',
            'Effect67 is textured fog modulation, not a255-scaled alpha overlay;65 is a textured alpha transition, not a solid black rectangle.',
            'Only native commands65/67 have bounded task models; other6Fcommands fail closed.',
            'Full138FB0 queue status and46virtual metric sources are explicit backend inputs.',
            'Defaults inScalarState are test placeholders, not proof of original initialization.',
            'Callbacks and required_actions are integration obligations; tests cannot prove actual graphics/audio/runtime behavior.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    p.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    p.add_argument('--out',type=Path,default=ROOT/'analysis/vm_scalar_semantics.json')
    args=p.parse_args()
    if args.out.resolve() in {args.elf.resolve(),args.script.resolve()}:raise ValueError('Refuse source overwrite')
    result=analyze(Image(args.elf.read_bytes()),args.script.read_bytes())
    args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence_id':result['evidence_id'],'handlers':len(result['handler_classes']),
        'regions':len(result['evidence_regions']),'samples':sum(map(len,result['samples'].values()))}))


if __name__=='__main__':main()
