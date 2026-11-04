"""Hash-bound text-control contracts; the original ELF is never executed.

Logical reducers use the font shape of vm_page_semantics. Renderers, history,
menus and transfers are explicit obligations, never assumed successful NOPs.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from vm_handlers import Image, ROOT, build_report, hx
from vm_presentation_semantics import UnresolvedDependency, extended_decode, s32, f32, wait_predicate
from opening_instructions import SCRIPT_SHA, frame_one
from choice_branch import Script

INIT_OPCODES=(0x41,0x45,0x54,0x56,0x5E,0x60,0x62,0x64)
OPCODES=(0x09,0x0C,0x1A,0x23,0x32,0x4C,0x4D,0x65,0x66)+INIT_OPCODES
LOOKAHEAD_STOP={0x04,0x09,0x1A,0x65,0x66,0x6A,0x6B,0x6C,0x85}
DYNAMIC_MODES={0x0D:0,0x0E:1,0x0F:4,0x10:2,0x11:3}


def retail_setting(index):
    """175F78 is jr ra; daddu v0,zero,zero, independent of index."""
    if type(index) is not int:raise TypeError('Integer original index required')
    return 0


def parse(data,offset,limit=None):
    limit=min(len(data),len(data) if limit is None else limit)
    if not 0<=offset<limit or data[offset] not in OPCODES:raise ValueError('Unsupported text control')
    row=frame_one(data,offset,limit);op=row['opcode'];raw=data[offset+1:row['end_exclusive']]
    if op==0x4C:row.update(style=raw[0],size=raw[1])
    elif op==0x4D:row['width']=int.from_bytes(raw,'big')
    elif op in (0x65,0x66):
        row['x']=int.from_bytes(raw[:2],'big',signed=op==0x65)
        row['y']=int.from_bytes(raw[2:],'big',signed=op==0x65)
    elif op in INIT_OPCODES:
        row['raw_unsigned']=int.from_bytes(raw,'big')
        row['value']=s32(row['raw_unsigned']) if len(raw)==4 else row['raw_unsigned']
    return row


def _sync(font):
    p,r=font['primary'],font['ruby']
    r['x']=p['x'];r['y']=s32(p['y']-r['size']+r['vertical_offset'])
    font['anchor_x']=s32(p['x']-16)


def _line(font):
    p=font['primary'];p['x']=font['origin_x']
    p['y']=s32(p['y']+p['size']+p['line_spacing'])
    font['line_count']=s32(font['line_count']+1)


def initialize_control(state,opcode,value):
    """12FA88 shared default-slot15 persistent layout/cadence settings.

No glyph clear, asset load or scheduler frame is implicit. 45 stores the u8 in
manager328 but sign-extends it into ruby+24. Unlike position(), it does not sync.
"""
    if opcode not in INIT_OPCODES:raise ValueError('Unsupported initialization control')
    if opcode in (0x41,0x45) and not 0<=value<=255:raise ValueError('Expected u8 value')
    out=deepcopy(state);m=out['manager'];f=out['font'];p=f['primary']
    value=s32(value)
    fields={0x41:'plus31c',0x45:'plus328',0x54:'plus324',0x56:'plus320',
            0x5E:'plus310',0x60:'plus314',0x62:'plus30c',0x64:'plus318'}
    m[fields[opcode]]=value
    if opcode==0x41:m['plus29c']=value;m['plus294']=0
    elif opcode==0x45:f['ruby']['vertical_offset']=value if value<128 else value-256
    elif opcode==0x54:p['letter_spacing']=value
    elif opcode==0x56:p['line_spacing']=value
    elif opcode==0x60:f['right_limit']=s32(640-value)
    elif opcode==0x64:f['bottom_limit']=s32(448-value)
    else:
        was_at_origin=p['x']==f['origin_x'] and p['y']==f['origin_y']
        axis='x' if opcode==0x5E else 'y';f['origin_'+axis]=value
        if p[axis]<value:p[axis]=value;_sync(f)
        if was_at_origin:
            p['x']=f['origin_x'];p['y']=f['origin_y'];_sync(f);f['line_count']=0
    return dict(state=out,handler_return=0)


def style_size(font,style,size,default_size=None):
    """16A6B0: size0 uses descriptor default; 255 independently preserves."""
    out=deepcopy(font);p=out['primary']
    if not 0<=style<=255 or not 0<=size<=255:raise ValueError('Expected two u8 values')
    if style!=255:p['style']=style
    if size==0:
        if default_size is None:raise UnresolvedDependency('16BF88 descriptor default primary size')
        size=default_size
    if size!=255:p['size']=size
    return out


def position(font,x,y,relative=False):
    """65 signed delta /66 unsigned absolute; both synchronize ruby via169E68."""
    out=deepcopy(font);p=out['primary']
    p['x']=s32(p['x']+x) if relative else x
    p['y']=s32(p['y']+y) if relative else y
    _sync(out);return out


def decoration(font,width,atlas_handle):
    """4D logical three-node horizontal decoration, including original UVs.

Atlas0 object+70 must be resolved by caller. Does not draw or substitute a dash
font glyph. Width<6 intentionally preserves the original inverted middle quad.
"""
    if type(width) is not int or not 0<=width<=65535:raise ValueError('Expected BE16 width')
    if atlas_handle is None:raise UnresolvedDependency('10B290(0) atlas object+70')
    out=deepcopy(font);p,r=out['primary'],out['ruby'];wrapped=False
    if out['right_limit']<s32(p['x']+width) and p['x']!=out['origin_x']:
        _line(out);wrapped=True
    if s32(r['y']+r['size'])<p['y']:_sync(out)
    elif r['x']<p['x']:r['x']=p['x']
    # Original adds2 to y for drawing, then subtracts2; division rounds to zero.
    half=int((s32(p['size']-8))/2)
    x=p['x'];y=s32(p['y']+2+half);ch=out['channels'][0]
    xs=[x,s32(x+3),s32(x+width-3),s32(x+width)]
    us=[0.9375,0.9609375,0.9765625,1.0];nodes=[]
    for i in range(3):
        node=dict(kind='atlas0-horizontal-decoration',xyxy=[xs[i],y,xs[i+1],s32(y+8)],
            uvuv=[us[i],0.375,us[i+1],0.4375],rgb=list(p['rgb']),
            current=ch['plus08'],step=ch['plus0c'],atlas_handle=atlas_handle,
            source_entry='0x00168fc0')
        ch['glyphs'].append(node);nodes.append(node)
    p['x']=s32(x+width+p['letter_spacing'])
    return dict(font=out,nodes=deepcopy(nodes),wrapped=wrapped,handler_return=0)


def range_transition(font,range_state):
    """32: change node+8 in recorded inclusive ranges, defaults both128."""
    out=deepcopy(font)
    for ch,start in zip(out['channels'],[range_state['plus0c'],range_state['plus10']]):
        nodes=ch['glyphs']
        if not 0<=start<=len(nodes):raise UnresolvedDependency('Original out-of-range iterator behavior')
        for node in nodes[start:]:node['step']=f32(range_state['plus14'])
        ch['plus08']=128.0;ch['plus0c']=128.0
    return out


def lookahead09(data,offset,font,metrics,*,limit=None,default_size=None,
                context_vtable=0x2239F0,dispatch_style=None,dynamic_width=None,max_steps=4096):
    """122EF8 cursor-preserving width scan, not sequential VM execution.

metrics.lookup(unit,style,size)['width'] is raw glyphrecord+4, even for8140.
dispatch_style(op,value,font)->font is required for42/43 or nondefault4C.
dynamic_width(mode,data,operand_offset,font)->int models10D468 completely.
"""
    limit=min(len(data),len(data) if limit is None else limit)
    out=deepcopy(font);saved=(out['primary']['style'],out['primary']['size'])
    pos=offset;width=0;trace=[]
    def take(n):
        nonlocal pos
        if pos<0 or pos+n>limit:raise ValueError('Truncated09 lookahead')
        result=data[pos:pos+n];pos+=n;return result
    for _ in range(max_steps):
        at=pos;op=take(1)[0];trace.append({'offset':at,'opcode':op})
        if op in LOOKAHEAD_STOP:break
        if op==2:
            while take(1)[0]==0x21:pass
            pos-=1;unit=int.from_bytes(take(2),'big')
            p=out['primary'];width=metrics.lookup(unit,p['style'],p['size'])['width']
            trace[-1].update(unit=unit,width_replaces_accumulator=width);break
        if op in DYNAMIC_MODES:
            if dynamic_width is None:raise UnresolvedDependency('10D468 dynamic insertion width')
            width=dynamic_width(DYNAMIC_MODES[op],data,pos,deepcopy(out));break
        if op in (0x46,0x4D):width=s32(width+int.from_bytes(take(1 if op==0x46 else 2),'big'))
        elif op in (0x42,0x43,0x4C):
            values=take(2 if op==0x4C else 1)
            if op==0x4C and context_vtable==0x2239F0:
                out=style_size(out,values[0],values[1],default_size)
            else:
                if dispatch_style is None:raise UnresolvedDependency('Current-context slot2 style delegation')
                out=dispatch_style(op,bytes(values),deepcopy(out))
        else:pos=frame_one(data,at,limit)['end_exclusive']
    else:raise UnresolvedDependency('09 lookahead exceeded bounded step count')
    out=style_size(out,*saved,default_size=default_size)
    wrapped=width>0 and out['right_limit']<s32(out['primary']['x']+width)
    if wrapped:_line(out)
    return dict(font=out,cursor=offset,width=width,wrapped=wrapped,trace=trace)


def begin09(state,scanned_font,indicator):
    """1231C0, after successful lookahead. Callback mutates private copy."""
    out=deepcopy(state);out['font']=deepcopy(scanned_font);m=out['manager']
    if out['objects']['object2c_plus00']!=0:return dict(state=out,handler_return=0)
    if m['plus808']!=0:m['plus814']=m['plus80c']
    out['context_vtable']=0x2239B0
    if indicator is None:raise UnresolvedDependency('16CAD0 wait indicator')
    indicator(out)
    return dict(state=out,handler_return=1)


def tick09(state,input_mask,indicator):
    """11FE80 ->120160. Return1 even on acceptance; no1195B0 override."""
    out,accepted,reason=wait_predicate(state,input_mask)
    if accepted:
        out['context_vtable']=0x2239F0
        if indicator is None:raise UnresolvedDependency('16CB10 wait indicator completion')
        indicator(out)
    return dict(state=out,accepted=accepted,context_return=1,reason=reason)


def paragraph0c(state,*,mark_current=None,record_visit=None,special_reset=None,
                special_transfer=None):
    """1243E8/123558, retail175F78=0. External history callbacks are mandatory.

object20_flag5 is the119EB0(object20,5) predicate, not a guessed bitfield.
The normal path yields1 without installing0B context or issuing16CB40.
"""
    out=deepcopy(state);m=out['manager'];o=out['objects']
    if m['plus2c0']:
        if mark_current is None:raise UnresolvedDependency('10EDC0 current label mark')
        mark_current(out)
    if o['object20_plus04'] and o['object20_flag5']:
        return dict(state=out,handler_return=0)
    if o['object30_plus00']:
        if special_reset is None:raise UnresolvedDependency('11A5C8 object30 reset')
        special_reset(out);return dict(state=out,handler_return=0)
    if m['plus808']:m['plus814']=m['plus810']
    if record_visit is None:raise UnresolvedDependency('10ECA0(currentD4,0,0) visit/history')
    record_visit(out)
    if o['object2c_plus00']:
        if special_transfer is None:raise UnresolvedDependency('10DAF0 object2c+C/+10 transfer')
        special_transfer(out)
    return dict(state=out,handler_return=1)


def end1a(state,header_entry,*,close_menu=None,end_recording=None,transfer=None):
    """133F60 retail path, including temporary script168 suppression.

close_menu(out) models121760; end_recording(out,0) models114AE0 when active;
transfer(out,label,1) must implement10F9B0+10D868 including control/history.
Callbacks mutate only the private state. Original field names are deliberate.
"""
    out=deepcopy(state)
    if close_menu is None:raise UnresolvedDependency('121760 manager+854 menu teardown')
    close_menu(out);runtime=out['script_runtime'];saved=runtime['plus168'];runtime['plus168']=0
    if out['manager']['plus32c_active']:
        if end_recording is None:raise UnresolvedDependency('114AE0 recording end')
        end_recording(out,0)
    if transfer is None:raise UnresolvedDependency('10F9B0 +10D868 entry transfer')
    transfer(out,header_entry,1)
    out['script_runtime']['plus168']=saved;out['script_runtime']['plus16c']=0
    return dict(state=out,handler_return=1)


def stub23(state):
    """12E640->135C90(jr ra;nop), then handler returns1."""
    return dict(state=deepcopy(state),handler_return=1)


REGIONS=[(0x175F78,0x175FA0),(0x135C90,0x135C98),
 (0x122EF8,0x123258),(0x11FDB0,0x11FDC0),(0x11FE80,0x11FF50),
 (0x123558,0x123668),(0x1243E8,0x1244FC),
 (0x168318,0x168398),(0x16A6B0,0x16A748),(0x16A8C8,0x16A998),
 (0x1326E0,0x132790),(0x16B670,0x16B750),(0x16ACC0,0x16ADC0),
 (0x168FC0,0x169218),(0x169AB0,0x169AF0),(0x169E68,0x169F08),
 (0x113A48,0x113AE0),(0x16B750,0x16B910),(0x168BC8,0x168C60),
 (0x16B910,0x16B980),(0x133F60,0x134000),(0x10D260,0x10D300),
 (0x10FAB8,0x10FAD0),(0x115CC8,0x115CE8),
 (0x16A420,0x16A6B0),(0x16A860,0x16A8C8),(0x16AF30,0x16AF68),
 (0x1686D0,0x1686E0),(0x111550,0x111560),
 (0x16C710,0x16C7B0),(0x16CAD0,0x16CBE0),(0x110820,0x110830),(0x1135F8,0x113610)]


def analyze(image,script):
    if hashlib.sha256(script).hexdigest()!=SCRIPT_SHA:raise ValueError('Script SHA mismatch')
    assert [image.word(a) for a in (0x175F78,0x175F7C)]==[0x03E00008,0x0000102D]
    assert [image.word(a) for a in (0x135C90,0x135C94)]==[0x03E00008,0]
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
    program=Script(script);samples={f'{op:02x}':[] for op in OPCODES}
    for row in program.instructions(15):
        op=row['opcode']
        if op in OPCODES and len(samples[f'{op:02x}'])<6:
            samples[f'{op:02x}'].append(parse(script,row['offset']))
    entry=[]
    for offset in (0x20,0x60):
        raw=script[offset:offset+64];name=raw.split(b'\0',1)[0].decode('ascii')
        entry.append(dict(offset=offset,label=name,raw_hex=raw.hex(),raw_sha256=hashlib.sha256(raw).hexdigest()))
    header_initialization=[parse(script,row['offset']) for row in program.instructions(17)
        if row['offset']<0xAD499 and row['opcode'] in INIT_OPCODES]
    assert [r['value'] for r in header_initialization]==[32,32,32,32,0,7,6,1]
    return dict(schema_version=1,evidence_id='VM-TEXT-CONTROLS-001',
        method='Local static MIPS evidence + bounded Python contracts; no target execution or REA provider output',
        source=dict(elf_sha256=image.sha256,script_sha256=SCRIPT_SHA),
        handler_classes=classes,evidence_regions=regions,samples=samples,header_entries=entry,
        header_initialization=header_initialization,
        initialization_dispatch=[dict(opcode=op,table_word=image.record(0x22AAC8+4*(op-0x41),False)) for op in INIT_OPCODES],
        lookahead_dispatch=[dict(opcode=i,target=hx(image.word(0x22A6B0+4*i))) for i in range(0x86)],
        constants=[image.record(a,False) for a in (0x235E5C,*range(0x236EF4,0x236F0C,4))],
        semantics={
          'settings':'175F78 and175F80 unconditionally return0 in this build.175F88 is a separate array getter; no equivalence assumed.',
          'wait_indicator_completion':'16CBC8 invokes16C790(slot1),09completion16CB10 invokes16C790(slot0). Each slot is188bytes at1E44200+188*slot;clear+4 and+0 only;no font/cursor effects.',
          'cold_effect_fields':'110824 calls1135F8(manager+2D0),which clears+4/+0/+8/+C;effect active/handle/flags startzero.',
          '09':'122EF8 preserves cursor and primary style/size; scans width, may lineadvance even atorigin. Text02 and0D..11 replace accumulated width.1231C0 object2c active returns0; elsecopytimer80c->814 if808,install2239B0,16CAD0,return1.11FE80 accepts via120160;restore2239F0+16CB10;alwaysreturn1.',
          '0C':'Shared0B gates/history/timer810->814, normal branch returns1 without changingcontext or calling16CB40. object2c path10DAF0 remains explicit dependency.',
          '4C':'Two u8 primary style/size.255preserves independently;size0loadsdescriptor default.',
          '4D':'BE16width;conditionalwrap then16ACC0align. Threeatlas0 horizontalquads,8high,3/n-6/3wide;RGBprimary;channeldefaultcurrent/step. Advance x bywidth+spacing. Atlashandle is10B290(0)+70.',
          '65':'Two signedBE16 deltas addprimaryx/y;sync rubyandanchor via169E68.',
          '66':'Two unsignedBE16 absoluteprimaryx/y;sync rubyandanchor via169E68.',
          '32':'manager2F0+C/+10 savedglyphindexes..count-1 get node+8=manager2F0+14 float. Bothchanneldefault+8/+C become128.',
          '23':'135C90 is proven empty jrra;nop. Default handler yields1.',
          '1A':'Retail:121760 menu teardown;save script168,set0;end active32Crecording;resolve header+20 label and10D868(flag1);restore168;clear16C;return1.',
          '41':'u8 ->manager31C and29C,reset294=0;298unchanged.',
          '45':'u8 ->manager328;signextend8 ->rubyvertical_offset(+24);noimmediatealignment.',
          '54':'BE32 ->manager324 andprimaryletter_spacing.',
          '56':'BE32 ->manager320 andprimaryline_spacing.',
          '5E_62':'BE32 ->manager310/30C andfontoriginx/y. If currentprimarywasatoldoriginXY,resetbothaxes toneworigin,syncruby,clearlinecount. Elseclampchangedaxisupwardonlyifbelowneworigin,andthen syncruby. No glyph clear.',
          '60_64':'BE32 ->manager314/318;right_limit=640-value/bottom_limit=448-value (s32).'},
        limitations=['09 42/43 currentcontext delegates and0D..11dynamic insertion require callbacks; synthetic tests do not establish target runtime behavior.',
          '0C history, exceptional object state;1A menu/recording/control transfer require real backend callbacks.',
          '4D exact texture pixel content/allocation/rendering not implemented here; geometry/UV established. Iterator range validation is defensive, not original error behavior.',
          'No1A or23 sample in block15 is synthesized if absent. Othercontexts retain raw vtables but are not claimed equivalent toslot15.',
          'Logical font shape assumes known baseclass methods; altered virtualclasses require separate proof. Hostfloat32 is not bit-exact R5900.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    p.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    p.add_argument('--out',type=Path,default=ROOT/'analysis/vm_text_controls.json')
    a=p.parse_args()
    if a.out.resolve() in {a.elf.resolve(),a.script.resolve()}:raise ValueError('Refuse source overwrite')
    report=analyze(Image(a.elf.read_bytes()),a.script.read_bytes())
    a.out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(evidence_id=report['evidence_id'],classes=len(report['handler_classes']),
        regions=len(report['evidence_regions']),samples=sum(map(len,report['samples'].values())))))


if __name__=='__main__':main()
