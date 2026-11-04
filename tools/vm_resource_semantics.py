"""Verified-build resource/choice contracts for 72/73/74, 7F and normal 6C.

No ELF execution or resource loading. A native integration must explicitly
provide each loader/lookup/activation dependency; absent callbacks are errors.
The cursor indexes the caller's byte buffer, not a guessed native address.
"""
import argparse
import copy
from dataclasses import asdict, dataclass, is_dataclass
import hashlib
import json
from pathlib import Path

from vm_handlers import Image, ROOT, build_report, direct_edges, hx
from vm_presentation_semantics import UnresolvedDependency, extended_decode, s32
from opening_instructions import SCRIPT_SHA, START, END, frame_window
from choice_branch import CHOICE_OFFSET, Script, decode_operands

OPCODES=(0x72,0x73,0x74)
CHOICE7F_OFFSET=0xAD615
DEPENDENCIES={
    0x137350:'request_ready() -> bool',
    0x11E310:'begin_request(token_bytes, mode) -> pending_group_id; implements lookup101B58 and request137578/137598',
    0x135618:'request_completed() -> bool',
    0x135660:'finalize_request() -> None; original11E3B8 copies pending to active before this call',
    0x101CA8:'lookup_cue(active_group_id, token_bytes) -> opaque cue or None/0',
    0x101DC0:'fallback_name() -> token_bytes; semantic source of this name remains a registry dependency',
    0x138E10:'activate_cue(opaque_cue, token_bytes) -> None; includes138C90 and1395A8',
    0x101928:'cue_index(token_bytes) -> signed32 index; original writes ScriptData+E0',
    0x100EC8:'read_variable(id) -> integer',
    0x100EE0:'write_variable(id, value)',
    0x1AC690:'7F preparation side effect; unresolved subsystem',
    0x1133F0:'push manager+294 timing state via1163E8',
    0x1133D0:'pop manager+294 timing state via116470',
    0x135BD8:'register graphical choice(options, fallback); frontend later supplies done and index',
    0x1114F8:'font/manager reset with original side effects',
    0x1114F0:'install manager context(singleton name); precedes dependent backend effects',
    0x111550:'write manager+29C=value and manager+294=0',
    0x10DAF0:'restore block and label ID, original lookup10FA28; caller next overwrites cursor',
    0x10D868:'transfer(position, selector, label_bytes, flag) -> ScriptPosition; includes history/readstate',
    0x14BCC0:'special-mode option eligibility(original_index) -> bool',
    0x115E58:'choose from filtered options, including appended fallback -> valid index',
    0x19C910:'choice_begin_hook(position, alternate_context_flag); resolve current label to string before native call',
    0x10EDC0:'lookup current D4 history record via10E630 and OR word0 bit31; preserve014C/0150 (see CHOICE_RUNTIME_AUDIT.md)',
    0x117560:'predicate on manager+04 object, gates choice seen-mark',
    0x10ECA0:'mark label(label_id, second_flag, third_flag)',
    0x113448:'manager+58 ->17D380 subsystem action',
    0x16AB38:'font main virtual slot0 result',
    0x16AB60:'font main virtual slot1 result',
    0x16A788:'push font virtual slot4 then slot2 results to font+2C stack',
    0x16A6B0:'font control setters1684F0/168340(a1,a2)',
    0x16AA98:'set font colors via16A9F0(128,128,128,0,0,0)',
    0x16A8C8:'add main font coordinates then secondary alignment169E68(a1,a2)',
    0x16A698:'get main font168388 control',
    0x16A668:'get main font168398 control',
    0x10D7D0:'select runtime template(index) -> ScriptPosition; original selector32+index',
    0x16A7E8:'pop font stack to168340 then1684F0',
    0x19CAD8:'selection notification(index)',
    0x16A950:'restore main font coordinates and secondary alignment(a1,a2)',
    0x117EE8:'selected glyph ranges transition(choice_state, float_value)',
    0x16BA10:'font animation/pending predicate before6C commit',
}


@dataclass
class ResourceState:
    provider_plus08:int=0
    provider_plus0c:int=0
    provider_plus10:int=0
    manager_plus718:int=0
    manager_plus71c:int=0
    manager_plus720:int=0
    script_plus_e0:int=-1
    cursor:int=0


def parse_operand(data,offset,limit=None,max_token_bytes=4096):
    """10D638 then10D680: skip marker(plus2 if zero), consume C string.

The declared payload length does not control this handler's C-string cursor.
Defensive bounds are stricter than unchecked original reads. Retain mismatches.
"""
    limit=min(len(data),len(data) if limit is None else limit)
    if offset<0 or offset+2>limit or data[offset] not in OPCODES:
        raise ValueError('Invalid/truncated resource opcode/header')
    marker=data[offset+1]
    width=1 if marker else 3
    payload=offset+1+width
    if payload>limit:
        raise ValueError('Truncated extended header')
    declared=marker if marker else int.from_bytes(data[offset+2:payload],'big')
    end=data.find(b'\0',payload,min(limit,payload+max_token_bytes))
    if end<0:
        raise ValueError('Resource C string is unterminated within bounds')
    token=bytes(data[payload:end])
    try:decoded=token.decode('ascii')
    except UnicodeDecodeError:decoded=None
    return {'opcode':data[offset],'offset':offset,'payload_offset':payload,
        'end_exclusive':end+1,'header_bytes':width,'declared_payload_bytes':declared,
        'actual_cstring_bytes':len(token)+1,'declared_matches_cstring':declared==len(token)+1,
        'token_hex':token.hex(),'token_ascii':decoded,'raw_hex':data[offset:end+1].hex(),
        'raw_sha256':hashlib.sha256(data[offset:end+1]).hexdigest()}


class Calls:
    def __init__(self,callbacks):
        self.callbacks=callbacks
        self.events=[]

    def invoke(self,address,*args):
        if address not in self.callbacks:
            raise UnresolvedDependency(f'{hx(address)} {DEPENDENCIES[address]}')
        self.events.append({'address':hx(address),'arguments':[_evidence_value(a) for a in args]})
        return self.callbacks[address](*args)

    def predicate(self,address):
        value=self.invoke(address)
        if value not in (False,True,0,1):
            raise ValueError(f'{hx(address)} must return original boolean result')
        return bool(value)


def _evidence_value(value):
    if is_dataclass(value):return _evidence_value(asdict(value))
    if isinstance(value,bytes):return {'bytes_hex':value.hex()}
    if isinstance(value,(tuple,list)):return [_evidence_value(x) for x in value]
    if isinstance(value,dict):return {str(k):_evidence_value(v) for k,v in value.items()}
    return value


@dataclass
class ScriptPosition:
    selector:int
    label_id:int
    cursor:int


def _transfer(calls,position,option,flag):
    result=calls.invoke(0x10D868,copy.deepcopy(position),option['block_selector'],
        bytes.fromhex(option['label_hex']),flag)
    if not isinstance(result,ScriptPosition):
        raise ValueError('10D868 adapter must return ScriptPosition and implement its history side effects')
    return copy.deepcopy(result)


def parse_graphical_choice(data,offset,limit=None,max_options=64):
    """7F: skipped header, u8 count, count*(u8 selector,Cstring), fallback pair."""
    limit=min(len(data),len(data) if limit is None else limit)
    if offset<0 or offset+2>limit or data[offset]!=0x7F:
        raise ValueError('Invalid graphical choice/header')
    marker=data[offset+1];width=1 if marker else 3
    pos=offset+1+width
    if pos>=limit:raise ValueError('Truncated graphical choice payload')
    declared=marker if marker else int.from_bytes(data[offset+2:pos],'big')
    payload=pos;count=data[pos];pos+=1
    if count>max_options:raise ValueError('Defensive option limit exceeded')
    def pair():
        nonlocal pos
        if pos>=limit:raise ValueError('Truncated selector')
        selector=data[pos];pos+=1
        end=data.find(b'\0',pos,limit)
        if end<0:raise ValueError('Unterminated graphical target')
        raw=bytes(data[pos:end]);pos=end+1
        return {'block_selector':selector,'label_hex':raw.hex(),
            'label_ascii':raw.decode('ascii') if raw.isascii() else None}
    options=[pair() for _ in range(count)];fallback=pair()
    raw=data[offset:pos]
    return {'opcode':0x7F,'offset':offset,'end_exclusive':pos,'payload_offset':payload,
        'declared_payload_bytes':declared,'actual_payload_bytes':pos-payload,
        'declared_matches_payload':declared==pos-payload,'option_count':count,
        'options':options,'fallback':fallback,'raw_hex':raw.hex(),
        'raw_sha256':hashlib.sha256(raw).hexdigest()}


def graphical_choice_begin(record,position,old_context,manager_plus808,callbacks):
    """12E180, normal119A18 or automatic115E58 branch. No fabricated UI."""
    if record['opcode']!=0x7F:raise ValueError('Expected7F record')
    calls=Calls(callbacks);options=copy.deepcopy(record['options'])
    fallback=copy.deepcopy(record['fallback']);position=copy.deepcopy(position)
    position.cursor=record['end_exclusive']
    value=calls.invoke(0x100EC8,4)
    calls.invoke(0x100EE0,0x19B,value)
    calls.invoke(0x1AC690)
    if manager_plus808:
        filtered=[]
        for index,option in enumerate(options):
            eligible=calls.invoke(0x14BCC0,index)
            if eligible not in (False,True,0,1):raise ValueError('Eligibility must be boolean')
            if eligible:filtered.append(option)
        filtered.append(fallback)
        index=calls.invoke(0x115E58,copy.deepcopy(filtered))
        if type(index) is not int or not 0<=index<len(filtered):raise ValueError('Invalid selected index')
        position=_transfer(calls,position,filtered[index],0)
        return {'position':position,'context':old_context,'choice':None,'handler_return':0,
            'filtered_options':filtered,'selected_index':index,'events':calls.events}
    if len(options)>6:
        raise ValueError('Normal7F would overlap fallback storage beyond six option pairs')
    calls.invoke(0x1133F0)
    calls.invoke(0x111550,0)
    calls.invoke(0x1114F0,'singleton120880/vtable223A50')
    choice={'options':options,'fallback':fallback,'old_context':old_context,
        'done_plus00':0,'selected_plus04':-1,'active_plus50':0}
    calls.invoke(0x135BD8,copy.deepcopy(options),copy.deepcopy(fallback))
    calls.invoke(0x1114F8)
    choice['active_plus50']=1;choice['saved_position']=asdict(position)
    return {'position':position,'context':'singleton120880/vtable223A50',
        'manager_plus294':0,'manager_plus29c':0,'choice':choice,'handler_return':1,'events':calls.events}


def graphical_choice_poll(choice,position,callbacks):
    """119B60 only.120900 returns inverse of this completion result.

The independent manager+18/119A10 path in120900 must be checked by integration.
"""
    out=copy.deepcopy(choice);calls=Calls(callbacks)
    if not out['done_plus00']:
        return {'choice':out,'position':copy.deepcopy(position),'completed':False,
            'poll_return':0,'context_return':1,'events':[]}
    index=out['selected_plus04']
    if type(index) is not int or (index!=-1 and not 0<=index<len(out['options'])):
        raise ValueError('Selected index outside original object storage')
    calls.invoke(0x1114F8)
    option=out['fallback'] if index==-1 else out['options'][index]
    saved=ScriptPosition(**out['saved_position'])
    calls.invoke(0x10DAF0,saved.selector,saved.label_id)
    #119BD8..119BE0 immediately overwrites lookup-relative cursor with saved+4C.
    position=_transfer(calls,saved,option,1 if index==-1 else 0)
    calls.invoke(0x1133D0)
    calls.invoke(0x1114F0,out['old_context'])
    out['active_plus50']=0
    return {'choice':out,'position':position,'context':out['old_context'],'completed':True,
        'poll_return':1,'context_return':0,'events':calls.events}


def choice6c_setup(operation,post_operand_position,context,callbacks,*,
        manager_mode=False,control_plus10=0,manager_plus808=0):
    """Normal default15/mode1/extra0/flags0 setup; rejects other paths.

The caller must supply source-bound operands and post-operand relative cursor.
Callbacks are semantic adapters (not literal C ABI), with backend state external.
Returned checkpoint is only the recovered choice state, not a full save file.
"""
    if (operation.get('kind')!='choice_setup' or operation.get('mode')!=1 or
        operation.get('extra_byte_count')!=0 or operation.get('extra_hex')!='' or
        operation.get('option_count')!=len(operation.get('options',[])) or
        not 1<=operation['option_count']<=10 or any(o['raw_flag']!=0 for o in operation['options']) or
        context!='default15' or manager_mode or control_plus10 or manager_plus808):
        raise UnresolvedDependency('6C contract requires default15, mode1, 1..10 flags0 options, extra0, normal manager/control state')
    calls=Calls(callbacks);position=copy.deepcopy(post_operand_position)
    calls.invoke(0x19C910,copy.deepcopy(position),0)
    before_xy=[calls.invoke(0x16AB38),calls.invoke(0x16AB60)]
    choice={'mode_plus0c':1,'count_plus04':operation['option_count'],
        'options':[{'block_selector':o['block_selector'],'label_hex':o['label'].encode('ascii').hex(),
            'raw_flag':o['raw_flag']} for o in operation['options']],
        'saved_position':asdict(position),'old_context_plus1c4':context,
        'plus1c8':0,'plus1cc':0,'plus1d0':0,'plus18c':0,'plus190':0,'plus194':0,'plus198':0,
        'render_index_plus08':0,'selected_index_plus168':0,'before_xy_plus16c_170':before_xy,
        'phase':'preview','rendered_options':[]}
    calls.invoke(0x10EDC0)
    if not calls.predicate(0x117560):calls.invoke(0x10ECA0,position.label_id,1,0)
    calls.invoke(0x113448);calls.invoke(0x16A788)
    calls.invoke(0x16A6B0,0,0);calls.invoke(0x16AA98);calls.invoke(0x16A8C8,0,0)
    choice['first_option_xy_plus78_a0']=[calls.invoke(0x16AB38),calls.invoke(0x16AB60)]
    choice['preview_controls_plus184_188']=[calls.invoke(0x16A698),calls.invoke(0x16A668)]
    calls.invoke(0x1114F0,'singleton11E958/preview-slot1')
    template=calls.invoke(0x10D7D0,0)
    if not isinstance(template,ScriptPosition) or template.selector!=32:
        raise ValueError('Template adapter must select runtime block32 for index0')
    return {'choice':choice,'position':template,'context':'singleton11E958/preview-slot1',
        'handler_return':0,'events':calls.events}


def choice6c_preview_ready(choice,rendered_options,callbacks):
    """Tail checkpoint after verified preview16 path through118414.

This is not a replacement for executing preview: the caller supplies one
completed render record per option, including XY and both glyph start/end
ranges, after118338 has run its font finalization/highlight/prompt actions.
Only the remaining118428..11847C effects are modeled here.
"""
    out=copy.deepcopy(choice)
    if out['phase']!='preview' or len(rendered_options)!=out['count_plus04']:
        raise ValueError('All option previews must finish before interactive checkpoint')
    required={'x','y','main_start','main_end','secondary_start','secondary_end'}
    if any(not required<=set(record) for record in rendered_options):
        raise ValueError('Incomplete original per-option render state')
    calls=Calls(callbacks);out['rendered_options']=copy.deepcopy(rendered_options)
    out['render_index_plus08']=out['count_plus04']-1
    calls.invoke(0x1114F0,'singleton11E6C8/interactive')
    calls.invoke(0x16A7E8)
    position=ScriptPosition(**out['saved_position'])
    #118444/454/460 are direct D0/D4/relative-cursor setters, not a label jump.
    calls.invoke(0x19CAD8,0)
    out['phase']='interactive'
    return {'choice':out,'position':position,'context':'singleton11E6C8/interactive',
        'events':calls.events,'preview_tail_return':1}


def choice6c_commit(choice,position,selected_index,callbacks):
    """11E608 readiness + normal118D68 commit after confirmation transition.

Input navigation and118288 confirmation-start effects are separate obligations.
They must have completed before this call; caller phase must be confirming.
"""
    out=copy.deepcopy(choice)
    if out['phase']!='confirming':raise UnresolvedDependency('6C input confirmation/118288 transition must complete first')
    if type(selected_index) is not int or not 0<=selected_index<out['count_plus04']:
        raise ValueError('Invalid selected index')
    if asdict(position)!=out['saved_position']:
        raise ValueError('6C commit requires restored original script position, not a runtime template')
    calls=Calls(callbacks)
    if calls.predicate(0x16BA10):
        return {'choice':out,'position':copy.deepcopy(position),'committed':False,
            'context_return':1,'events':calls.events}
    out['selected_index_plus168']=selected_index
    calls.invoke(0x16A950,*out['before_xy_plus16c_170'])
    calls.invoke(0x117EE8,copy.deepcopy(out),0.0)
    calls.invoke(0x1114F0,'singleton120280/default15')
    target=_transfer(calls,position,out['options'][selected_index],0)
    out['phase']='committed'
    return {'choice':out,'position':target,'context':'singleton120280/default15',
        'manager_plus28_object_plus14':1,'committed':True,'context_return':1,'events':calls.events,
        'ordinary_history_gate':position.label_id!=-1 and (position.selector&0xffffffff)<32}
def _begin(state,token,mode,calls):
    group_id=calls.invoke(0x11E310,token,mode)
    if not isinstance(group_id,int):
        raise ValueError('begin_request must return pending group identifier from101B58')
    state.provider_plus0c=s32(group_id)


def provider72(state,token,calls):
    """11DC40: mode1 request accepts immediately after start; not full completion."""
    if not calls.predicate(0x137350):return False
    _begin(state,token,1,calls)
    state.provider_plus08=2
    return True


def provider73(state,token,calls):
    """11DCF8: start/poll/finalize phases. Called by73 and74 fallback."""
    phase=s32(state.provider_plus08)
    if phase in (0,2):
        if not calls.predicate(0x137350):return False
        _begin(state,token,0,calls)
        state.provider_plus08=1
        return False
    if phase==1:
        if not calls.predicate(0x135618):return False
        state.provider_plus10=state.provider_plus0c
        calls.invoke(0x135660)
        state.provider_plus08=0
        return True
    return False


def provider74(state,token,calls):
    """11DDA8: 138F68 is constant1 in this build; resolve/activate or fallback."""
    cue=calls.invoke(0x101CA8,state.provider_plus10,token)
    if cue is not None and cue!=0:
        calls.invoke(0x138E10,cue,token)
        return True
    fallback=calls.invoke(0x101DC0)
    if not isinstance(fallback,bytes):
        raise ValueError('fallback_name must return bytes')
    provider73(state,fallback,calls)
    # The original discards the fallback return value and always retries74.
    return False


def step(data,state,callbacks,limit=None):
    """One default-slot15 dispatch, with explicit provider dependencies.

Returns a copied state. External callbacks may have their own effects and must
implement the recorded contracts. Completion is handler acceptance, not proof
that a movie/texture/audio is fully decoded or visually presented.
"""
    out=copy.deepcopy(state)
    record=parse_operand(data,out.cursor,limit)
    opcode=record['opcode'];token=bytes.fromhex(record['token_hex'])
    calls=Calls(callbacks)
    if opcode==0x73:
        out.manager_plus71c=1  #114A68, executed on every retry
        accepted=provider73(out,token,calls)
    elif opcode==0x74:
        old=s32(out.manager_plus720)
        out.manager_plus718=int(old==0)
        out.manager_plus720=s32(old+1)  #114A78, including retries
        accepted=provider74(out,token,calls)
        if accepted:
            index=calls.invoke(0x101928,token)
            if not isinstance(index,int):raise ValueError('cue_index must return integer')
            out.script_plus_e0=s32(index)
    else:
        accepted=provider72(out,token,calls)
    out.cursor=record['end_exclusive'] if accepted else record['offset']
    return {'state':out,'handler_return':0 if accepted else 1,'accepted':accepted,
        'operand':record,'events':calls.events,'scope':'default-slot15 reference contract; callbacks are integration obligations'}


REGIONS=[
    (0x10D638,0x10D6C8),(0x10F110,0x10F168),(0x114A50,0x114AA0),
    (0x11DAC0,0x11DB08),(0x11DC40,0x11DE28),(0x11E310,0x11E3D4),
    (0x11E498,0x11E4B0),(0x137350,0x137390),(0x135618,0x135660),
    (0x138F68,0x138F70),(0x138E10,0x138E30),
    (0x119A18,0x119C60),(0x120830,0x1209A8),(0x1133D0,0x113410),
    (0x1163E8,0x1164F8),(0x14BC98,0x14BD18),(0x115E58,0x115F88),
    (0x118200,0x118628),(0x1186E8,0x1189F8),(0x118D68,0x118E20),
    (0x11E608,0x11E660),(0x10D738,0x10D788),(0x10D868,0x10DB48),
    (0x19C910,0x19C9B8),(0x16A788,0x16A830),(0x117EE8,0x117F68),
    (0x11A210,0x11A2A0),(0x11A380,0x11A398),(0x16A8C8,0x16A994),
    (0x16AB38,0x16AB88),(0x117D08,0x117D60),
]


def analyze(image,script):
    if hashlib.sha256(script).hexdigest()!=SCRIPT_SHA:
        raise ValueError('Script SHA-256 mismatch')
    base=build_report(image,ROOT/'local/extracted/SLPM_664.52')
    classes=[c for c in base['handler_classes'] if set(c['opcodes'])&set((*OPCODES,0x6C,0x7F))]
    regions={}
    for c in classes:
        ctor=int(c['constructor'],16)
        following=min(int(x['constructor'],16) for x in base['handler_classes'] if int(x['constructor'],16)>ctor)
        key=f'{ctor:08x}-{following:08x}'
        regions[key]=image.region(ctor,following)
        methods=[int(v['target'],16) for v in c['vtable_entries'][:25]]
        c['all_context_slots']=[{'slot':i,'entry':hx(a),
            'direct_edges':direct_edges(image,a,min([v for v in methods if v>a]+[following]))}
            for i,a in enumerate(methods)]
    for a,z in REGIONS:regions[f'{a:08x}-{z:08x}']=image.region(a,z)
    for region in regions.values():
        for row in region['instructions']:
            row['extended_decode']=extended_decode(int(row['raw_word'],16),int(row['address'],16))
    # Fixed observed return at138F68 is why74 has no separate readiness callback.
    assert image.word(0x138F68)==0x03E00008 and image.word(0x138F6C)==0x24020001
    assert image.word(0x127C74)==0x14400004 and image.word(0x127940)==0x1040000B
    framed=frame_window(script,START,END)
    samples=[]
    for row in framed:
        if row['opcode'] not in OPCODES:continue
        decoded=parse_operand(script,row['offset'],END)
        assert decoded['end_exclusive']==row['end_exclusive']
        samples.append(decoded)
    synthetic=[]
    dummy=b'\x73\x07pr0000\x00'
    state=ResourceState()
    callbacks={0x137350:lambda:True,0x11E310:lambda name,mode:7,
               0x135618:lambda:True,0x135660:lambda:None}
    for _ in range(2):
        result=step(dummy,state,callbacks)
        state=result['state']
        synthetic.append({**result,'state':asdict(state)})
    graphical=parse_graphical_choice(script,CHOICE7F_OFFSET)
    parsed_script=Script(script)
    graphical['resolved_targets']=[parsed_script.resolve(p['block_selector'],p['label_ascii'])
        for p in graphical['options']]
    graphical['resolved_fallback']=parsed_script.resolve(graphical['fallback']['block_selector'],
        graphical['fallback']['label_ascii'])
    sixc=parsed_script.instruction(15,CHOICE_OFFSET)
    sixc['operands']=decode_operands(sixc)
    assert graphical['raw_sha256']=='b7f19b334111b7f3bacd4a652e934256e89d24d6d41c8b7327ca0d2ac33d9adf'
    assert image.word(0x118444)==0x8E450010 and image.word(0x118450)==0x8E450014
    assert image.word(0x10D960)==0x2EAF0020
    return {'schema_version':2,'evidence_id':'VM-RESOURCE-001',
        'authority':'local-static-analysis; no REA/runtime/provider execution',
        'source':{'elf_path':'local/extracted/SLPM_664.52','elf_sha256':image.sha256,
            'script_path':'local/assets/SCENARIO/sn4g.sn4','script_sha256':SCRIPT_SHA},
        'handler_classes':classes,'evidence_regions':regions,'script_samples':samples,
        'graphical_choice_sample':graphical,'text_choice_sample':sixc,
        'operand_contract':'marker!=0 consumes1 header byte; zero consumes3. Then C string including NUL. Header length is not used to place the cursor in these handlers.',
        'default_semantics':{
            '72':{'entry':'0x00127788','helper':'0x00127520','provider':'0x0011dc40',
                'condition':'137350 readiness; if true begin11E310(token,mode1), provider+8=2',
                'success':'advance past token, return0','not_ready':'rewind to opcode start a2, return1',
                'interpretation':'accepted request is not completed loading; do not treat72 as blocking until resource decode'},
            '73':{'entry':'0x00127e10','helper':'0x00127c20','provider':'0x0011dcf8',
                'before_each_attempt':'manager+71C=1',
                'phase0_or2':'if ready begin(mode0),setphase1; ALWAYS return not-accepted this attempt',
                'phase1':'if135618 completed: provider+10=provider+C;135660 finalize;phase0; accepted',
                'other_phase':'not-accepted','not_accepted':'rewind opcode start and return1',
                'accepted':'advance and return0'},
            '74':{'entry':'0x00127ae8','helper':'0x001278e8','provider':'0x0011dda8',
                'before_each_attempt':'old=manager+720;manager+718=(old==0);manager+720=old+1, including retries',
                'ready_gate':'138F68 constant1 in verified build',
                'lookup':'101CA8(provider+4 registry,provider+10 active_group,token)',
                'found':'138E10(cue,token), then10F110 obtains101928 token index and writes script+E0; advance;return0',
                'missing':'101DC0(registry) obtains fallback name; run provider73 helper; discard its result; rewind74;return1',
                'important':'74 retry can change provider state and manager counters; never convert a missing cue to successful no-op'},
        },
        'dependencies':{hx(a):d for a,d in DEPENDENCIES.items()},
        'graphical_choice_contract':{
            'default':'12E530 ->12E180; ctor12E170/vtable225158',
            'shared_preparation':'variable[19B]=variable[4];1AC690 side effect',
            'normal':'manager+808=0:119A18 pushes timing state1133F0,sets29C/294=0,context120880; stores options/fallback;135BD8 UI registration;1114F8;saveD0/D4/post7Fcursor;active=1;return1',
            'poll':'context120900 checks manager+18 via119A10; if enabled calls119820, otherwise119B60; returns inverse completion',
            'completion':'119B60 waits choice+0. On done reset1114F8,restoreD0/D4/cursor,10D868(selected,flag0) or fallback(index-1,flag1),pop timing1133D0,restoreoldcontext,active0',
            'special':'manager+808!=0: filter original indices14BCC0, appendfallback unconditionally,115E58 selects,10D868 flag0,return0',
            'filter':'14BCC0 returnsfalse for unsignedindex>=4; otherwise table[5*min_signed(variable4,8)+index+1] at22C2B0 nonzero. Negative variable4 behavior not normalized.',
            'selection':'115E58 favors candidates with10F018==0; chooses unique or17AA28 among them, otherwise among all. RNG/readstate delegated.',
            'payload_scope':'target selectors and labels only; no background image reference encoded in7F operand',
            'reference_functions':['parse_graphical_choice','graphical_choice_begin','graphical_choice_poll']},
        'text_choice_contract':{
            'scope':'Only normal default15,mode1,extra0,flags0,manager-modefalse,control+10=0,manager+808=0. Preview execution and input confirmation remain explicit obligations.',
            'setup':'125778/1186E8:19C910 hook;savefontXY/D0/D4/post6Ccursor/oldcontext;10EDC0;conditional10ECA0(savedD4,1,0);113448;pushfont16A788;16A6B0(0,0);16AA98;setoptions;16A8C8(0,0);savefontcontrols;context11E958;template32',
            'preview_ready':'118338 final option ->118428 context11E6C8;16A7E8 pop;118444restoreD0,118454restoreD4,118460restorecursor;19CAD8(0)',
            'confirmation_requirement':'118288 and transition context must finish before choice6c_commit; reference phase confirming is an integration assertion, not implemented input navigation',
            'commit':'11E608 waits16BA10==0;118D68 restoresfontXY16A950;117EE8 selected glyphranges float0;default120280;10D868(selected target,flag0);manager+28 object+14=1',
            'history_correction':'At normal interactive commit current selector is saved original block, not32..41.10D958 oldD4!=-1 and10D960 unsignedoldselector<32 gate ordinaryhistory. Do not skip10E658/10ECA0/10E878 based on templates.',
            'save_fields':['currentScriptD0,D4,cursor','savedScriptD0,D4,post6Ccursor','manager context and choice phase','mode/count/options/flags/extra state','selected and render indices','old context and1C8/1CC/1D0 flags','prechoicefontXY and preview font controls','peroptionXY and both glyph start/end arrays','font stacks/live glyph state','history/readstate and19C910 global hook state','manager+28 control object state'],
            'reference_functions':['choice6c_setup','choice6c_preview_ready','choice6c_commit'],
            'not_a_full_save_schema':True},
        'dependency_scope':'Callbacks are explicit missing backend semantics; no default True, fake resource, or implicit no-op is supplied.',
        'synthetic_two_step73_vector':{'provenance':'model-only callbacks; not observed gameplay/loading',
            'steps':synthetic},
        'unknowns':['SPK cue/dependency/program interpretation is owned by the separate resource analysis; names here are literal operands.',
            '7F135BD8 frontend/UI result producer and1AC690 preparation are explicit unresolved dependencies.',
            '6C reference models checkpoints only: preview glyph execution, highlight/prompt and118288 confirmation start are required external phases, never NOPs.',
            '6C19C910 invokes a configurable callback and updates global choice/read bookkeeping; full state serialization remains external.',
            '137350/135618 external global queues and resource decoder work are not implemented.',
            '138E10->138C90/1395A8 activates program behavior beyond this contract; not equated to swapping one background image.',
            '101DC0 fallback-name ownership and all registry/index mappings require backend integration.',
            'Full context-specific behavior must use retained slot bodies; only slot15 is executable here.',
            'Original relative cursor/block addressing must wrap the reference byte-buffer offsets.',
            'No emulator run, complete CFG, R5900 emulation, real audio/video playback or native game is claimed.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    parser.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    parser.add_argument('--out',type=Path,default=ROOT/'analysis/vm_resource_semantics.json')
    args=parser.parse_args()
    if args.out.resolve() in {args.elf.resolve(),args.script.resolve()}:
        raise ValueError('Output must be distinct from source artifacts')
    report=analyze(Image(args.elf.read_bytes()),args.script.read_bytes())
    args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence_id':report['evidence_id'],'handlers':len(report['handler_classes']),
        'regions':len(report['evidence_regions']),'source_tokens':[s['token_ascii'] for s in report['script_samples']]},ensure_ascii=False))


if __name__=='__main__':main()
