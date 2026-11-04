"""Strict, hash-bound control semantics for the extracted X3 PS2 build.

Pure arithmetic and label numbering are executable. Transfers produce ordered
effects; completing one requires an explicit implementation of every effect.
Unknown runtime flags and callbacks never become NOPs or zero-valued variables.
"""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

from choice_branch import Script, decode_operands
from opening_instructions import frame_one, SCRIPT_SHA
from vm_handlers import Image, ROOT, hx


class UnknownControlState(ValueError):
    pass


ARITHMETIC = {2:'subtract',3:'add',4:'multiply',5:'divide_truncate_toward_zero',
              6:'assign',13:'signed_remainder',14:'external_PS2_random_range'}
COMPARISONS = {6:'equal',7:'equal',8:'greater',9:'less',10:'greater_equal',
               11:'less_equal',12:'not_equal'}


def signed16(value):
    value &= 65535
    return value-65536 if value >= 32768 else value


def _signed_operand(value):
    if type(value) is not int or not -32768 <= value <= 32767:
        raise ValueError('Expected a signed 16-bit operand')
    return value


def _trunc_div(lhs,rhs):
    if rhs == 0:
        raise ZeroDivisionError('Original divide/remainder executes BREAK 7 on zero divisor')
    q=abs(lhs)//abs(rhs)
    return -q if (lhs<0)!=(rhs<0) else q


def arithmetic(operator,lhs,rhs,*,rng_provider=None):
    """Return the stored signed16 result, not an unbounded Python result.

    rng_provider(0,rhs) must reproduce original 0x17AA28/PRNG behavior. Supplying
    Python's unrelated RNG would not establish replay/save compatibility.
    """
    _signed_operand(lhs); _signed_operand(rhs)
    if operator == 2: value=lhs-rhs
    elif operator == 3: value=lhs+rhs
    elif operator == 4: value=lhs*rhs
    elif operator == 5: value=_trunc_div(lhs,rhs)
    elif operator == 6: value=rhs
    elif operator == 13: value=lhs-_trunc_div(lhs,rhs)*rhs
    elif operator == 14:
        if rng_provider is None:
            raise UnknownControlState('Original PS2 RNG provider required')
        value=rng_provider(0,rhs)
        if type(value) is not int:
            raise ValueError('RNG provider must return original integer result')
    else:
        raise UnknownControlState(f'Unsupported arithmetic operator {operator}; not a NOP')
    return signed16(value)


def compare(operator,lhs,rhs):
    _signed_operand(lhs); _signed_operand(rhs)
    if operator in (6,7): return lhs==rhs
    if operator == 8: return lhs>rhs
    if operator == 9: return lhs<rhs
    if operator == 10: return lhs>=rhs
    if operator == 11: return lhs<=rhs
    if operator == 12: return lhs!=rhs
    raise UnknownControlState(f'Unsupported comparison operator {operator}')


def read_variable(variables,variable_id):
    if variable_id not in variables:
        raise UnknownControlState(f'Variable {variable_id:#x} is unknown; no zero default')
    return _signed_operand(variables[variable_id])


def rhs_value(operation,variables):
    if operation['rhs_kind']=='signed_immediate': return _signed_operand(operation['rhs'])
    if operation['rhs_kind']=='variable_id': return read_variable(variables,operation['rhs'])
    raise UnknownControlState('Unknown RHS kind')


def evaluate_variable(operation,variables,*,rng_provider=None):
    if operation['kind']!='variable_operation': raise ValueError('Expected variable operation')
    # The original reads LHS even for assignment, but assignment never uses it.
    # An unknown old value may therefore be overwritten by a known assignment.
    lhs=0 if operation['operator']==6 else read_variable(variables,operation['variable_id'])
    return arithmetic(operation['operator'],lhs,rhs_value(operation,variables),rng_provider=rng_provider)


def evaluate_condition(operation,variables):
    if operation['kind']!='conditional_transfer': raise ValueError('Expected conditional transfer')
    lhs=read_variable(variables,operation['variable_id'])
    rhs=rhs_value(operation,variables)
    value=compare(operation['operator'],lhs,rhs)
    return dict(lhs=lhs,rhs=rhs,comparison_result=value,jump_taken=not value,
                target_selector=operation['block_selector'],target_label=operation['label'])


def label_hash(name):
    """0x10F628: 32-bit shifted-byte sum, then fold low two bytes."""
    raw=name.encode('ascii',errors='strict')
    if not raw or b'\0' in raw: raise ValueError('Invalid label for hash')
    total=0
    for i,byte in enumerate(raw):
        total=(total+(byte<<(i&31)))&0xFFFFFFFF
    return ((total&255)+(total>>8))&255


def runtime_label_ids(script):
    """Reconstruct 0x10F6E0 numbering without patching any source bytes.

    Order is block -> hash bucket -> linked records, not lexical/file order.
    Every original bucket chain is checked against its encoded name hash.
    """
    rows=[]; counter=0
    for selector,block in enumerate(script.blocks):
        _,parsed=script.block(selector)
        by_offset={s['table_offset']:s for s in parsed['symbols']}
        seen=set()
        buckets=struct.unpack_from('<256I',script.data,block['offset']+0x30)
        for bucket,offset in enumerate(buckets):
            ordinal=0
            while offset:
                if offset in seen or offset not in by_offset:
                    raise ValueError('Repeated, cyclic or invalid symbol chain')
                seen.add(offset)
                symbol=by_offset[offset]
                if label_hash(symbol['name'])!=bucket:
                    raise ValueError('Symbol hash and original bucket disagree')
                internal=symbol['name'].startswith('_')
                number=65535 if internal else counter
                if not internal: counter+=1
                if counter>65535: raise ValueError('Runtime label ID overflow')
                rows.append(dict(block_selector=selector,label=symbol['name'],runtime_label_id=number,
                    internal=internal,bucket=bucket,chain_ordinal=ordinal,
                    symbol_file_offset=block['offset']+offset,
                    source_tag=symbol['tag'],code_relative_offset=symbol['code_relative_offset'],
                    instruction_offset=block['offset']+symbol['destination_offset']))
                offset=offset+symbol['link_delta'] if symbol['link_delta'] else 0
                ordinal+=1
        if seen!=set(by_offset): raise ValueError('Unreachable symbol record in source table')
    return rows


def option_template(index):
    """The 22 literal bytes created by 0x10D038 for selectors 32..41."""
    if type(index) is not int or not 0<=index<10:
        raise ValueError('Original option-template index must be 0..9')
    return bytes.fromhex('500000000043092b02')+bytes((0x82,0x60+index))+bytes.fromhex('814603500000000043001b')


class ControlScript(Script):
    def __init__(self,data):
        super().__init__(data)
        self.label_rows=runtime_label_ids(self)
        self.label_map={(r['block_selector'],r['label']):r for r in self.label_rows}

    def resolve_runtime(self,selector,label):
        try:return dict(self.label_map[(selector,label)])
        except KeyError as exc:raise ValueError('Unknown packaged runtime label') from exc

    def read_at(self,selector,code_relative_offset):
        """Both packaged and generated-script offsets are relative to code start."""
        if type(code_relative_offset) is not int or code_relative_offset<0:
            raise ValueError('Invalid code cursor')
        if 32<=selector<=41:
            data=option_template(selector-32)
            row=frame_one(data,code_relative_offset,len(data))
            row['source_kind']='runtime-template-reconstructed-from-ELF'
            row['file_offset']=None
        else:
            block,parsed=self.block(selector)
            offset=block['offset']+parsed['code_offset']+code_relative_offset
            row=self.instruction(selector,offset)
            row['source_kind']='packaged-script'
            row['file_offset']=offset
        row['block_selector']=selector
        row['code_relative_offset']=code_relative_offset
        row['next_code_relative_offset']=code_relative_offset+row['byte_length']
        return row


def forward_link(words,selector,label_id):
    """0x10E658's final two stores; preceding snapshot is a separate effect."""
    w0,w1=words
    return [(w0&0xF0003FFF)|((label_id&0x3FFF)<<14),
            (w1&0xFFFFFC1F)|((selector&31)<<5)]


def backward_link(words,selector,label_id):
    w0,w1=words
    return [(w0&0xFFFFC000)|(label_id&0x3FFF),(w1&0xFFFFFFE0)|(selector&31)]


def mark_visited(words):
    return [words[0]|0x10000000,words[1]]


def unpack_links(words):
    w0,w1=words
    return dict(forward_selector=(w1>>5)&31,forward_label=(w0>>14)&0x3FFF,
                backward_selector=w1&31,backward_label=w0&0x3FFF,
                visited_bit=bool(w0&0x10000000),choice_seen_bit=bool(w0&0x80000000))


def associate_media_once(words,media_id):
    """0x10F198: fill the 14-bit media field only while it is the 0x3FFF sentinel."""
    w0,w1=words
    if media_id != -1 and ((w1>>10)&0x3FFF)==0x3FFF:
        w1=(w1&0xFF0003FF)|((media_id&0x3FFF)<<10)
    return [w0,w1]


def initial_history_record(previous_word1=0):
    """0x10CE18 masks; bits25..31 of word1 are allocator-reserved and preserved.

    Passing0 chooses zero reserved bits for a native-owned record, not an assertion
    that every original allocation had zeroed reserved bits.
    """
    return [0x0FFFFFFF,(previous_word1&0xFE000000)|0x00FFFFFF]


CHAPTER_PREFIXES=('mm','my','yx','yy','yz','rx','ry','rz','sx','sy','sz','kx','ky','kz','hn','pk','pr','ep')


def initial_chapter_tracker():
    """0x19C768 initializes these fields; both shipped registration tables have null slot8."""
    return dict(current_category=0,current_chapter=1,current_valid=True,
                retained_category=0,retained_chapter=1,retained_label='',
                suspend_retained_updates=False,callback_slot8=0)


def chapter_tracker_update(tracker,label):
    """0x19CB50 normal build path: bounded label classification and progress pointer."""
    result=deepcopy(tracker)
    if result['callback_slot8']!=0:
        raise UnknownControlState('Non-null 0x19CB50 callback slot8 requires explicit implementation')
    raw=label.encode('ascii',errors='strict')
    category=CHAPTER_PREFIXES.index(label[:2]) if label[:2] in CHAPTER_PREFIXES else 255
    cursor=3 if len(raw)>2 and 97<=raw[2]<=122 else 2
    digits=raw[cursor:cursor+2]
    chapter=(digits[0]-48)*10+digits[1]-48 if len(digits)==2 and all(48<=x<=57 for x in digits) else 255
    valid=category<18 and chapter not in (0,255)
    result.update(current_category=category,current_chapter=chapter,current_valid=valid)
    if valid and not result['suspend_retained_updates']:
        result.update(retained_category=category,retained_chapter=chapter,retained_label=label[:13])
    return result


def visit_and_record(words,label,script_runtime,tracker,*,repeat_argument=1):
    """0x10ECA0's a2=0 path, including its live script+168 recording state."""
    runtime=deepcopy(script_runtime); updated_tracker=deepcopy(tracker)
    if type(runtime.get('recording_enabled')) is not bool:
        raise UnknownControlState('script+168 recording state must be known')
    if runtime['recording_enabled']:
        previous=runtime['last_recorded_label']
        invoke=(repeat_argument==0 or previous is None or previous!=label or runtime['record_force'])
        if invoke:updated_tracker=chapter_tracker_update(updated_tracker,label)
        runtime['last_recorded_label']=label
        runtime['record_force']=False
    return dict(words=mark_visited(words),script_runtime=runtime,chapter_tracker=updated_tracker)


def initial_control_environment():
    """Verified constructor/default-context values, before later gameplay changes."""
    return dict(pending_text=False,readback_active=False,script_014c=False,manager_0740=False,
                recorder_0744_active=False,manager_mode_113368=False,script_0150=False)


def cold_manager_snapshot(script):
    """Constructor snapshot only; NOT a substitute for loading an existing save."""
    entry_names=[]
    for offset in (0x20,0x60):
        field=script.data[offset:offset+64]
        if 0 not in field:raise ValueError('Unterminated ScenarioLink entry field')
        entry_names.append(field.split(b'\0',1)[0].decode('ascii'))
    if entry_names[0]!=entry_names[1]:
        raise UnknownControlState('Entry mode flag must be recovered for differing header entries')
    matches=[r for r in script.label_rows if r['label']==entry_names[0]]
    if len(matches)!=1:raise ValueError('Header entry label is missing or ambiguous')
    entry=matches[0]
    return dict(scope='after manager initialization and ScriptData construction, before save restore/other startup writes',
        entry=entry,variables={i:0 for i in range(512)},environment=initial_control_environment(),
        control_state=dict(block_selector=entry['block_selector'],code_relative_offset=entry['code_relative_offset'],
                           current_label_id=entry['runtime_label_id']),
        auxiliary_cursor=dict(block_selector=entry['block_selector'],code_relative_offset=entry['code_relative_offset']),
        script_runtime=dict(media_id=-1,recording_enabled=True,record_force=True,last_recorded_label=None,
                            forward_snapshot_valid=False,forward_snapshot_label=None,
                            forward_snapshot_selector=None,forward_snapshot_target=None,pending_edge=False),
        chapter_tracker=initial_chapter_tracker(),
        history={r['runtime_label_id']:initial_history_record() for r in script.label_rows if not r['internal']},
        reserved_bits_policy='Native-owned history word1 bits25..31 set0; original constructor leaves these reserved bits unchanged')


def execute_normal_history_plan(script,plan,history,script_runtime,chapter_tracker):
    """Pure atomic reducer for the normal recovered history path.

    All inputs are copied. Non-normal callbacks fail before any effect is applied.
    Text-flush/autosave/replay callbacks remain separate explicit dependencies.
    """
    supported={'forward_link_with_snapshot','mark_visited','backward_link','clear_script_0150'}
    for effect in plan['effects']:
        if effect['kind']=='external_call' and effect['function']=='0x0010f198':continue
        if effect['kind'] not in supported:
            raise UnknownControlState(f'Unimplemented transfer effect: {effect}')
    records=deepcopy(history); runtime=deepcopy(script_runtime); tracker=deepcopy(chapter_tracker)
    by_id={r['runtime_label_id']:r['label'] for r in script.label_rows if not r['internal']}
    completed=[]
    for effect in plan['effects']:
        kind=effect['kind']
        record_id=effect.get('record_label',effect.get('args',{}).get('label_id'))
        if record_id is not None and record_id not in records:
            raise UnknownControlState(f'History record {record_id} was not initialized/restored')
        if kind=='forward_link_with_snapshot':
            previous=unpack_links(records[record_id])
            runtime.update(forward_snapshot_valid=True,forward_snapshot_label=record_id,
                forward_snapshot_selector=previous['forward_selector'],forward_snapshot_target=previous['forward_label'])
            records[record_id]=forward_link(records[record_id],effect['selector'],effect['label_id'])
        elif kind=='backward_link':
            records[record_id]=backward_link(records[record_id],effect['selector'],effect['label_id'])
        elif kind=='mark_visited':
            if effect['args']['a2']!=0:raise UnknownControlState('Autosave a2 path needs explicit handling')
            visit=visit_and_record(records[record_id],by_id[record_id],runtime,tracker,
                                   repeat_argument=effect['args']['a3'])
            records[record_id]=visit['words'];runtime=visit['script_runtime'];tracker=visit['chapter_tracker']
        elif kind=='clear_script_0150':runtime['pending_edge']=False
        elif kind=='external_call':
            records[record_id]=associate_media_once(records[record_id],runtime['media_id'])
        completed.append(effect['id'])
    return dict(control_state=commit_plan(plan,completed),history=records,script_runtime=runtime,
                chapter_tracker=tracker,completed_effect_ids=completed)


def _flag(environment,key):
    value=environment.get(key)
    if type(value) is not bool:
        raise UnknownControlState(f'Runtime flag {key} must be explicitly known')
    return value


def _plan_transfer(script,state,row,environment,*,pending_guard):
    """Return an ordered plan for 6A/6B/85, without suppressing external effects.

    state: block_selector, code_relative_offset, current_label_id (-1 initially).
    environment: pending_text, readback_active; public history transfers also
    need the five named flags in the report. Caller supplies the state *after*
    operand consumption, as in the original dispatch. No return stack is pushed.
    """
    op=row['opcode']
    if op not in (0x6A,0x6B,0x85,0x70,0x71): raise ValueError('Expected recovered transfer opcode')
    parsed=decode_operands(row)
    target=script.resolve_runtime(parsed['block_selector'],parsed['label'])
    result=dict(opcode=op,operands=parsed,target=target,before=dict(state),
                after=dict(state),effects=[],pushes_return_stack=False,
                flag_to_0x10D868=1 if op==0x6B else 0)
    def emit(kind,**args):
        result['effects'].append(dict(id=len(result['effects']),kind=kind,**args))
    if pending_guard and _flag(environment,'pending_text') and (op==0x85 or not target['internal']):
        emit('external_call',function='0x0011a220',args={'object':'manager+0x28'},
             reason='pending text; handler consumed operands then returned zero')
        result['outcome']='flush_pending_text_without_transfer'
        return result
    result['after'].update(block_selector=target['block_selector'],
                           code_relative_offset=target['code_relative_offset'])
    if target['internal']:
        result['outcome']='internal_transfer_preserve_current_label_id'
        return result
    result['after']['current_label_id']=target['runtime_label_id']
    if _flag(environment,'readback_active'):
        result['outcome']='readback_raw_transfer_no_history'
        return result
    old_id=state['current_label_id']; old_selector=state['block_selector']
    if old_id==-1 or old_selector>=32:
        result['outcome']='public_transfer_no_previous_packaged_label'
        return result
    new_id=target['runtime_label_id']; new_selector=target['block_selector']
    emit('forward_link_with_snapshot',record_label=old_id,selector=new_selector,label_id=new_id,
         function='0x0010e658',snapshot_fields={'valid':368,'record_label':372,'old_selector':376,'old_label':380})
    emit('mark_visited',record_label=old_id,function='0x0010eca0',args={'a2':0,'a3':1},
         external_record_callback='0x0019cb50 when script+0x168 recording mode is active')
    for key,func in [('script_014c','0x0010eea0'),('manager_0740','0x0010eee8'),
                     ('recorder_0744_active','0x0010ef60')]:
        if _flag(environment,key):emit('external_call',function=func,args={'label_id':old_id})
    if op==0x6B:
        result['outcome']='public_transfer_suppress_reverse_link_and_later_history'
        return result
    # 0x10DAE8 is a build-specific constant-zero function, so this branch always runs.
    emit('backward_link',record_label=new_id,selector=old_selector,label_id=old_id,function='0x0010e878')
    if not _flag(environment,'manager_mode_113368'):
        emit('external_call',function='0x0010f198',args={'label_id':new_id},
             reason='additional entry/history metadata; not fully reduced')
    if _flag(environment,'script_0150'):
        prior_selector=environment.get('script_0154_selector')
        prior_label=environment.get('script_0158_label')
        if type(prior_selector) is not int or type(prior_label) is not int:
            raise UnknownControlState('Pending history edge requires script+154/+158 values')
        emit('clear_script_0150')
        emit('backward_link',record_label=new_id,selector=prior_selector,label_id=prior_label,function='0x0010e878')
        emit('forward_link_with_snapshot',record_label=prior_label,selector=new_selector,label_id=new_id,
             function='0x0010e658',snapshot_fields={'valid':368,'record_label':372,'old_selector':376,'old_label':380})
    result['outcome']='public_transfer_with_bidirectional_history'
    return result


def plan_transfer(script,state,row,environment):
    """6A/6B/85 wrapper: operands consumed, then the pending-text guard."""
    if row['opcode'] not in (0x6A,0x6B,0x85):
        raise ValueError('Expected 6A/6B/85; use plan_conditional_transfer for 70/71')
    return _plan_transfer(script,state,row,environment,pending_guard=True)


def plan_conditional_transfer(script,state,row,variables,environment):
    """70/71 false branch calls10D868 directly and bypasses pending-text guard."""
    if row['opcode'] not in (0x70,0x71): raise ValueError('Expected 70/71 conditional')
    operands=decode_operands(row)
    condition=evaluate_condition(operands,variables)
    if condition['jump_taken']:
        plan=_plan_transfer(script,state,row,environment,pending_guard=False)
    else:
        plan=dict(opcode=row['opcode'],operands=operands,before=dict(state),after=dict(state),
                  effects=[],pushes_return_stack=False,outcome='comparison_true_fallthrough')
    plan['condition']=condition
    plan['handler_pending_guard_bypassed']=True
    return plan


def commit_plan(plan,completed_effect_ids):
    """Guard, not an effect executor: no caller may silently ignore history work."""
    required=[effect['id'] for effect in plan['effects']]
    if list(completed_effect_ids)!=required:
        raise UnknownControlState('Every ordered transfer effect must be implemented/completed before commit')
    return dict(plan['after'])


def build_report(script_bytes,elf_bytes):
    script=ControlScript(script_bytes); image=Image(elf_bytes)
    counts=Counter(); accesses=[]; framed=0
    for selector in range(len(script.blocks)):
        rows=script.instructions(selector); framed+=len(rows)
        for row in rows:
            if row['opcode'] in (0x68,0x69,0x70,0x71):
                operands=decode_operands(row)
                counts[(row['opcode'],operands['operator'])]+=1
                if operands['variable_id']==0x17D or (operands['rhs_kind']=='variable_id' and operands['rhs']==0x17D):
                    labels=[r for r in script.label_rows if r['block_selector']==selector and not r['internal']
                            and r['instruction_offset']<=row['offset']]
                    accesses.append(dict(block_selector=selector,instruction=row,operands=operands,
                        nearest_label=max(labels,key=lambda r:r['instruction_offset'])['label']))
    windows=[
        ('variable_table_zero_512_and_snapshot_count',0x100D40,0x100D70),
        ('variable_save_copy_1024',0x101080,0x101108),
        ('variable_restore_copy_1024',0x101108,0x101190),
        ('variable_snapshot_push_pop',0x101190,0x1012E0),
        ('manager_initialize',0x110660,0x1109D4),
        ('script_data_constructor',0x10CAF0,0x10CBCC),
        ('history_allocate_and_initialize',0x10CE18,0x10CFE8),
        ('startup_header_entry_transfer',0x10D1C8,0x10D260),
        ('readback_constructor',0x119DA0,0x119DE8),
        ('pending_text_constructor',0x11A200,0x11A220),
        ('recording_mode_constructor',0x115AA0,0x115AA8),
        ('recording_active_constructor',0x115B20,0x115B28),
        ('default_mode_predicate_dispatch',0x113368,0x1133D0),
        ('default_context_predicate_bridge',0x120410,0x120440),
        ('default_mode_predicate_returns_zero',0x134D88,0x134D90),
        ('first_media_association',0x10F198,0x10F260),
        ('chapter_progress_callback',0x19CB50,0x19CBE8),
        ('chapter_classification',0x19C4C0,0x19C598),
        ('bounded_label_copy_and_validation',0x19C638,0x19C6E0),
        ('chapter_progress_initialization',0x19C768,0x19C840),
        ('callback_registration_path_a',0x1AC50C,0x1AC518),
        ('callback_registration_path_b',0x1AF12C,0x1AF138),
        ('arithmetic_variable_and_comparison_helpers',0x100D78,0x101080),
        ('variable_operand_reader',0x12C0C0,0x12C1B0),
        ('conditional_operand_reader_and_false_branch',0x12C428,0x12C590),
        ('transfer_operand_reader_and_flag',0x124D48,0x124EA8),
        ('default_transfer_handler',0x1253E8,0x125448),
        ('normal_transfer_and_flag_branches',0x10D868,0x10DAF0),
        ('readback_raw_transfer',0x10DB48,0x10DBD8),
        ('forward_edge_write_and_snapshot',0x10E658,0x10E748),
        ('forward_edge_decode',0x10E748,0x10E878),
        ('backward_edge_write',0x10E878,0x10E8D8),
        ('visited_bit_and_callback',0x10ECA0,0x10EDC0),
        ('label_hash_and_loaders',0x10F628,0x10F898),
        ('label_offsets_and_ids',0x10FA28,0x10FAA8),
        ('packaged_block_bind',0x10CFE8,0x10D038),
        ('runtime_templates',0x10D038,0x10D168),
        ('runtime_template_selection',0x10D7D0,0x10D868),
        ('cursor_and_selector_primitives',0x10D700,0x10D750),
        ('rng_dependency',0x17AA28,0x17AA90),
    ]
    representative=script.read_at(15,script.resolve_runtime(15,'pr01_0115')['code_relative_offset']+1)
    env=dict(pending_text=False,readback_active=False,script_014c=False,manager_0740=False,
             recorder_0744_active=False,manager_mode_113368=True,script_0150=False)
    examples={}
    old=script.resolve_runtime(15,'pr01_0110')
    state=dict(block_selector=15,code_relative_offset=0,current_label_id=old['runtime_label_id'])
    for op in (0x6A,0x6B,0x85):
        raw=bytes((op,))+bytes.fromhex('0b0f707230315f3031313500')
        row=frame_one(raw,0,len(raw))
        examples[f'0x{op:02x}']=plan_transfer(script,state,row,env)
    initial=cold_manager_snapshot(script)
    normal_plan=plan_transfer(script,state,frame_one(bytes.fromhex('6a0b0f707230315f3031313500'),0,13),initial['environment'])
    normal_result=execute_normal_history_plan(script,normal_plan,initial['history'],initial['script_runtime'],initial['chapter_tracker'])
    return dict(schema_version=1,status='static-control-core-implemented; external-history-and-RNG-dependencies-explicit',
        method='stdlib hash-bound MIPS and source-script analysis; no ELF execution; no REA-provider claims',
        sources=dict(script=dict(path='local/assets/SCENARIO/sn4g.sn4',sha256=SCRIPT_SHA,size=len(script_bytes)),
                     elf=dict(path='local/extracted/SLPM_664.52',sha256=image.sha256,size=len(elf_bytes))),
        api=dict(module='tools/vm_control_semantics.py',
            pure_functions=['arithmetic(operator,lhs,rhs,rng_provider=None)','compare(operator,lhs,rhs)',
                'evaluate_variable(operation,variables,rng_provider=None)','evaluate_condition(operation,variables)',
                'runtime_label_ids(script)','forward_link(words,selector,label_id)',
                'backward_link(words,selector,label_id)','mark_visited(words)','unpack_links(words)',
                'associate_media_once(words,media_id)','initial_history_record(previous_word1=0)',
                'chapter_tracker_update(tracker,label)','visit_and_record(words,label,script_runtime,tracker,repeat_argument=1)'],
            script=['ControlScript(bytes)','resolve_runtime(selector,label)','read_at(selector,code_relative_offset)'],
            transfers=['plan_transfer(script,state,row,environment)',
                       'plan_conditional_transfer(script,state,row,variables,environment)',
                       'commit_plan(plan,completed_effect_ids)'],
            initialization=['cold_manager_snapshot(script)','initial_control_environment()'],
            normal_history='execute_normal_history_plan(script,plan,history,script_runtime,chapter_tracker); pure atomic reducer, rejects other external callbacks',
            variables='dict[int,int signed16]; missing values are unknown, never implicitly zero',
            transfer_state=['block_selector','code_relative_offset','current_label_id'],
            transfer_environment=list(env)+['script_0154_selector','script_0158_label'],
            offsets='code_relative_offset relative to SCR code start; file_offset is separately retained; templates have no source file offset'),
        arithmetic={str(k):v for k,v in ARITHMETIC.items()},comparisons={str(k):v for k,v in COMPARISONS.items()},
        arithmetic_rules=dict(variable_read='signed LH at 0x238AF0 + variable_id*2',
            variable_write='SH low16; next read sign-extends',immediate='68/70 signed BE16; 69/71 unsigned BE16 variable ID',
            division='signed truncation toward zero; remainder lhs - trunc(lhs/rhs)*rhs',
            zero_divisor='original div then BREAK 7; reference raises ZeroDivisionError',
            invalid_operator='original logs and returns0x0FFFFFFF; strict reference rejects instead of reproducing corrupt/error path',
            random='operator14 calls0x17AA28(a0=0,a1=rhs); PRNG/float path delegated, not replaced with Python RNG'),
        opcode_contracts={
            '68':'variable_id:u16BE,operator:u8,signed_rhs:i16BE; store operation result low16',
            '69':'variable_id:u16BE,operator:u8,rhs_variable_id:u16BE; read both signed16',
            '70':'variable_id:u16BE,comparison:u8,signed_rhs:i16BE,selector:u8,label:NUL; direct10D868 flag0 iff comparison false, bypasses6A pending-text guard',
            '71':'same as70 but RHS is variable ID',
            '6a':'consume selector+NUL label, invoke10D868 flag0 unless pending-text guard consumes instruction',
            '6b':'same, flag1; no observed return-stack push; still forward-link/old visited updates, suppresses reverse-link and later path',
            '85':'same transfer engine withflag0; NOT a zero-side-effect marker; pending-text rule differs for underscore names'},
        label_numbering=dict(public_count=sum(not r['internal'] for r in script.label_rows),
            symbol_count=len(script.label_rows),algorithm='block ascending -> bucket0..255 -> encoded chain; public IDs increment from0; underscore=0xFFFF',
            source_tag_warning='0x6F4E is on-disk placeholder; loader0x10F6E0 overwrites tags in runtime memory',
            rows=script.label_rows),
        runtime_templates=[dict(selector=32+i,index=i,raw_hex=option_template(i).hex(),
                                sha256=hashlib.sha256(option_template(i)).hexdigest()) for i in range(10)],
        template_rules=['32..41 map to generated22-byte code, not packaged blocks; selector32+i means option i',
            '0x10D7D0 selects32+i and sets relativecursor0; creation reserves10 slots',
            'template1B enters real option target through0x118628; selection context details inchoice_branch.json',
            'previous selector>=32 suppresses normal-transfer history bookkeeping; underscore targets preserve current label ID',
            'other generated selectors42..47 exist but are outside this implementation and fail closed'],
        variable_017d=dict(formula='70: if NOT (signed16(V[0x017D]) == signed16(1)) then branch to underscore target',
            source_scan=dict(blocks=len(script.blocks),framed_instructions=framed,all_blocks_framed=True),
            all_explicit_accesses=accesses,
            conclusion='Two prologue equality gates. The sole explicit script assignment is68 operator6 value1 inep05_0090. External initialization/persistence remain unknown; no assertion that fresh game starts1.'),
        observed_operator_counts=[dict(opcode=op,operator=operator,count=n) for (op,operator),n in sorted(counts.items())],
        transfer_examples=examples,
        initialization=dict(scope=initial['scope'],entry=initial['entry'],
            source_header_entry_fields=[dict(offset=o,raw_hex=script_bytes[o:o+64].hex()) for o in (0x20,0x60)],
            variable_table=dict(address='0x00238af0',elements=512,element_bytes=2,initial_value=0,
                                zero_function='0x00100d40',initialization_call_site='0x001107e8',
                                save_copy='0x00101080',restore_copy='0x00101108',copy_bytes=1024,
                                restore_call_site='0x00105c40',restore_buffer_offset=336,
                                limitation='Save-container selection/decompression and subsequent startup writes not reconstructed'),
            environment=initial['environment'],control_state=initial['control_state'],
            auxiliary_cursor=initial['auxiliary_cursor'],script_runtime=initial['script_runtime'],
            chapter_tracker=initial['chapter_tracker'],
            history_record_words=initial_history_record(),history_record_known_masks=[0xFFFFFFFF,0x01FFFFFF],
            reserved_bits_policy=initial['reserved_bits_policy'],
            cold_not_newgame_warning='This is a proven construction snapshot. Continue restores1024 bytes; a fresh game launched from an existing profile can retain external progress. Do not overwrite loaded state with this snapshot.'),
        normal_history=dict(first_media_formula='if script.E0 != -1 and ((word1>>10)&0x3FFF)==0x3FFF: word1=(word1&0xFF0003FF)|((E0&0x3FFF)<<10)',
            forward_snapshot='script+170=1,+174=old label ID,+178=previous forward selector,+17C=previous forward label, before replacing edge',
            normal_visit='10ECA0 a2=0 marksword0 bit28, manages last-recorded label/force flag, calls19CB50 when required; recording_enabled initializes true',
            chapter_prefixes=list(CHAPTER_PREFIXES),callback_slot8='Both shipped19C768 registration tables have word+0x20=0; non-null future callback is rejected',
            callback_registration_words=[image.record(0x2319D0+32,False),image.record(0x231BC0+32,False)],
            tested_example=dict(plan=normal_plan,control_state=normal_result['control_state'],
                script_runtime=normal_result['script_runtime'],chapter_tracker=normal_result['chapter_tracker'],
                changed_records={str(i):v for i,v in normal_result['history'].items() if v!=initial['history'][i]},
                note='Pure reference reducer fixture; not observed original runtime execution'),
            remaining_dependencies=['Nonzero script014C/manager0740/recorder0744 flags take extra history paths not reduced here',
                '10ECA0 a2=1 can trigger104E10 autosave after117560 andscript0148 checks; normal label transfers usea2=0',
                'Pending text flush/replay contexts handled by presentation-specific callbacks']),
        pointer_evidence=dict(arithmetic_table=[image.record(0x227F80+i*4,False) for i in range(16)],
                              comparison_table=[image.record(0x227FC0+i*4,False) for i in range(16)]),
        explicit_word_annotations={hx(a):dict(raw=image.record(a),meaning=m) for a,m in [
            (0x100F70,'R5900 MULT v0,a0,a1; low32 result also written to rd'),
            (0x100F74,'DIV a0,a1'),(0x100F78,'MFLO t7'),(0x100F80,'BREAK 7'),
            (0x100F8C,'DIV a0,a1'),(0x100F94,'MFHI t7')]},
        elf_evidence=[dict(name=n,**image.region(a,z)) for n,a,z in windows],
        limitations=['No full PS2 code execution or dynamic validation is claimed.',
            'Normal history core is executable, including19CB50 and10F198. Special recording/text/autosave callbacks remain explicit dependencies.',
            'Constructor initialization and raw1024-byte variable save/restore are recovered; full save-container/profile semantics are not.',
            'PRNG state, exact float rounding and RNG save/restore must be ported before operator14 is executable without a supplied compatible provider.',
            '0x017D access inventory covers explicit68/69/70/71 operand references only; native/custom handlers can access variables outside that subset.',
            'No return stack is established for6B; genuine call/return mechanisms elsewhere remain unknown.',
            'This reference rejects malformed/error paths more strictly than the original runtime.'])


def markdown(report):
    ids=report['label_numbering']
    return '\n'.join([
        '# 控制流、运行时标签与读态：可执行静态参考','',
        '源 ELF / sn4g SHA-256 强制绑定。已实现严格算术、条件判断、运行时标签编号、32..41模板读取、转移计划及普通读态更新执行器。特殊回调仍显式阻断；不会把未实现动作当作已完成。','',
        '## 可供原生执行器使用的接口','',
        '- `ControlScript(bytes).resolve_runtime(selector,label)`：返回运行时编号、相对代码偏移、源文件偏移。',
        '- `.read_at(selector,code_relative_offset)`：读取真实脚本指令或生成的32..41模板；模板没有伪造的file_offset。',
        '- `evaluate_variable(operation, variables)` / `evaluate_condition(operation, variables)`：复用choice_branch解码后的operand对象；变量键为整数，值为signed16。缺失值会阻断。',
        '- `plan_transfer(script,state,row,environment)`：返回before/after、按顺序执行的effects、实际分流结果。`commit_plan`要求全部effect ID完成；此函数不是副作用执行器。',
        '- `forward_link` / `backward_link` / `mark_visited` / `unpack_links`：已确认的两字读态记录位运算。','',
        '- `cold_manager_snapshot(script)`：只代表管理器构造后的已证实状态，不覆盖已有profile或存档。',
        '- `execute_normal_history_plan(...)`：复制状态后按顺序执行普通history effects，返回控制状态、history、script_runtime、chapter_tracker；未支持的特殊callback会在应用前阻断。','',
        '## 运算和条件','',
        '| operator | 算术68/69 | 条件70/71 |','|---|---|---|',
        '| 2 | 减 | 不支持 |','| 3 | 加 | 不支持 |','| 4 | 乘 | 不支持 |',
        '| 5 | 朝零截断除法 | 不支持 |','| 6 | 赋值 | 等于 |','| 7 | 不支持 | 等于 |',
        '| 8/9 | 不支持 | 大于/小于 |','| 10/11 | 不支持 | 大于等于/小于等于 |',
        '| 12 | 不支持 | 不等于 |','| 13 | 有符号余数 | 不支持 |','| 14 | 依赖原PS2随机函数 | 不支持 |','',
        '68/70右值为signed BE16；69/71右值为另一个变量的u16 ID。变量读取用LH、写回用SH，结果必须截成16位再按有符号读。70/71的比较为假才转移；比较为真顺序继续。false分支直接调用10D868(flag0)，绕过6A/85的pending-text guard，使用独立`plan_conditional_transfer`接口。除零对应原BREAK 7；本工具抛异常。未知operator原错误路径会记录错误并返回0x0FFFFFFF，本参考严格拒绝，不仿真该错误结果。','',
        '0x017D门的公式为 `jump = NOT (signed16(V[0x017D]) == 1)`，不是位掩码。全30块均完成静态分帧；该变量唯一显式68写1在block0/ep05_0090。构造清零时其值为0；读档或外部进度加载后必须使用恢复值，不能重新默认0。','',
        '## 标签编号与转移','',
        f'加载器0x10F6E0实际重编号 {ids["public_count"]} 个公开标签；总符号 {ids["symbol_count"]} 个。顺序是block→hash bucket→链，下划线内部符号=0xFFFF。原文件tag0x6F4E不是运行时页号。JSON提供全映射，工具逐条检验原hash bucket和链。','',
        '6A、6B、85先消耗selector和NUL标签，共用10D868。85也会更新标签ID/历史，不能统一当NOP。pending-text条件成立时，公开目标及85先调用11A220并返回，不发生转移；内部6A/6B允许继续。','',
        '6B仅把10D868的flag设1，未见返回栈push。公开标签普通转移仍先写旧页forward link、visited及条件记录，然后flag1直接返回，跳过新页backward link和后续history路径。6A/85的flag0写双向链接。下划线目标保留当前label ID；旧selector>=32或旧ID=-1跳过普通历史链；readback-active路径只做原始跳转与公开ID更新。','',
        'forward记录：word0 bits14..27=目标label，word1 bits5..9=目标selector；backward记录：word0 bits0..13=前页label，word1 bits0..4=前页selector；visited为word0 bit28。原函数还保存被覆盖的旧forward关系到script+170/+174/+178/+17C；这也在计划中显式保留。','',
        '32..41是原程序生成的22字节A..J选项编号模板，32+i对应选项i。模板末尾1B经选择对象当前render index进入目标正文；不是ISO中缺失的block。42..47等其他运行时模板尚未实现，拒绝越界。','',
        '## 构造与普通读态执行','',
        '0x1107E8调用0x100D40，清0x238AF0的512个signed16值和变量快照栈计数。0x101080保存/0x101108恢复整1024字节；已有读档调用点0x105C40从选中存档缓冲+336恢复。完整存档容器、profile选择和解压未恢复。','',
        'sn4g头+0x20与+0x60都为top00_0000。0x10D038选择对应字符串，查出block17并转移，随后保存aux cursor。因此冷构造入口是17/top00_0000，不是直接pr01_0020。ScriptData初始label ID=-1，经入口转移后成为该label运行时ID。','',
        'pending_text、readback、script014C/0150、manager0740、recorder0744都由构造/初始化显式置0。默认context的113368谓词通过helper4.slot16返回0。script+168记录模式初始却为1；+180 force初始1，+184 last-label为空，普通visited必须处理记录回调。','',
        '19CB50的两张已登记表slot8都是0；内部逻辑按18个prefix及两位chapter分类，更新current_category/current_chapter/current_valid，允许时保留最多13字节label。重复同一label且force已清时不重复更新。这些字段现已由chapter_tracker_update和visit_and_record执行。19C868的非空slot0属于另一回调，本模块未将其假设为空。','',
        '10F198并非计数加一：当script.E0!=-1且word1 bits10..23仍为0x3FFF时才写入E0低14位，保留首次媒体关联。普通history reducer已实现该规则及forward快照。','',
        '原history构造将word0定为0x0FFFFFFF、word1低24位全1且bit24清0；bits25..31保留分配器原值。本工具为原生拥有的记录选择保留位0，并在JSON明确该策略，未冒称原PS2完整原始字等于此值。','',
        '## 验证与限制','',
        '`python tools/vm_control_semantics.py` 生成证据；`python -m unittest discover -s tests -p test_vm_control_semantics.py` 验证算术边界、门公式、标签编号、位字段及副作用阻断。','',
        '完整VM仍需特殊记录/自动存档回调、完整profile/存储、其他opcode及兼容PRNG。报告中的静态调用合同不能替代原版实测。所有结论附原指令与file offset；MIPS子集未解析的字仍保留。',''])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    p.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    p.add_argument('--json',type=Path,default=ROOT/'analysis/vm_control_semantics.json')
    p.add_argument('--doc',type=Path,default=ROOT/'docs/VM_CONTROL_SEMANTICS.md')
    a=p.parse_args()
    if len({x.resolve() for x in (a.script,a.elf,a.json,a.doc)})!=4:
        raise ValueError('Source and outputs must be distinct')
    r=build_report(a.script.read_bytes(),a.elf.read_bytes())
    a.json.parent.mkdir(parents=True,exist_ok=True);a.doc.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    a.doc.write_text(markdown(r),encoding='utf-8')
    print(json.dumps(dict(status=r['status'],public_labels=r['label_numbering']['public_count'],
                         source_blocks=r['variable_017d']['source_scan']['blocks'],
                         elf_windows=len(r['elf_evidence']))))


if __name__=='__main__':main()
