"""Bind original page-entry callbacks to shipped chart resources, without GUI.

The timechart parser recovers the prefix needed by 0x1AC598, not the entire UI
layout tail. Pure reducers preserve pre-existing progress and never unlock labels
that were not supplied by the caller's executed page-entry event.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

from vm_handlers import Image, ROOT, hx
from vm_control_semantics import ControlScript, UnknownControlState

TIM_SHA='bb53e46ca0622f7abc549c9aee269c885f16f7ddd8ab4c69f22f6344b69377c6'
CHAPTER_SHAS={
    0:'893e7d0f74e43fecd4622513793118e3754ec2619146768ee246e05575a50a2c',
    2:'ef9118b71679e717b310c5f6bd3d9734439e14abdc8bafd40b7faa0955aceb38',
}


class Reader:
    def __init__(self,data,offset=0):self.data,self.pos=data,offset

    def take(self,count):
        if count<0 or self.pos<0 or self.pos+count>len(self.data):
            raise ValueError('Resource read outside source')
        result=self.data[self.pos:self.pos+count];self.pos+=count
        return result

    def u16(self):return int.from_bytes(self.take(2),'little')

    def double_nul_string(self):
        start=self.pos
        end=self.data.find(b'\0',start)
        if end<0:raise ValueError('Unterminated resource string')
        raw=self.take(end-start)
        if self.take(2)!=b'\0\0':raise ValueError('Expected original double-NUL string terminator')
        return dict(offset=start,end_exclusive=self.pos,raw_hex=raw.hex(),
                    raw_sha256=hashlib.sha256(raw).hexdigest(),decoded_cp932=raw.decode('cp932',errors='strict'))


def fixed_label_record(raw,offset,index):
    if len(raw)!=14 or 0 not in raw:raise ValueError('Expected 14-byte NUL-terminated label slot')
    body,padding=raw.split(b'\0',1)
    if any(padding):raise ValueError('Nonzero label padding outside recovered asset contract')
    try:label=body.decode('ascii',errors='strict')
    except UnicodeDecodeError as exc:raise ValueError('Non-ASCII script label') from exc
    return dict(index=index,offset=offset,label=label,raw_hex=raw.hex(),
                raw_sha256=hashlib.sha256(raw).hexdigest())


def parse_timechart(data):
    if hashlib.sha256(data).hexdigest()!=TIM_SHA:
        raise ValueError('Timechart SHA-256 mismatch; build-bound parser refused')
    r=Reader(data)
    if r.take(16)!=b'SN4G tc ver4\0\0\0\0':raise ValueError('Unexpected timechart signature')
    time_count=r.u16();time_offset=r.pos
    times=[r.u16() for _ in range(time_count)]
    string_count=r.u16();strings=[r.double_nul_string() for _ in range(string_count)]
    count16=r.u16();record16_offset=r.pos;raw16=r.take(count16*16)
    tables={}
    for name in ('seen_labels','checkpoint_labels'):
        count=r.u16();start=r.pos
        entries=[]
        for i in range(count):
            offset=r.pos;entries.append(fixed_label_record(r.take(14),offset,i))
        if not entries or entries[0]['label']!='':raise ValueError('Missing reserved zero label entry')
        tables[name]=dict(offset=start,count=count,entries=entries)
    return dict(kind='sn4g-timechart-callback-prefix',sha256=TIM_SHA,size=len(data),
        time_table=dict(offset=time_offset,count=time_count,values=times),strings=strings,
        record16_table=dict(offset=record16_offset,count=count16,raw_sha256=hashlib.sha256(raw16).hexdigest()),
        **tables,
        parsed_prefix_end=r.pos,unparsed_tail=dict(offset=r.pos,size=len(data)-r.pos,
                                                 sha256=hashlib.sha256(data[r.pos:]).hexdigest()),
        scope='Only loader prefix needed by1AC598; remaining timechart layout/navigation is retained and unresolved')


def parse_chapter_table(data,game_index):
    if game_index not in CHAPTER_SHAS or hashlib.sha256(data).hexdigest()!=CHAPTER_SHAS[game_index]:
        raise ValueError('Chapter table source/game SHA-256 mismatch')
    r=Reader(data)
    count=r.u16()
    if not 0<count<=128:raise ValueError('Original chapter pointer/bit arrays support at most128 entries')
    entries=[]
    for i in range(count):
        start=r.pos;group=r.take(1)[0]
        if group==0:
            if r.take(1)!=b'\0':raise ValueError('Unknown zero-group entry padding')
            label='';title=None
        else:
            field=r.take(13)
            if 0 not in field:raise ValueError('Unterminated chapter label')
            body,padding=field.split(b'\0',1)
            if any(padding):raise ValueError('Unknown chapter label padding')
            label=body.decode('ascii',errors='strict')
            title=r.double_nul_string()
        raw=data[start:r.pos]
        entries.append(dict(index=i,group=group,label=label,title=title,offset=start,end_exclusive=r.pos,
                            raw_hex=raw.hex(),raw_sha256=hashlib.sha256(raw).hexdigest()))
    # These two supplied chapter assets contain an exact second copy of the
    # record payload. 1AF010 consumes only the first count records; preserve the
    # trailing copy as observed bytes instead of inventing a second active table.
    tail=data[r.pos:]
    if tail!=data[2:r.pos]:raise ValueError('Unaccounted chapter table tail is not the verified duplicate payload')
    return dict(kind='chapter-callback-table',game_index=game_index,sha256=CHAPTER_SHAS[game_index],
                size=len(data),count=count,entries=entries,complete_byte_accounting=True,
                duplicate_payload_tail=dict(offset=r.pos,size=len(tail),sha256=hashlib.sha256(tail).hexdigest(),
                    identical_to_record_payload=True,used_by_1af010=False))


def binding_for_game(game_index,*,startup_flag_11):
    if type(startup_flag_11) is not bool:raise UnknownControlState('Startup flag11 must be explicitly known')
    if game_index not in (0,1,2):raise ValueError('Unsupported original game index')
    if startup_flag_11:
        return dict(game_index=game_index,enabled=False,reason='Original initializer releases resource and returns0')
    if game_index==1:
        return dict(game_index=1,enabled=True,resource_slot=6,resource_path='CHART/sn4g_tim.dat',
                    registration_table='0x002319d0',slot0='0x001ac598',slot1=0,slot8=0,kind='timechart')
    return dict(game_index=game_index,enabled=True,resource_slot=7,
                resource_path=f'CHART/{"sn4" if game_index==0 else "sn2"}_chap.dat',
                registration_table='0x00231bc0',slot0='0x001af188',slot1=0,slot8=0,kind='chapter')


def initial_timechart_state(table):
    return dict(seen_bitmap_hex=bytes((table['seen_labels']['count']+7)//8).hex(),checkpoint_index=0)


def timechart_callback(table,state,label):
    """0x1AC598; ignores any second callback argument, scans each table from1."""
    bitmap=bytearray.fromhex(state['seen_bitmap_hex'])
    if len(bitmap)!=(table['seen_labels']['count']+7)//8:
        raise ValueError('Timechart progress bitmap size mismatch')
    if not 0<=state['checkpoint_index']<table['checkpoint_labels']['count']:
        raise ValueError('Timechart checkpoint outside table')
    result=deepcopy(state);matches={}
    for row in table['seen_labels']['entries'][1:]:
        if row['label']==label:
            i=row['index'];bitmap[i>>3]|=1<<(i&7);matches['seen_index']=i;break
    for row in table['checkpoint_labels']['entries'][1:]:
        if row['label']==label:
            result['checkpoint_index']=row['index'];matches['checkpoint_index']=row['index'];break
    result['seen_bitmap_hex']=bitmap.hex()
    return dict(state=result,matches=matches,callback='0x001ac598',changed=result!=state)


def initial_chapter_state():return dict(selected_bitmap_hex=bytes(16).hex())


def chapter_callback(table,state,label,*,second_argument):
    """0x1AF188: select matching row and clear other bits in the same group."""
    if type(second_argument) is not int:raise UnknownControlState('Callback a1 must be known')
    bitmap=bytearray.fromhex(state['selected_bitmap_hex'])
    if len(bitmap)!=16:raise ValueError('Expected original128-bit chapter bitmap')
    result=deepcopy(state)
    if second_argument:
        return dict(state=result,matched_index=None,changed=False,reason='nonzero_a1_early_return')
    hit=next((row for row in table['entries'] if row['group'] and row['label']==label),None)
    if hit:
        index=hit['index'];bitmap[index>>3]|=1<<(index&7)
        for row in table['entries']:
            if row['index']!=index and row['group']==hit['group']:
                j=row['index'];bitmap[j>>3]&=~(1<<(j&7))&255
        result['selected_bitmap_hex']=bitmap.hex()
    return dict(state=result,matched_index=hit['index'] if hit else None,changed=result!=state)


def resource_descriptor(image,base):
    rows=[]
    for index in range(16):
        address=base+index*16
        values=[image.word(address+i*4) for i in range(4)]
        if values[0]==0xFFFFFFFF:return rows
        pointer=values[1];offset=image.offset(pointer);end=image.data.index(0,offset)
        rows.append(dict(resource_slot=values[0],path=image.data[offset:end].decode('ascii'),
                         option_words=values[2:],descriptor_words=[image.record(address+i*4,False) for i in range(4)]))
    raise ValueError('Resource descriptor has no bounded terminator')


def build_report(elf,script,tim,chapters):
    image=Image(elf);program=ControlScript(script);table=parse_timechart(tim)
    chapter_tables={str(i):parse_chapter_table(data,i) for i,data in chapters.items()}
    known={r['label'] for r in program.label_rows}
    absent=[r['label'] for name in ('seen_labels','checkpoint_labels') for r in table[name]['entries']
            if r['label'] and r['label'] not in known]
    if absent:raise ValueError('Timechart callback label absent from matching source script')
    windows=[
        ('game_index_getter',0x100410,0x100418),
        ('resource_descriptor_selection',0x1005C4,0x1005F4),
        ('consume_loaded_resource',0x100718,0x100830),
        ('startup_game_index_selects_chart_or_chapter',0x1008D8,0x10099C),
        ('timechart_loader_prefix',0x1AC108,0x1AC2B4),
        ('timechart_bitmap_and_callback_registration',0x1AC478,0x1AC520),
        ('timechart_page_enter_callback',0x1AC598,0x1AC690),
        ('chapter_resource_parser_and_registration',0x1AF010,0x1AF140),
        ('chapter_page_enter_callback',0x1AF188,0x1AF2D0),
        ('copy_callback_registry_and_initial_state',0x19C768,0x19C840),
        ('page_entry_dispatch_slot0',0x19C868,0x19C910),
        ('choice_dispatch_slot1',0x19C910,0x19C9B8),
    ]
    return dict(schema_version=1,status='source-bound-progress-callbacks-executable; UI-tail-unresolved',
        method='Static ELF loader/callback reconstruction plus immutable supplied CHART resources; no runtime observation',
        sources=dict(elf_sha256=image.sha256,script_sha256=hashlib.sha256(script).hexdigest(),
                     timechart_sha256=TIM_SHA,chapter_sha256=CHAPTER_SHAS),
        api=dict(module='tools/vm_progress_callbacks.py',
            functions=['binding_for_game(game_index,startup_flag_11=bool)','parse_timechart(bytes)',
                'initial_timechart_state(table)','timechart_callback(table,state,label)',
                'parse_chapter_table(bytes,game_index)','initial_chapter_state()',
                'chapter_callback(table,state,label,second_argument=int)'],
            callback_scope='These implement the registered slot0 only. 19C868 still performs shared category/chapter/currentlabel bookkeeping after the callback.',
            save_contract='Persist the entire bitmap and checkpoint index; callbacks preserve earlier bits and never reset profile progress'),
        bindings=[binding_for_game(i,startup_flag_11=False) for i in range(3)],
        descriptor_index_words=[image.record(0x204B88+i*4,False) for i in range(3)],
        resource_descriptors={str(i):resource_descriptor(image,image.word(0x204B88+i*4)) for i in range(3)},
        callback_tables={hx(base):[image.record(base+i*4,False) for i in range(14)] for base in (0x2319D0,0x231BC0)},
        timechart=table,chapter_tables=chapter_tables,
        first_page_example=dict(label='pr01_0020',before=initial_timechart_state(table),
            result=timechart_callback(table,initial_timechart_state(table),'pr01_0020'),
            status='reference reducer fixture, not original runtime trace'),
        source_label_crosscheck=dict(all_timechart_labels_resolve=True,missing=[]),
        elf_evidence=[dict(name=n,**image.region(a,z)) for n,a,z in windows],
        limitations=['Timechart title/layout/navigation tail beyond callback tables is not parsed or rendered here.',
            'sn4g uses game_index1, resource6, callback1AC598. sn4g_end.dat is resource5 and is NOT the chapter callback input.',
            'startup flag11 disables these initializer paths; calling bindings requires an explicit value.',
            'Bitmap persistence transport still belongs to save/profile implementation; reducers do not prove PS2 save-file compatibility.',
            'Callbacks consume labels from actual execution; scanning all labels and applying them would incorrectly unlock progress.'])


def markdown(report):
    t=report['timechart']
    return '\n'.join([
        '# 页面进度回调与真实CHART资源绑定','',
        '当前sn4g的页面进入回调已能执行。它是时间图回调1AC598；不能误用另两作的章节回调1AF188。所有输入哈希绑定，只读原资源。','',
        '| 游戏index | 资源slot | 资源 | slot0 |','|---|---|---|---|',
        '| 0 / sn4 | 7 | CHART/sn4_chap.dat | 1AF188 |',
        '| 1 / sn4g | 6 | CHART/sn4g_tim.dat | 1AC598 |',
        '| 2 / sn2 | 7 | CHART/sn2_chap.dat | 1AF188 |','',
        '1008D8读取100410的游戏index，index1走1AC108，否则index0/2走1AF010。资源描述符指针表在204B88；对应slot与路径均在JSON保留原字。两张登记表仅slot0非零，slot1/slot8均0。sn4g_end.dat是slot5，用于另外的结局系统，不是1AF188输入。','',
        f'时间图magic为SN4G tc ver4，前缀包含101个时间值、192个双NUL字符串、34个16字节记录。seen标签表位于{t["seen_labels"]["offset"]:#x}，共302个14字节槽；checkpoint标签表位于{t["checkpoint_labels"]["offset"]:#x}，共301个槽。index0为空保留。全部非空标签均能解析到本源sn4g脚本。','',
        '1AC598在第一张表从index1查找首个完全匹配标签，置seen_bitmap[i>>3]的第(i&7)位；第二张表同样搜索，命中则更新checkpoint_index。不命中保留既有进度。第一屏pr01_0020在两表均为index1，所以首次事件将bitmap byte0置bit1，并把checkpoint_index设1。','',
        '1AF188仅在第二参数a1==0时匹配chapter条目；命中设置该条目bit，并清同group的其他条目bit，其他group保留。sn4/sn2章节表现已完整覆盖解析，原始label/title偏移和bytes保留。','',
        '## 原生调用','',
        '先`parse_timechart(bytes)`，新profile用`initial_timechart_state(table)`；真实页面事件调用`timechart_callback(table,state,label)`，使用返回state，并持久化完整38字节bitmap与checkpoint_index。读取旧profile时使用旧state，不能重新初始化。','',
        '这是19C868的slot0回调实现。19C868在回调后仍执行共用prefix/chapter/currentlabel更新；调用方需继续完成这些逻辑。不能遍历所有标签来调用回调，否则会把未阅读内容标成已见。','',
        '## 范围','',
        f'只解析时间图到{t["parsed_prefix_end"]:#x}的回调所需前缀；剩余{t["unparsed_tail"]["size"]}字节UI布局/导航数据保留SHA，尚未解析。原版flag11为非零时初始化会禁用此资源路径；绑定API要求显式传值。没有宣称原版动态观察或完整PS2存档兼容。','',
        '`python tools/vm_progress_callbacks.py` 重跑；`python -m unittest discover -s tests -p test_vm_progress_callbacks.py` 验证。',''])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--json',type=Path,default=ROOT/'analysis/vm_progress_callbacks.json')
    p.add_argument('--doc',type=Path,default=ROOT/'docs/VM_PROGRESS_CALLBACKS.md')
    a=p.parse_args()
    source_paths=[ROOT/'local/extracted/SLPM_664.52',ROOT/'local/assets/SCENARIO/sn4g.sn4',
        ROOT/'local/assets/CHART/sn4g_tim.dat',ROOT/'local/assets/CHART/sn4_chap.dat',ROOT/'local/assets/CHART/sn2_chap.dat']
    if len({x.resolve() for x in source_paths+[a.json,a.doc]})!=7:raise ValueError('Sources and outputs must be distinct')
    data=[x.read_bytes() for x in source_paths]
    r=build_report(data[0],data[1],data[2],{0:data[3],2:data[4]})
    a.json.parent.mkdir(parents=True,exist_ok=True);a.doc.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    a.doc.write_text(markdown(r),encoding='utf-8')
    print(json.dumps(dict(status=r['status'],timechart_seen_labels=r['timechart']['seen_labels']['count'],
                         checkpoint_labels=r['timechart']['checkpoint_labels']['count'],
                         chapter_entries={k:v['count'] for k,v in r['chapter_tables'].items()})))


if __name__=='__main__':main()
