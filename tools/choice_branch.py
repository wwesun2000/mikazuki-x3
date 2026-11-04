"""Source-bound static recovery of the prologue's conditional 0x6C choice.

This parses real instruction operands and selected target prefixes. It is not a
complete VM, does not execute the ELF, and never gives unknown opcodes NOP semantics.
"""
import argparse
import hashlib
import json
from pathlib import Path

from opening_instructions import SCRIPT_SHA, frame_one, frame_window
from scenario import parse_link, parse_scr
from vm_handlers import Image, ROOT, hx

CHOICE_OFFSET = 0xA259C
PREVIEW_ALLOWLIST = 0x205DD0


class OperandReader:
    def __init__(self, payload):
        self.data, self.pos = payload, 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError('Truncated operand payload')
        result = self.data[self.pos:self.pos+count]
        self.pos += count
        return result

    def byte(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), 'big')

    def label(self):
        end = self.data.find(b'\0', self.pos)
        if end < 0:
            raise ValueError('Unterminated target label')
        raw = self.take(end-self.pos+1)[:-1]
        if not raw:
            raise ValueError('Empty target label')
        try:
            return raw.decode('ascii', errors='strict')
        except UnicodeDecodeError as exc:
            raise ValueError('Non-ASCII target label') from exc

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError('Unconsumed operand bytes')


def decode_operands(row):
    """Strict operand decoder for the recovered control subset only."""
    op = row['opcode']
    r = OperandReader(bytes.fromhex(row['payload_hex']))
    if op == 0x6C:
        mode, count, extra_count = r.byte(), r.byte(), r.byte()
        extra = r.take(extra_count)
        options = [dict(index=i, raw_flag=r.byte(), block_selector=r.byte(),
                        label=r.label()) for i in range(count)]
        result = dict(kind='choice_setup', mode=mode, option_count=count,
                      extra_byte_count=extra_count, extra_hex=extra.hex(), options=options)
    elif op in (0x68, 0x69):
        variable, operator, rhs = r.u16(), r.byte(), r.u16()
        result = dict(kind='variable_operation', variable_id=variable, operator=operator,
                      rhs_kind='signed_immediate' if op == 0x68 else 'variable_id',
                      rhs=rhs-65536 if op == 0x68 and rhs >= 32768 else rhs)
    elif op in (0x70, 0x71):
        variable, operator, rhs = r.u16(), r.byte(), r.u16()
        result = dict(kind='conditional_transfer', variable_id=variable, operator=operator,
                      rhs_kind='signed_immediate' if op == 0x70 else 'variable_id',
                      rhs=rhs-65536 if op == 0x70 and rhs >= 32768 else rhs,
                      block_selector=r.byte(), label=r.label(), jump_when='comparison_false')
    elif op in (0x6A, 0x6B, 0x85):
        result = dict(kind={0x6A:'label_transfer', 0x6B:'label_transfer_variant',
                            0x85:'label_marker'}[op],
                      block_selector=r.byte(), label=r.label())
    else:
        raise ValueError(f'No recovered operand semantics for {op:#x}')
    r.finish()
    return result


def assign_only(operation, variables):
    """Bounded semantic reference; rejects unimplemented arithmetic/RHS kinds."""
    if (operation['kind'] != 'variable_operation' or operation['operator'] != 6
            or operation['rhs_kind'] != 'signed_immediate'):
        raise ValueError('Unsupported variable operation; not a NOP')
    value = operation['rhs'] & 65535
    variables[operation['variable_id']] = value-65536 if value >= 32768 else value


def conditional_jump_only(operation, variables):
    if (operation['kind'] != 'conditional_transfer' or operation['operator'] not in (6,7)
            or operation['rhs_kind'] != 'signed_immediate'):
        raise ValueError('Unsupported comparison; not a NOP')
    if operation['variable_id'] not in variables:
        raise ValueError('Unknown variable value; branch cannot be chosen')
    return variables[operation['variable_id']] != operation['rhs']


class Script:
    def __init__(self, data):
        if hashlib.sha256(data).hexdigest() != SCRIPT_SHA:
            raise ValueError('Script SHA-256 mismatch; fixed branch refused')
        self.data, self.blocks = data, parse_link(data)
        self.parsed = {}

    def block(self, selector):
        if not 0 <= selector < len(self.blocks):
            raise ValueError('Target selector outside packaged script blocks')
        block = self.blocks[selector]
        if selector not in self.parsed:
            self.parsed[selector] = parse_scr(self.data[block['offset']:block['offset']+block['size']])
        return block, self.parsed[selector]

    def resolve(self, selector, label):
        block, parsed = self.block(selector)
        matches = [s for s in parsed['symbols'] if s['name'] == label]
        if len(matches) != 1:
            raise ValueError('Target label missing or ambiguous')
        symbol = matches[0]
        off = block['offset'] + symbol['table_offset']
        raw = self.data[off:off+symbol['record_size']]
        return dict(block_selector=selector, label=label, symbol=symbol,
                    symbol_file_offset=off, symbol_raw_hex=raw.hex(),
                    symbol_raw_sha256=hashlib.sha256(raw).hexdigest(),
                    instruction_offset=block['offset']+symbol['destination_offset'])

    def instruction(self, selector, offset):
        block, parsed = self.block(selector)
        if offset < block['offset']+parsed['code_offset']:
            raise ValueError('Instruction before code section')
        return frame_one(self.data, offset, block['offset']+block['size'])

    def instructions(self, selector):
        block, parsed = self.block(selector)
        return frame_window(self.data, block['offset']+parsed['code_offset'],
                            block['offset']+block['size'])


def target_prefix(script, option, allowlist):
    """Follow only the validated preview prefix, stopping at first 0x16.

    Non-allowlisted records are *original-context skips*, not VM NOP guesses.
    Allowed unimplemented controls fail closed. Glyph formatting stays outside
    this narrow semantic reference; text records retain full raw units.
    """
    target = script.resolve(option['block_selector'], option['label'])
    pos, rows, texts = target['instruction_offset'], [], []
    for _ in range(64):
        row = script.instruction(option['block_selector'], pos)
        op = row['opcode']
        if op not in allowlist:
            row['preview_action'] = 'original_0x111738_skip_by_preview_allowlist'
        elif op == 2:
            row['preview_action'] = 'text_handler_slot1'
            texts.append(row['text'])
        elif op in (0x22, 4):
            row['preview_action'] = 'context_handler_slot1; detailed_text_state_not_reimplemented'
        elif op == 0x16:
            row['preview_action'] = 'finish_option_via_0x118338'
        else:
            raise ValueError(f'Unsupported allowed preview opcode {op:#x}')
        rows.append(row)
        pos = row['end_exclusive']
        if op == 0x16:
            break
    else:
        raise ValueError('No option terminator inside bounded prefix')
    # This particular original target starts 22,6A. In normal context 6A goes
    # to the assignment; in preview context the allowlist skips its operands.
    if len(rows) < 2 or rows[0]['opcode'] != 0x22 or rows[1]['opcode'] != 0x6A:
        raise ValueError('Target does not have the established normal-prefix shape')
    transfer = decode_operands(rows[1])
    assignment_target = script.resolve(transfer['block_selector'], transfer['label'])
    assignment_row = script.instruction(transfer['block_selector'], assignment_target['instruction_offset'])
    assignment = decode_operands(assignment_row)
    state = {}
    assign_only(assignment, state)
    return dict(option=option, resolved_target=target, preview_instructions=rows,
                preview_text_records=texts, normal_transfer=transfer,
                assignment_target=assignment_target, assignment_instruction=assignment_row,
                assignment=assignment,
                semantic_reference_after_selected_assignment={str(k):v for k,v in state.items()},
                status='static-ELF-context-and-script-aligned; runtime-pending')


def build_report(script_bytes, elf_bytes):
    script, image = Script(script_bytes), Image(elf_bytes)
    allow = [image.word(PREVIEW_ALLOWLIST+i*4) for i in range(19)]
    rows = script.instructions(15)
    first = next(r for r in rows if r['opcode'] == 0x6C)
    if first['offset'] != CHOICE_OFFSET:
        raise ValueError('Unexpected first lexical choice location')
    choice = decode_operands(first)
    preceding = [script.resolve(15,s['name']) for s in script.block(15)[1]['symbols']
                 if s['tag'] == '0x6f4e' and script.block(15)[0]['offset']+s['destination_offset'] <= CHOICE_OFFSET]
    label = max(preceding,key=lambda x:x['instruction_offset'])
    targets = [target_prefix(script,o,allow) for o in choice['options']]
    gates = []
    for row in rows:
        if row['offset'] in (0xA226D,0xA2318):
            operation = decode_operands(row)
            gates.append(dict(instruction=row, operation=operation,
                              target=script.resolve(operation['block_selector'],operation['label']),
                              when_variable_1_jump=conditional_jump_only(operation,{381:1}),
                              when_variable_0_jump=conditional_jump_only(operation,{381:0})))
    # Every byte is assigned by original sb instructions 0x10D0FC..0x10D164.
    templates = []
    for i in range(choice['option_count']):
        raw = bytes.fromhex('500000000043092b02')+bytes((0x82,0x60+i))+bytes.fromhex('814603500000000043001b')
        templates.append(dict(index=i, runtime_block_selector=32+i, raw_hex=raw.hex(),
                              raw_sha256=hashlib.sha256(raw).hexdigest(),
                              provenance='reconstructed from literal stores 0x10D0FC..0x10D164',
                              prefix_cp932=bytes((0x82,0x60+i,0x81,0x46)).decode('cp932'),
                              byte_length=len(raw)))
    regions = [
        ('choice_factory_case',0x110344,0x110360),
        ('choice_constructor',0x125768,0x125778),
        ('choice_default_slot15',0x125B30,0x125B48),
        ('choice_parameter_reader',0x125778,0x1259C8),
        ('choice_setup',0x1186E8,0x1189F8),
        ('runtime_option_template_builder',0x10D038,0x10D168),
        ('preview_dispatch_allowlist',0x11E508,0x11E608),
        ('preview_context_slot_bridge',0x11E9E0,0x11EA30),
        ('preview_1b_entry',0x132070,0x1320A0),
        ('preview_1b_target_transfer',0x118628,0x1186E8),
        ('preview_16_entry',0x125F90,0x125FC8),
        ('preview_16_advance',0x118338,0x118568),
        ('select_runtime_template',0x10D7D0,0x10D800),
        ('select_block_and_offset',0x10D830,0x10D868),
        ('interactive_choice_input',0x11E748,0x11E828),
        ('confirm_transition_thunk',0x11EBA8,0x11EBD0),
        ('confirm_transition_wait',0x11E608,0x11E678),
        ('commit_selected_target',0x118D68,0x118E20),
        ('selected_index_getters',0x117D10,0x117D60),
        ('label_lookup',0x10F820,0x10F898),
        ('symbol_relative_offset',0x10FA48,0x10FA68),
        ('main_label_transfer',0x10D868,0x10DAD8),
        ('variable_handler',0x12C0C0,0x12C1B0),
        ('conditional_handler',0x12C428,0x12C590),
        ('variable_and_comparison_helpers',0x100D78,0x101074),
    ]
    return dict(schema_version=1,
        method='stdlib source-bound static MIPS operand/context analysis; no ELF execution; not REA-provider output',
        status='conditional-prologue-choice-statically-recovered; runtime-corroboration-pending',
        sources=dict(script=dict(path='local/assets/SCENARIO/sn4g.sn4',size=len(script_bytes),sha256=SCRIPT_SHA),
                     elf=dict(path='local/extracted/SLPM_664.52',size=len(elf_bytes),sha256=image.sha256)),
        lexical_scan=dict(block_selector=15,instruction_count=len(rows),
                          choice_offsets=[r['offset'] for r in rows if r['opcode']==0x6C],
                          static_framing_not_execution_order=True),
        choice=dict(instruction=first,operands=choice,nearest_label=label,targets=targets),
        gates=dict(variable_id=0x17D,current_runtime_value=None,conditions=gates,
                   interpretation='If variable 0x017D equals 1 at both gates, local control route reaches pr01_0110; inequality routes via _pr1 and transfer to pr01_0120, bypassing this choice. Not a whole-program reachability proof.',
                   transfers=[dict(instruction=script.instruction(15,a),operands=decode_operands(script.instruction(15,a)))
                              for a in (0xA2325,0xA2501)],
                   unverified='Variable initialization and meanings are not recovered; no assumption of first choice on a fresh save.'),
        context_contract=dict(preview_allowlist=allow,
            choice_factory_table_word=image.record(0x229934,False),
            preview_allowlist_words=[image.record(PREVIEW_ALLOWLIST+i*4,False) for i in range(19)],
            handler_vtables={str(op):[image.record(vt+i*4,False) for i in range(16)]
                             for op,vt in ((0x6C,0x223F68),(0x16,0x224048),(0x1B,0x225708))},
            runtime_templates=templates,
            preview_chain=['6C parse -> 1186E8 stores selector/label arrays',
                '1186E8 -> context 11E958, runtime block 32 via 10D7D0',
                'template terminal 1B -> handler slot1 132070 -> 118628',
                '118628 uses render-index +8, arrays +44/+1C, symbol lookup 10FA48, raw transfer 10D830',
                '11E508 dispatches only allowlist via handler slot1; 6A is skipped by 111738',
                '02 renders text; 16 -> 118338 advances render-index or interactive context 11E6C8',
                '118338 restores saved selector/page identifier/cursor at object+10/+14/+18 after all previews'],
            commit_chain=['11E748 input mask 0x2100 ->118288 and context11EB28',
                '11EBA8 ->11E608 waits via16BA10 then118D68',
                '118D68 when object+1D0==0 restores default context120280',
                '117D40/117D28 use selected-index +168 to read selector+44/label+1C',
                '118D68 ->10D868 selected label; normal6A goes to internal symbol then68 assignment'],
            variable_table=dict(base_virtual_address=hx(0x238AF0),element_width_bytes=2,signed_read=True,
                                operand_byte_order='big',operation_6='replace RHS; store low16',
                                comparison_6_and_7='equality',conditional_transfer_when='comparison false')),
        elf_tables=dict(arithmetic_dispatch=[image.record(0x227F80+i*4,False) for i in range(16)],
                        comparison_dispatch=[image.record(0x227FC0+i*4,False) for i in range(16)]),
        elf_evidence=[dict(name=n,**image.region(a,z)) for n,a,z in regions],
        unknowns=[
            'This is the first lexical 6C in prologue block15, conditionally reachable; first choice in the current runtime playthrough remains unverified.',
            '0x017D initial value, save-persistence mapping, semantic name and unlock policy.',
            'Other branch opcodes, call/return stack and all chapter transitions have not been modeled.',
            'Mode byte, signed option layout flags, extra-byte pairs and alternate/replay contexts are retained raw; only this mode1/flags0/extra0 sample is aligned.',
            'Exact layout/animation, input routing, font timing, and 22/04 preview side effects require wider handler implementation.',
            '0x19C910 invokes a configurable callback and read/history helpers; full side effects and registered callback were not traced.',
            'Normal label transfer also updates history/read-state; selected target and immediate assignment are recovered, full save semantics are not.',
            'MIPS subset decoding retains unknown R5900/FPU words; static windows are not complete decompilations.',
        ])


def markdown(report):
    c = report['choice']
    lines = ['# 序章条件选择分支：静态恢复', '',
        '本报告来自原始 ELF 与 sn4g.sn4 的哈希绑定静态分析，未执行 PS2 代码。',
        '它确认一个真实选择分支的参数与上下文协议，尚未证明它是当前实机存档必经的第一个选项。', '',
        '## 已确认的脚本边界', '',
        f"- block 15 的完整静态分帧含 {report['lexical_scan']['instruction_count']} 条记录，仅一个 0x6C。",
        f"- 选择位于 `{c['instruction']['offset']:#x}`，最近标签 `pr01_0110`；原始字节 `{c['instruction']['raw_hex']}`。",
        '- 参数为 mode=1、选项数=2、额外字节数=0；每项由 flag、block selector、NUL 终止标签组成。', '',
        '| index | 目标 | 正文证据 | 选择后的赋值 |', '|---|---|---|---|']
    for t in c['targets']:
        text=''.join(x['decoded_cp932'] or '[decode failed]' for x in t['preview_text_records'])
        o=t['option']; a=t['assignment']
        lines.append(f"| {o['index']} | {o['block_selector']}/{o['label']} | {text} | variable 0x{a['variable_id']:04X} = {a['rhs']} |")
    lines += ['', '正文由已分帧的 02..03 指令取得；表中仅包含选项自身，不延伸叙述后续剧情。每条正文、标签记录与赋值指令的源偏移、raw bytes、SHA-256 均保留于 JSON。', '',
        '## 为什么它是选择，而不是相邻候选文本', '',
        '0x6C 经 factory/vtable 默认槽15的 0x125B30 转入 0x125778；参数读取器调用 0x1186E8，把目标 selector 和 label 分别存入选择对象 +0x44 和 +0x1C 数组。', '',
        '0x10D038 建立 block32..41 的22字节运行时脚本。每个模板含字形 Ａ：/Ｂ：等和末尾 0x1B。预览上下文 0x11E958 使用 0x11E508 的19项白名单，调用各 handler 槽1；0x1B 的槽1为 0x132070，进入 0x118628，以 render-index（对象+8）查询目标并通过 0x10FA48 / 0x10D830进入真实选项标签。', '',
        '两个目标的前缀均为 22 → 6A → 02正文03 → 04 → 16。6A 不在预览白名单，原程序以 0x111738 跳过其操作数；02正文被显示，16 的槽1调用 0x118338，转下一模板或进入交互上下文 0x11E6C8。这是原有上下文明确规定的跳过，不是将未知指令猜成 NOP。', '',
        '确认路径从 0x11E748 的输入 mask 0x2100 进入过渡上下文，0x11E608 等待后调用 0x118D68。普通路径恢复默认上下文，并通过 selected-index（+0x168）取得 selector/label，调用 0x10D868。输入 mask 的物理按键归属未在本报告恢复。', '',
        '回到正常上下文时 6A 生效，分别跳至 `_pr2` / `_pk0`，首条68执行赋值。0x100F18 操作表的 index6直接返回 RHS，再由0x100EE0写16位；不是根据分支文字猜测变量用途。', '',
        '## 前置条件与限制', '',
        '0xA226D 和 0xA2318 的70都比较 variable0x017D 与1，operator7为相等，比较为假才跳转。等于1的局部路径通过0xA2325进入pr01_0110；另一局部路径通过_pr1及0xA2501进入pr01_0120，跳过选项。变量初值、解锁含义、存档映射未知，因此此处称“首个线性/条件选择”，不能称“新游戏必见首选项”。', '',
        '解析器对未知 operand opcode、未实现比较/变量操作、未知变量值、越界、未终止字符串、未消费尾字节全部报错。它只提供选择协议及赋值的窄范围语义参考，没有执行全部剧情、动画、音频或原生存读档。', '',
        '## 下一步', '',
        '先用原版实机核对是否出现这两个选项，确定0x017D条件；若被跳过，应继续记录真正首次可交互选项并按同一解析器解析其label。原生实现应分别保存script selector/cursor、selected/render index、变量表和选择阶段，待history/read-state及保存格式恢复后再谈完整兼容。', '',
        '重跑：`python tools/choice_branch.py`；验证：`python -m unittest discover -s tests -p test_choice_branch.py`。', '',
        '### 未恢复事项', '']
    lines += ['- '+u for u in report['unknowns']]
    return '\n'.join(lines)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--script',type=Path,default=ROOT/'local/assets/SCENARIO/sn4g.sn4')
    p.add_argument('--elf',type=Path,default=ROOT/'local/extracted/SLPM_664.52')
    p.add_argument('--json',type=Path,default=ROOT/'analysis/choice_branch.json')
    p.add_argument('--doc',type=Path,default=ROOT/'docs/CHOICE_BRANCH.md')
    args=p.parse_args()
    paths=[x.resolve() for x in (args.script,args.elf,args.json,args.doc)]
    if len(set(paths)) != 4:
        raise ValueError('Sources and outputs must be distinct')
    report=build_report(args.script.read_bytes(),args.elf.read_bytes())
    args.json.parent.mkdir(parents=True,exist_ok=True)
    args.doc.parent.mkdir(parents=True,exist_ok=True)
    args.json.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    args.doc.write_text(markdown(report),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],choice_offset=CHOICE_OFFSET,
                          targets=len(report['choice']['targets']),elf_windows=len(report['elf_evidence']))))


if __name__ == '__main__':
    main()
