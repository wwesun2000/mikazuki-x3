"""Hash-bound, bounded static handler mapping for SLPM_664.52. Never executes it.

Function windows below are evidence slices, not a complete CFG or decompilation.
MIPS delay slots are retained; undecoded R5900 words remain explicitly unknown.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from vm_flow import decode, EXPECTED_SHA256

ROOT = Path(__file__).resolve().parents[1]
FACTORY_TABLE = 0x229784
NULL_CASE = 0x110508
ALLOCATOR = 0x10FAD0
READERS = {
    0x10D5D8: 'read_a1_bytes_big_endian_from_script_plus_D8',
    0x10D610: 'advance_main_cursor_by_a1_return_relative_offset',
    0x10D638: 'consume_header_marker_skip_two_if_zero_return_cursor',
    0x10D680: 'current_cstring_pointer_then_advance_strlen_plus_one',
    0x10D6C8: 'read_a1_bytes_big_endian_from_script_plus_DC',
    0x10D720: 'get_main_cursor_pointer',
    0x10D788: 'advance_aux_cursor_by_a1_return_relative_offset',
}


def hx(value):
    return f'0x{value:08x}'


def signed16(word):
    value = word & 0xFFFF
    return value if value < 0x8000 else value - 0x10000


class Image:
    """ELF32 PT_LOAD mapping with no memory-only or cross-segment reads."""
    def __init__(self, data):
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        if self.sha256 != EXPECTED_SHA256:
            raise ValueError('Build SHA-256 mismatch; fixed-address analysis refused')
        if data[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError('Expected little-endian ELF32')
        header = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
        if header[2] != 8 or header[9] != 32:
            raise ValueError('Expected MIPS ELF32 program headers')
        self.segments = []
        for i in range(header[10]):
            offset = header[5] + i * header[9]
            if offset < 0 or offset + 32 > len(data):
                raise ValueError('Program header outside source')
            kind, off, va, _, size, memsize, flags, alignment = struct.unpack_from('<8I', data, offset)
            if kind == 1:
                if size > memsize or off + size > len(data):
                    raise ValueError('Invalid file-backed PT_LOAD size')
                self.segments.append(dict(virtual_address=va, file_offset=off,
                                          file_size=size, memory_size=memsize,
                                          flags=flags, alignment=alignment))

    def offset(self, address, size=4):
        if size <= 0 or address < 0:
            raise ValueError('Invalid read range')
        matches = [s for s in self.segments if s['virtual_address'] <= address
                   and address + size <= s['virtual_address'] + s['file_size']]
        if len(matches) != 1:
            raise ValueError('Address not in exactly one file-backed PT_LOAD segment')
        s = matches[0]
        return s['file_offset'] + address - s['virtual_address']

    def word(self, address):
        if address % 4:
            raise ValueError('Unaligned instruction/table address')
        return struct.unpack_from('<I', self.data, self.offset(address))[0]

    def record(self, address, instruction=True):
        off = self.offset(address)
        result = dict(address=hx(address), file_offset=off,
                      raw_hex=self.data[off:off+4].hex(), raw_word=f'{self.word(address):08x}')
        if instruction:
            result['decoded'] = decode(self.word(address), address)
        return result

    def region(self, start, end):
        if start % 4 or end % 4 or end <= start or end-start > 0x4000:
            raise ValueError('Invalid or excessive evidence window')
        self.offset(start, end-start)
        off = self.offset(start, end-start)
        return dict(start=hx(start), end_exclusive=hx(end), file_offset=off,
                    raw_sha256=hashlib.sha256(self.data[off:off+end-start]).hexdigest(),
                    boundary_status='bounded-static-window; not a proven complete CFG',
                    instructions=[self.record(a) for a in range(start, end, 4)],
                    direct_edges=direct_edges(self, start, end))


def direct_edges(image, start, end):
    result = []
    for a in range(start, end, 4):
        w = image.word(a)
        if w >> 26 in (2, 3):
            target = ((a+4) & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
            row = dict(site=hx(a), file_offset=image.offset(a), raw_word=f'{w:08x}',
                       target=hx(target), kind='jal' if w >> 26 == 3 else 'j',
                       delay_slot=image.record(a+4))
            if target in READERS:
                row['reader_role'] = READERS[target]
                # A literal in the unconditional jal delay slot has especially clear provenance.
                for candidate in [a+4, a-4, a-8, a-12]:
                    if candidate < start:
                        continue
                    cw = image.word(candidate)
                    if cw >> 26 in (9, 25) and (cw >> 21) & 31 == 0 and (cw >> 16) & 31 == 5:
                        row['a1_literal_candidate'] = dict(value=signed16(cw),
                            evidence=image.record(candidate),
                            status='executed-call-delay-slot' if candidate == a+4 else
                            'nearby-syntactic-literal; register-liveness-and-branch-path-unproven')
                        break
            result.append(row)
    return result


def factory_case(image, case):
    if case == NULL_CASE:
        if image.word(case) != 0x1000FE1D or image.word(case+4) != 0x0000802D:
            raise ValueError('Null factory case changed')
        return dict(kind='null', evidence=image.region(case, case+8))
    words = [image.word(case+i*4) for i in range(5)]
    # Fixed observed sequence: allocation with a0=size in delay slot, save v0,
    # call constructor with a0=v0 in its delay slot.
    if words[0] != 0x0C043EB4 or words[1] & 0xFFFF0000 != 0x24040000 or \
            words[2] != 0x0040802D or words[3] >> 26 != 3 or words[4] != 0x0040202D:
        raise ValueError(f'Unrecognized factory case at {hx(case)}')
    constructor = ((case+16) & 0xF0000000) | ((words[3] & 0x3FFFFFF) << 2)
    return dict(kind='constructed', allocation_size=words[1] & 0xFFFF,
                constructor=hx(constructor), evidence=image.region(case, case+28))


def constructor_vtable(image, constructor):
    a, b, c, d = [image.word(constructor+i*4) for i in range(4)]
    if a & 0xFFFF0000 != 0x3C0F0000 or b & 0xFFFF0000 != 0x25EF0000 or \
            c != 0x03E00008 or d != 0xAC8F0000:
        raise ValueError(f'Constructor pattern mismatch at {hx(constructor)}')
    return ((a & 0xFFFF) << 16) + signed16(b)


def build_report(image, source_path):
    targets = [image.word(FACTORY_TABLE+i*4) for i in range(135)]
    cases = {hx(a): factory_case(image, a) for a in sorted(set(targets))}
    allowed = [image.word(0x206010+i*4) for i in range(113)]
    classes = []
    regions = {}

    def retain(start, end):
        key = f'{start:08x}-{end:08x}'
        if key not in regions:
            regions[key] = image.region(start, end)
        return key

    for case_address, case in cases.items():
        if case['kind'] == 'null':
            continue
        ctor = int(case['constructor'], 16)
        vt = constructor_vtable(image, ctor)
        words = [image.word(vt+i*4) for i in range(28)]
        if any(not 0x100000 <= v < 0x204B38 or v % 4 for v in words[:25]) or any(words[25:]):
            raise ValueError(f'Unexpected 25-method plus zero-padding table at {hx(vt)}')
        methods = words[:25]
        entry = methods[15]
        end = min(v for v in methods if v > entry)
        helper_start, helper_end = ctor+16, min(methods)
        default_region = retain(entry, end)
        helper_edges = direct_edges(image, helper_start, helper_end) if helper_start < helper_end else []
        entry_edges = regions[default_region]['direct_edges']
        starts = {helper_start} if helper_start < helper_end else set()
        for e in helper_edges + entry_edges:
            target = int(e['target'], 16)
            if helper_start <= target < helper_end:
                starts.add(target)
        starts = sorted(starts)
        windows = {}
        for i, start in enumerate(starts):
            windows[start] = retain(start, starts[i+1] if i+1 < len(starts) else helper_end)
        reachable = set()
        pending = [int(e['target'], 16) for e in entry_edges]
        while pending:
            address = pending.pop()
            if address in reachable or address not in windows:
                continue
            reachable.add(address)
            pending.extend(int(e['target'], 16) for e in regions[windows[address]]['direct_edges'])
        reader_windows = []
        for address, region_id in [(entry, default_region)] + list(windows.items()):
            reads = [e for e in regions[region_id]['direct_edges'] if 'reader_role' in e]
            if reads:
                reader_windows.append(dict(entry=hx(address), evidence_region=region_id,
                    default_context_direct_edge_reachable=address == entry or address in reachable,
                    reader_calls=reads))
        opcodes = [i for i, t in enumerate(targets) if t == int(case_address, 16)]
        classes.append(dict(id=f'vtable_{vt:08x}', opcodes=opcodes,
            factory_case=case_address, allocation_size=case['allocation_size'],
            constructor=case['constructor'], constructor_evidence=retain(ctor, ctor+16),
            vtable_address=hx(vt), vtable_entries=[dict(slot=i, **image.record(vt+i*4, False),
                target=hx(words[i])) for i in range(28)],
            vtable_layout='25 observed executable pointers, followed by three zero words; class names unknown',
            default_context_slot=15, default_context_entry=hx(entry),
            default_context_evidence=default_region, default_context_direct_edges=entry_edges,
            local_helper_windows=[dict(entry=hx(a), evidence_region=k,
                reachable_via_default_context_direct_edges=a in reachable) for a, k in windows.items()],
            parameter_reader_windows=reader_windows,
            parameter_reader_status=('reader-calls-observed' if reader_windows else
                'no-known-reader-call-in-bounded-windows; does-not-prove-no-operands'),
            confidence='high-static-for-pointer-chain; conditional/direct-edge reachability only',
            processing_entry_status='slot15 is dispatch entry; helper windows are not validated opcode semantics'))

    by_case = {c['factory_case']: c for c in classes}
    entries = []
    for opcode, target in enumerate(targets):
        c = by_case.get(hx(target))
        entries.append(dict(opcode=opcode, opcode_hex=f'0x{opcode:02x}',
            factory_table_word=image.record(FACTORY_TABLE+opcode*4, False),
            factory_case=hx(target), status='mapped-handler' if c else 'null-handler',
            class_id=c['id'] if c else None, constructor=c['constructor'] if c else None,
            vtable=c['vtable_address'] if c else None,
            default_context_entry=c['default_context_entry'] if c else None,
            default_context_allowlist_member=opcode in allowed))

    fixed = {
        'factory_dispatch_and_loop': (0x10FD28, 0x10FDB0),
        'factory_default_out_of_range': (0x110580, 0x110588),
        'default_context_step': (0x120308, 0x1203E0),
        'default_context_slot15_delegate': (0x1203E0, 0x12040C),
        'manager_tick': (0x113148, 0x113260),
        'inline_text_driver': (0x1126E0, 0x112CFC),
        'main_reader': (0x10D5D8, 0x10D610),
        'main_cursor_delta': (0x10D610, 0x10D638),
        'header_consumer': (0x10D638, 0x10D680),
        'cstring_consumer': (0x10D680, 0x10D6C8),
        'aux_reader': (0x10D6C8, 0x10D700),
        'main_cursor_pointer': (0x10D720, 0x10D728),
        'aux_cursor_delta': (0x10D788, 0x10D7B0),
    }
    fixed_refs = {name: retain(a, b) for name, (a, b) in fixed.items()}
    inline_targets = [image.word(0x229A0C+i*4) for i in range(134)]
    inline_region = regions[fixed_refs['inline_text_driver']]
    return dict(schema_version=1, evidence_id='VM-HANDLERS-001',
        authority='local-static-analysis-not-REA', status='bounded-static-map-completed',
        source=dict(path=str(source_path), sha256=image.sha256, size_bytes=len(image.data),
                    file_backed_load_segments=image.segments),
        method='Standard library, verified factory/constructor patterns, raw table words, bounded helper windows and direct edges; no target execution.',
        counts=dict(factory_table_entries=135, unique_factory_cases=len(cases),
                    constructed_classes=len(classes), null_table_entries=sum(e['status']=='null-handler' for e in entries),
                    default_allowlist_entries=len(allowed), initialized_manager_slots=137,
                    evidence_regions=len(regions)),
        correction_to_previous_report=dict(
            previous='The earlier VM_FLOW report described the factory constructor loop as 135 indices.',
            corrected='The switch table covers 0..0x86 (135). The loop increment compares s1 < 0x89, initializes 137 slots, and indices 0x87/0x88 route through the default null case.',
            evidence=['factory_dispatch_and_loop', 'factory_default_out_of_range'],
            out_of_table_slots=[dict(opcode=i, factory_case=hx(NULL_CASE), status='null-handler') for i in (0x87, 0x88)]),
        opcode_entries=entries, factory_cases=cases, handler_classes=classes,
        default_context_allowlist=allowed, reader_helpers={hx(k): v for k, v in READERS.items()},
        fixed_evidence=fixed_refs, evidence_regions=regions,
        inline_text_detail=dict(
            start='0x001126e0', end_exclusive='0x00112cfc', instruction_count=391,
            raw_sha256=inline_region['raw_sha256'],
            direct_call_count=sum(e['kind']=='jal' for e in inline_region['direct_edges']),
            unique_direct_targets=sorted({e['target'] for e in inline_region['direct_edges']}),
            lookahead_switch=dict(address='0x00229a0c', count=134,
                entries=[dict(opcode=i, target=hx(t), **image.record(0x229A0C+i*4, False))
                         for i,t in enumerate(inline_targets)],
                groups={hx(t):[i for i,v in enumerate(inline_targets) if v==t]
                        for t in sorted(set(inline_targets))},
                dispatch_site='0x00112c08', context_delegate_site='0x00112cc0',
                significance='Lookahead can delegate selected opcodes through current context vtable+8. This is a third auxiliary 134-entry switch, not the complete VM opcode set.'),
            observations=[
                dict(range=['0x0011276c','0x00112798'], statement='Main cursor byte 0x03 clears text-active flag; 0x21 is skipped; otherwise rewind one and read two bytes.'),
                dict(range=['0x00112830','0x00112998'], statement='Lookahead preserves/restores block, cursor, context, font state and other manager/script state; font fields are not assumed x/y.'),
                dict(site='0x001129d4', target='0x0016b200', statement='Font-side call can receive current plus up to two lookahead characters; exact render timing unverified.'),
                dict(field='manager+0x2B8', statement='Auxiliary-cursor path searches 0x02, reads two-byte units to 0x03, calls font helpers; ruby association remains a candidate.'),
            ]),
        inline_text_findings=[
            'Opcode 0x02 -> constructor 0x122BE0 -> vtable 0x223DA8 -> slot15 0x122DA0: sets manager+0x2C0=1 and tail-jumps to 0x122BF0, which sets +0x2B4=1. No script operand reader is called in these two slices.',
            'Manager tick selects 0x1126E0 while +0x2B4 is set. Bounded driver is [0x1126E0,0x112CFC); internal early return does not end the lexical function window.',
            'Main text path uses ScriptData+0xD8; byte 0x03 terminates the active text flag and 0x21 is skipped. Other bytes are rewound by one then read as a two-byte aggregate; auxiliary text path uses +0xDC. Precise mode predicates are not fully recovered.',
            '0x10D5D8 and 0x10D6C8 aggregate bytes big-endian irrespective of little-endian ELF. 0x10D638 consumes a one-byte marker, skips two further bytes if zero, and returns the relative cursor; it does not return the encoded length.',
        ],
        unknowns=[
            'Class and function labels are analyst labels; source names were not recovered.',
            'Pointer mapping is not proof that a given opcode/context path executes at a particular game screen.',
            'Direct-edge helper reachability is an overapproximation; branch predicates, indirect calls and runtime state are unresolved.',
            'Helper windows partition the pre-vtable-method region using observed direct call/jump targets; exact function boundaries and complete CFGs are not asserted.',
            'Known reader calls do not provide a complete operand grammar; absence of a reader call does not establish zero operands.',
            'R5900/MMI/VU decoding is incomplete. Unknown words remain raw evidence, never treated as NOP.',
            'Conditional VM, selection, full text/ruby timing, mode switches, save serialization and compatibility across games remain unimplemented.',
        ])


def markdown(report):
    rows = []
    for c in sorted(report['handler_classes'], key=lambda c: min(c['opcodes'])):
        readers = ', '.join(w['entry'] for w in c['parameter_reader_windows']) or '未见已知读取调用'
        helpers = ', '.join(e['target'] for e in c['default_context_direct_edges']) or '无直接调用/尾跳'
        rows.append('| '+', '.join(f'{o:02X}' for o in c['opcodes'])+' | '+c['constructor']+' | '+
                    c['vtable_address']+' | '+c['default_context_entry']+' | '+readers+' | '+helpers+' |')
    nulls = ', '.join(e['opcode_hex'] for e in report['opcode_entries'] if e['status']=='null-handler')
    return '''# Opcode handler 静态映射

证据 `VM-HANDLERS-001`，详见 `analysis/vm_handlers.json`。工具绑定 ELF SHA-256
`50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160`；不匹配即拒绝分析。
使用 Python 标准库复用现有指令解码器，没有执行目标、启动模拟器或安装依赖。
这是本地静态证据，不是 REA 运行或动态跟踪结果。

## 已恢复的完整指针链

135 个 jump-table 项（0x00–0x86）全部恢复为 factory case → 构造函数 → vtable →
默认上下文 slot15。表中共有 73 个不同 case，其中 72 个分配对象并调用构造函数，
一个 case 写 null，对应 20 个表内 opcode。72 个构造函数均为已校验的四指令
vtable 安装序列；每张表观察到 25 个代码指针和随后三个零字。

**修正此前结论：** 135 是 switch 表项数。`0x10FD88` 为 `slti t7,s1,137`，
所以管理器构造循环初始化 137 个槽。索引 0x87、0x88 经 `0x110580` 转入空 case，
没有从 135 项表外读取新处理器。原始循环、default case 和表字节均已保留。

默认上下文 `0x1203E0` 从 handler vtable `+0x3C` 取入口，即零起算 slot15。
默认允许表 113 项也单独保留；是否分配 handler 和是否被该上下文允许不是同一属性。

表内 null opcode：''' + nulls + '''。

## 参数读取与处理入口

下表按类分组。slot15 是处理入口，最后一列是该入口的直接调用/尾跳目标。
“读取窗口”包含类局部窗口中已知 ScriptData 读取助手的调用；是否能从 slot15
沿直接边到达在 JSON 中逐项标明。部分窗口可能只供其他上下文使用。
不能把所有读取窗口强行串成操作数格式，也不能因未见读取调用断言没有参数。

| Opcode（十六进制） | 构造函数 | vtable | 默认 slot15 | 含参数读取调用的局部窗口 | slot15 直接目标 |
| --- | --- | --- | --- | --- | --- |
''' + '\n'.join(rows) + '''

JSON 的 `opcode_entries` 保留全部 135 个表项的文件偏移、原始字节和指针；
`handler_classes` 保留类内 helper 窗口、slot15、reader 调用及邻近参数字面量证据。
`evidence_regions` 保存全部选取窗口的原机器码与部分解码。窗口边界由构造器、
vtable 方法入口和直接调用目标限定，属于静态范围划分，不声称完成全部 CFG。
MIPS 延迟槽原指令随调用保留；“附近字面量”与“调用延迟槽字面量”分开标注。

## 文本与控制流的可实施锚点

- `0x02` → `0x122BE0` → vtable `0x223DA8` → slot15 `0x122DA0`。
  该方法设置 manager `+0x2C0=1`，再尾跳 `0x122BF0` 设置 `+0x2B4=1`。
  两段中未调用脚本参数读取器，正文由后续 tick 中 `0x1126E0` 消费。
- 内联文字驱动保存区间为 `[0x1126E0,0x112CFC)`，包含内部提前返回后的代码，
  没有用“遇到首个 jr ra”错误截断。主路径从 ScriptData `+0xD8` 读取：
  `0x03` 清文本活动标记；`0x21` 被跳过；普通字符先退一个字节再读取两字节。
  还有 `+0xDC` 辅助游标路径。分支条件、精确逐字节奏与 ruby 模式仍未全部恢复。
- 该驱动还有第三张 134 项辅助表 `0x229A0C`，分派于 `0x112C08`；部分前瞻
  opcode 在 `0x112CC0` 通过当前上下文 vtable `+8` 调用 handler。因此正文推进
  也可能含控制操作，不能直接把候选文本数组依次显示来替代原版 VM。
- `0x10D5D8`／`0x10D6C8` 按 `(result << 8) | byte` 聚合 a1 个字节，
  因此脚本多字节读取是大端顺序，不能套用 ELF 的小端字节序。
- `0x10D638` 消耗一个标记字节；为零时再跳过两个字节，最后返回当前相对游标。
  它不是“返回长度值”的函数。`0x10D680` 是返回当前 C 字符串并前移 strlen+1 的助手。
- `0x6A/0x6B/0x85` 共享 vtable `0x223EF8`，slot15 `0x1253E8` 调用
  `0x124D48` 读取头、selector、NUL 结尾标签，再条件调用 `0x124E38` 转移标签。
  这加强此前跳转候选证据，仍未证明 0x6B 的附加 flag 就是 call/return。

当前成果可以作为原生 VM 的 handler 表、入口和读取助手实现参考，尚不是可运行 VM。
选择、条件表达式、所有上下文、原版存档字段和全剧情兼容均仍需恢复。
不支持的 R5900 指令在报告中保留为 unknown，不能视作 NOP。

## 重现与验证

```powershell
python tools/vm_handlers.py
python -m unittest discover -s tests -p test_vm_handlers.py -v
```

默认生成本 JSON 和本 Markdown，读取源 ELF 前后不写入源文件。自动测试覆盖错误构建
拒绝、PT_LOAD 边界、135 项映射完整性、null 与 137 槽边界、文本/标签链及读取助手证据。
'''


def write_outputs(report, source, output, doc):
    resolved = [Path(p).resolve() for p in (source, output, doc)]
    if len(set(resolved)) != 3:
        raise ValueError('Source and both output paths must be distinct')
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    doc.write_text(markdown(report), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, default=ROOT/'local/extracted/SLPM_664.52')
    parser.add_argument('--output', type=Path, default=ROOT/'analysis/vm_handlers.json')
    parser.add_argument('--doc', type=Path, default=ROOT/'docs/VM_HANDLERS.md')
    args = parser.parse_args()
    # No output mutation before source identity and analysis have both succeeded.
    report = build_report(Image(args.elf.read_bytes()), args.elf)
    write_outputs(report, args.elf, args.output, args.doc)
    print(json.dumps(report['counts']))


if __name__ == '__main__':
    main()
