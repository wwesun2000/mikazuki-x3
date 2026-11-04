"""Create declared inputs on the fixed slot7 RAM; never compute expected outputs."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA = '46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'


def main():
    base_plan = json.loads((ROOT / 'analysis/ghidra/oracle-choice-transfer-plan.json').read_text())
    ram_path = Path(base_plan['ram_input_path'])
    ram = ram_path.read_bytes()
    assert hashlib.sha256(ram).hexdigest() == base_plan['ram_sha256']
    assert base_plan['archive_sha256'] == STATE_SHA
    assert hashlib.sha256((ROOT / base_plan['archive']).read_bytes()).hexdigest() == STATE_SHA
    elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()
    assert hashlib.sha256(elf).hexdigest() == ELF_SHA
    assert ram[0x100000:0x204b38] == elf[0x1000:0x105b38]
    u = lambda a: struct.unpack_from('<I', ram, a)[0]
    h = lambda a: struct.unpack_from('<H', ram, a)[0]
    manager = u(0x235e40); script = u(manager + 0x38); choice = u(manager + 8)
    resume = u(manager + 0x28); special = u(manager + 0x20); default_context = u(0x235f3c)
    source_selector = u(script + 0xd0)
    source_base = u(u(script + 8 + source_selector * 4) + 0x430)
    source_offset = (u(script + 0xd8) - source_base) & 0xffffffff
    handlers = {op: u(manager + 0x5c + op * 4) for op in (0x6a, 0x6b, 0x85)}
    assert all(u(u(handler) + 60) == 0x1253e8 for handler in handlers.values())
    public_selector = u(choice + 0x44 + 4)
    public_pointer = u(choice + 0x1c + 4)
    public_name = ram[public_pointer:ram.index(0, public_pointer, public_pointer + 128)]
    # Find a real private label through the original relocated bucket chains.
    block = u(script + 8 + public_selector * 4); private = None; seen = set()
    for bucket in range(256):
        record = u(block + 0x30 + bucket * 4)
        while record and record not in seen:
            assert 0 < record < len(ram) - 136
            seen.add(record)
            name = ram[record + 8:ram.index(0, record + 8, record + 136)]
            if name == b'_rx8':
                private = (record, name, h(record + 2), u(record + 4))
            delta = h(record); record = record + delta if delta else 0
    assert private and private[2] == 0xffff
    labels = [('public', public_name, public_pointer), ('private-prefix', private[1], private[0] + 8)]
    scratch, out_pointer = 0x1f80000, 0x1f80400
    cases = []
    def raw_patch(address, data, reason):
        assert not (address < 0x204b38 and address + len(data) > 0x100000)
        assert 0 <= address <= len(ram) - len(data)
        return dict(address=f'0x{address:08x}', hex=data.hex(), reason=reason)
    def word(address, value, reason):
        return raw_patch(address, struct.pack('<I', value & 0xffffffff), reason)
    def resume_patch(active, relative=source_offset, context=default_context):
        return raw_patch(resume, struct.pack('<5I', source_selector, u(script + 0xd4), relative, context, active),
                         'Declared resume record from original selector/label/relative cursor; explicit context and active flag')
    def add(identifier, entry, registers, patches, **coverage):
        cases.append(dict(id=identifier, function_address=f'0x{entry:08x}',
                          return_defined=entry != 0x11a220, coverage=coverage,
                          input=dict(registers={k: f'0x{v & 0xffffffffffffffff:016x}' for k, v in registers.items()}, memory=patches)))
    for active in (0, 1, 0x80000000, 0xffffffff):
        add(f'active-{active:08x}', 0x11a210, dict(a0=resume), [word(resume + 16, active, 'Nonzero predicate input')], active=active)
    for delta in (0, 16):
        for context in (u(manager + 0x40), default_context):
            add(f'restore-{delta}-{context:08x}', 0x11a220, dict(a0=resume),
                [resume_patch(1, source_offset + delta, context)], active=1, cursor_delta=delta, context=f'0x{context:08x}')
    def operand_patches(opcode, label_name, active, marker):
        start = scratch + (12 if marker == 0 else 14)
        prefix = b'\0\xA6\x5C' if marker == 0 else bytes([marker])
        encoded = prefix + bytes([public_selector]) + label_name + b'\0'
        storage = bytearray([0xa5] * 256); offset = start - scratch; storage[offset:offset + len(encoded)] = encoded
        return [raw_patch(scratch, storage, 'Synthetic operand framing plus bytes of a verified original public/private label; name aligned at scratch+16'),
                word(script + 0xd8, start, 'Set cursor to the explicitly supplied operand bytes'),
                resume_patch(active), word(manager + 0x40, default_context, 'Install real default context, as original choice transition does'),
                word(special + 4, int(opcode == 0x85 and label_name.startswith(b'_')), 'Explicit special-state getter input'),
                raw_patch(out_pointer, bytes.fromhex('a55aa55a') * 16, 'Sentinel out-word and surrounding canary')]
    for opcode in (0x6a, 0x6b, 0x85):
        for label_kind, label_name, _ in labels:
            for active in (0, 1):
                for marker in (0, 0x0b):
                    add(f'parse-{opcode:02x}-{label_kind}-a{active}-m{marker:02x}', 0x124d48,
                        dict(a0=handlers[opcode], a1=out_pointer, a2=opcode),
                        operand_patches(opcode, label_name, active, marker), opcode=opcode, label_kind=label_kind, active=active, framing_marker=marker)
    for entry, opcodes in ((0x1253e8, (0x6a, 0x6b, 0x85)), (0x124f00, (0x85,))):
        for opcode in opcodes:
            for label_kind, label_name, _ in labels:
                for active in (0, 1):
                    add(f'wrapper-{entry:08x}-{opcode:02x}-{label_kind}-a{active}', entry,
                        dict(a0=handlers[opcode], a1=default_context, a2=source_offset, a3=opcode),
                        operand_patches(opcode, label_name, active, 0x0b), opcode=opcode, label_kind=label_kind, active=active,
                        route='actual snapshot slot15' if entry == 0x1253e8 else 'explicit alternate entry with the verified common object layout')
    for opcode in (0x6a, 0x6b, 0x85):
        for label_kind, _, name_pointer in labels:
            add(f'execute-{opcode:02x}-{label_kind}', 0x124e38, dict(a0=handlers[opcode], a1=opcode),
                [raw_patch(handlers[opcode] + 4, struct.pack('<2I', public_selector, name_pointer), 'Already-parsed target fields from original label record'),
                 word(manager + 0x40, default_context, 'Install real default context for transition')], opcode=opcode, label_kind=label_kind)
    observed = list(base_plan['observed_regions'])
    for name, address, size in [('resume', resume, 0x40), ('special', special, 0x40),
                               ('operand_storage', scratch, 256), ('parse_out', out_pointer, 64),
                               *[(f'handler_{op:02x}', handler, 0x40) for op, handler in handlers.items()]]:
        observed.append(dict(name=name, address=f'0x{address:08x}', size=size))
    plan = {k: base_plan[k] for k in ('schema', 'elf_sha256', 'archive_sha256', 'archive', 'ram_sha256', 'ram_size', 'ram_input_path')}
    plan.update(case_kind='Actual slot7 RAM plus explicit operand/resume/handler input patches; no expected values',
                base_plan_sha256=hashlib.sha256((ROOT / 'analysis/ghidra/oracle-choice-transfer-plan.json').read_bytes()).hexdigest(),
                original_targets=dict(manager=hex(manager), script=hex(script), resume=hex(resume), special=hex(special),
                                      public_label=public_name.decode('ascii'), private_label=private[1].decode('ascii'),
                                      private_record=hex(private[0]), handlers={hex(k): hex(v) for k, v in handlers.items()}),
                observed_regions=observed, cases=cases)
    assert len(cases) == 54
    destination = ROOT / 'analysis/ghidra/oracle-control-transfer-plan.json'
    destination.write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps(dict(plan=str(destination.relative_to(ROOT)), cases=len(cases), original_private_label=private[1].decode('ascii'))))


if __name__ == '__main__':
    main()
