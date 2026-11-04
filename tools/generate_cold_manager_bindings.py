"""Compile verified fixed-ELF constructor facts into native manager bindings."""
import argparse
from pathlib import Path
from vm_handlers import Image, ROOT, factory_case, constructor_vtable, signed16


def context_rows(image):
    """Verify every instruction of the original hot/cold getter and both constructor forms."""
    rows = []
    for call in range(0x110694, 0x110760, 8):
        target = image.word(call)
        # First three delay slots set up semaphore pointers used later in 110778.
        delay = {0x110694: 0x26735588, 0x11069c: 0x261055a8, 0x1106a4: 0x26340048}.get(call, 0)
        if target >> 26 != 3 or image.word(call + 4) != delay:
            raise ValueError(f'Context initialization call changed at {call:x}')
        getter = (target & 0x3ffffff) << 2
        w = [image.word(getter + n * 4) for n in range(17)]
        cell_offset = w[1] & 0xffff
        ctor = (w[9] & 0x3ffffff) << 2
        size = w[7] & 0xffff
        expected = [0x27bdfff0, 0x8f820000 | cell_offset, 0xffb00000, 0xffbf0008,
                    0x14400009, 0xdfb00000, 0x0c043eb4, 0x24040000 | size,
                    0x0040802d, 0x0c000000 | (ctor >> 2), 0x0040202d, 0xaf900000 | cell_offset,
                    0x0200102d, 0xdfb00000, 0xdfbf0008, 0x03e00008, 0x27bd0010]
        if w != expected:
            raise ValueError(f'Unexpected context getter at {getter:x}')
        secondary = 0
        if size == 4:
            primary = constructor_vtable(image, ctor)
        elif size == 8:
            w = [image.word(ctor + n * 4) for n in range(11)]
            if ([x >> 16 for x in w[:4]] != [0x3c0e, 0x3c0f, 0x25ce, 0x25ef]
                    or w[4] != 0xac8e0000 or w[5] >> 16 != 0x25cd
                    or w[6:] != [0xac8f0004, 0x8dcffff4, 0x008f2021, 0x03e00008, 0xac8d0000]):
                raise ValueError(f'Unexpected dual-vtable constructor at {ctor:x}')
            primary = ((w[0] & 0xffff) << 16) + signed16(w[2])
            if image.word(primary - 12) != 4:
                raise ValueError(f'Unexpected secondary offset for {primary:x}')
            secondary = primary + signed16(w[5])  # delay-slot store overrides initial secondary vtable
        else:
            raise ValueError(f'Unsupported allocation of {size} bytes')
        rows.append((getter, 0x23daf0 + signed16(cell_offset), primary, secondary))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    check = parser.parse_args().check
    image = Image((ROOT / 'local/extracted/SLPM_664.52').read_bytes())
    lines = ['// Generated from the hash-verified original ELF. Regenerate with tools/generate_cold_manager_bindings.py.',
             '#pragma once', '#include <array>', '#include <cstdint>', 'namespace kx3::cold_factory {',
             'struct Binding { std::uint32_t branch, constructor, vtable, bytes; };']
    for name, table, length in [('opcode', 0x229784, 137), ('auxiliary', 0x229770, 5)]:
        lines.append(f'inline constexpr std::array<Binding,{length}> {name} = {{{{')
        for i in range(length):
            # 10FD48 rejects >= 0x87 and 110580 routes to the original null case.
            branch = image.word(table + i * 4) if i < 135 else 0x110508
            case = factory_case(image, branch)
            ctor = int(case['constructor'], 16) if case['kind'] == 'constructed' else 0
            vtable = constructor_vtable(image, ctor) if ctor else 0
            lines.append(f'    {{0x{branch:08x},0x{ctor:08x},0x{vtable:08x},{case.get("allocation_size", 0)}}}, // {i:02x}')
        lines.append('}};')
    contexts = context_rows(image)
    lines.append('struct Context { std::uint32_t getter, cell, primary, secondary; };')
    lines.append(f'inline constexpr std::array<Context,{len(contexts)}> contexts = {{{{')
    for row in contexts:
        lines.append('    {' + ','.join(f'0x{x:08x}' for x in row) + '},')
    lines.append('}};')
    lines.append('}')
    output = ROOT / 'port/core/manager_handler_bindings.hpp'
    content = '\n'.join(lines) + '\n'
    if check:
        if output.read_text() != content: raise ValueError('Original factory bindings differ')
    else:
        output.write_text(content)
    print(f'Verified 137 opcode slots, 5 auxiliary slots and {len(contexts)} context constructors.')


if __name__ == '__main__':
    main()
