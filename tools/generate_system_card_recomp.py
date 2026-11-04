"""Recover the ordinary system-menu card modes from the retail state tables."""
import re
import struct
from generate_sound_recomp import export, pilot

entries = (0x100d30, 0x102548, 0x1032b8, 0x19d808, 0x1a48a0, 0x1a49f8, 0x1a5de8, 0x1a6588, 0x1a70d0,
           0x1a89e0, 0x1a8a00, 0x1a8a20)
tables = ((0x1a5de8, 0x230a18, 50), (0x1a6588, 0x230ae0, 50), (0x1a70d0, 0x230c84, 51))

if __name__ == '__main__':
    iso = pilot.ROOT / 'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run = pilot.generate(iso, pilot.EVAL / 'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                         entries=entries, work=pilot.ROOT / 'local/pc-core/ps2recomp-system-card',
                         callback_export={a:pilot.ROOT / 'analysis/ghidra' /
                             ('pc-auto-slot-v1' if a in (0x1a5de8, 0x1a89e0) else 'system-card-menus-59')
                             for a in entries},
                         reviewed_switches=tuple(entry for entry, _, _ in tables),
                         jump_tables=tuple((table, n) for _, table, n in tables))
    elf = (run / 'SLPM_664.52').read_bytes()
    for entry, table, count in tables:
        targets = struct.unpack_from(f'<{count}I', elf, table - 0xff000)
        code = next((run / 'generated').glob(f'*_0x{entry:x}.cpp')).read_bytes()
        switch = code.split(b'switch (jumpTarget)', 1)[1].split(b'default:', 1)[0]
        cases = {int(pc, 16) for pc in re.findall(rb'case 0x([0-9a-f]+)u:', switch, re.I)}
        if cases != set(targets):
            raise ValueError(f'Original state destinations differ for {entry:x}')
    export(run, entries, 'system_card', 'generate_system_card_recomp.py')
    (pilot.ROOT / 'port/core/system_card_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries), encoding='ascii')
