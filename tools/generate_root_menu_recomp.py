"""Recompile the retail root menu's action table, navigation, and list entry points."""
from generate_sound_recomp import export, pilot

entries = (0x175f78, 0x19d810, 0x1a1c60, 0x1a1d70, 0x1a1e00, 0x1a1eb0,
           0x1a1ec8, 0x1ab468, 0x1af818)

if __name__ == '__main__':
    iso = pilot.ROOT / 'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run = pilot.generate(iso, pilot.EVAL / 'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                         entries=entries, work=pilot.ROOT / 'local/pc-core/ps2recomp-root-menu',
                         jump_tables=((0x230348, 8),))
    export(run, entries, 'root_menu', 'generate_root_menu_recomp.py')
    (pilot.ROOT / 'port/core/root_menu_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries), encoding='ascii')
