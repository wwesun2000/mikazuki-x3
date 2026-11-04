"""Recompile the original ending and chapter lists, movement, selection and replay."""
from generate_sound_recomp import export, pilot

entries=(0x15f528,0x1ab490,0x1ab578,0x1ab5e8,0x1aba00,0x1aba60,0x1abab0,0x1abb00,0x1abb48,
         0x1af838,0x1af850)

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-ending-menu')
    export(run,entries,'ending_menu','generate_ending_menu_recomp.py')
    (pilot.ROOT/'port/core/ending_menu_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries),encoding='ascii')
