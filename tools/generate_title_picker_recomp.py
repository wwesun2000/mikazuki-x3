"""Recover the retail new-game and continue work selectors and their focus/accept callbacks."""
from generate_sound_recomp import export, pilot

entries = (0x108d58, 0x1092e8, 0x1092f0, 0x10a000, 0x10a498, 0x10a4a0)
if __name__ == '__main__':
    iso = pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run = pilot.generate(iso, pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                         entries=entries, work=pilot.ROOT/'local/pc-core/ps2recomp-title-picker')
    export(run, entries, 'title_picker', 'generate_title_picker_recomp.py')
    (pilot.ROOT/'port/core/title_picker_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries), encoding='ascii')
