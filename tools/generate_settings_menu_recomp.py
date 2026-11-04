"""Recompile original settings entry, input, apply, and sound/pad preference accessors."""
from generate_sound_recomp import export, pilot

entries=(0x106050,0x15de60,0x15dec0,0x15ded0,0x15df98,0x15dfc8,0x15dfe8,
         0x1a2520,0x1a2608,0x1a26a8,0x1a2738,0x1a2a18)

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-settings-menu',allow_padding=True)
    export(run,entries,'settings_menu','generate_settings_menu_recomp.py')
    (pilot.ROOT/'port/core/settings_menu_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries),encoding='ascii')
