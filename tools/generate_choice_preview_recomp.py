"""Recover the retail option preview, range finalization and context return bodies."""
from generate_sound_recomp import export, pilot

# The original 125778/1186E8 setup and 11E748 navigation already belong to
# readback_handlers and scenario_input. These functions run between them.
entries = (0x131930,0x132070,0x125f90,0x125f38,0x11a390,
           0x1189f8,0x118628,0x118338,0x118568,0x117568,0x117b60,0x117d08,0x117d10,
           0x16a9d8,0x16a400,0x16a410,0x16ac38,0x16ac78,0x16a7e8,0x16bc58,
           0x16b750,0x16b768,0x168990,
           0x11e508,0x11ea00,0x11ea30,0x204898,0x1261e0,0x12ad30,0x122c38,0x12f750)

if __name__ == '__main__':
    run=pilot.generate(pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso',
                       pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',entries=entries,
                       work=pilot.ROOT/'local/pc-core/ps2recomp-choice-preview',
                       shared_returns={0x117568:0x117b60,0x16a9d8:0x16a400})
    export(run,entries,'choice_preview','generate_choice_preview_recomp.py')
    names={a:next((run/'generated').glob(f'*_0x{a:x}.cpp')).stem for a in entries}
    (pilot.ROOT/'port/core/choice_preview_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},{names[a]})\n' for a in entries),encoding='ascii')
