"""Recover the held-pad interval selector proven reachable at the cafe checkpoint."""
from generate_sound_recomp import export, pilot

entries=(0x115c18,0x116180,0x121998,0x1219e0,0x121f58,
         0x1222b0,0x1222f8,0x122310,0x122328,0x1224e8,
         0x15f120,0x15f3e0,0x15f4e8,0x16fba8,0x16fbc0,0x16fc00,0x175d98,
         0x1897b8,0x189870,0x189de8,0x19d6c8,0x19d6e0,0x135a98,0x17a090)

if __name__=='__main__':
    run=pilot.generate(pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso',
        pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',entries=entries,
        callback_export=pilot.ROOT/'analysis/ghidra/interval-modal-v2',
        work=pilot.ROOT/'local/pc-core/ps2recomp-interval-menu')
    export(run,entries,'interval_menu','generate_interval_menu_recomp.py')
    names={a:next((run/'generated').glob(f'*_0x{a:x}.cpp')).stem for a in entries}
    (pilot.ROOT/'port/core/interval_menu_entries.hpp').write_text(
        ''.join(f'KX3_MENU_ENTRY(0x{a:x},{names[a]})\n' for a in entries),encoding='ascii')
