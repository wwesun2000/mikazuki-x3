"""Recompile both retail eight-direction slides and their registered callbacks."""
from generate_sound_recomp import export, pilot

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    entries=(0x18a710,0x18a890,0x18a9f0,0x18aac0,0x18aad8,0x18ad18,0x18aef8,0x18b028,
             0x18b040,0x18b290,0x18b408,0x18b580)
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-screen-slide',
                       callback_export={a:pilot.ROOT/('analysis/ghidra/screen-family-v1' if a<0x18aad8 else
                                                     'analysis/ghidra/screen111-module-v3') for a in entries},
                       jump_tables=((0x22f1cc,8),(0x22f204,8),(0x22f224,8)))
    export(run,entries,'screen_slide','generate_screen_slide_recomp.py')
