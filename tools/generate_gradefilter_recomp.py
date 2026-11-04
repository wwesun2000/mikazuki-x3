"""Regenerate effect_gradefilter.c from retail code and its registered EE callbacks."""
from generate_sound_recomp import export, pilot

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    entries=(0x179c50,0x179c60,0x1812a8,0x1814c0,0x181660,0x181858,0x1819b8)
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-gradefilter',
                       callback_export=pilot.ROOT/'analysis/ghidra/gradefilter-v1')
    export(run,entries,'gradefilter','generate_gradefilter_recomp.py')
