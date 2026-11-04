"""Recompile the retail expand-blur factories, rectangle history, draw and retirement."""
from generate_sound_recomp import export, pilot

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    entries=(0x182a08,0x182aa0,0x182ac8,0x182cd8,0x182d58,0x182e90,0x182f70,0x183088,0x183240)
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-expandblur')
    export(run,entries,'expandblur','generate_expandblur_recomp.py')
