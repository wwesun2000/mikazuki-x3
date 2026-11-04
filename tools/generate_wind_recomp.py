"""Recover the retail wind transition and the update callback it installs on expiry."""
from generate_sound_recomp import export,pilot

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    entries=(0x18ef38,0x18f108,0x18f230,0x18f370,0x18f3e8,0x18f4d0,0x18f718)
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-wind',
                       callback_export=pilot.ROOT/'analysis/ghidra/wind-71-all',allow_padding=True)
    export(run,entries,'wind','generate_wind_recomp.py')
