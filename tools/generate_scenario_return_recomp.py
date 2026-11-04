"""Recompile the VM's return to the active script header label."""
from generate_sound_recomp import export, pilot

if __name__=='__main__':
    entries=(0x114b28,0x1218f8,0x122070,0x10d260,0x133f60)
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-scenario-return')
    export(run,entries,'scenario_return','generate_scenario_return_recomp.py')
