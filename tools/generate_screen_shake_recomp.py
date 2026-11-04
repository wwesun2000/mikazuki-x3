"""Translate the original random camera shake and its float RNG adapters."""
from generate_sound_recomp import export,pilot

entries=(0x181f90,0x182078,0x182188,0x1822f0,0x17a8b0,0x17a9c8)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-screen-shake",
                       callback_export=pilot.ROOT/"analysis/ghidra/cue-motion-v3")
    export(run,entries,"screen_shake","generate_screen_shake_recomp.py")
