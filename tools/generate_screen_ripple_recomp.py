"""Translate the original horizontal ripple and shared strip constructor."""
from generate_sound_recomp import export,pilot
entries=(0x181a20,0x1819d0,0x181bc8,0x181d98,0x181f78)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-screen-ripple",
                       # Reuse the byte-checked replacement-export mechanism for
                       # the wrapper whose old Ghidra body included its tail callee.
                       reviewed_switches=(0x1819d0,0x181d98),
                       callback_export=pilot.ROOT/"analysis/ghidra/remaining-cue-effects-v3")
    export(run,entries,"screen_ripple","generate_screen_ripple_recomp.py")
