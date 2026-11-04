"""Translate the original single-precision visual sine/tangent library."""
from generate_sound_recomp import export,pilot
entries=(0x1f4d40,0x1f3cb0,0x1f4620,0x1f4718,0x1f29d8,0x1f0838,0x1f08f0)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-visual-trig",allow_padding=True,
                       callback_export=pilot.ROOT/"analysis/ghidra/visual-trig-v1")
    export(run,entries,"visual_trig","generate_visual_trig_recomp.py")
