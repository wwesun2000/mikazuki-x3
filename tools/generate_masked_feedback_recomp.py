"""Translate original focus-mask framebuffer feedback."""
from generate_sound_recomp import export,pilot
entries=(0x17f008,0x17f1a8,0x17f230,0x17f658)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-masked-feedback",
                       callback_export=pilot.ROOT/"analysis/ghidra/remaining-cue-effects-v3")
    export(run,entries,"masked_feedback","generate_masked_feedback_recomp.py")
