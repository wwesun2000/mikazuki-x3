"""Translate the original field feedback factory/update/draw/cleanup."""
from generate_sound_recomp import export,pilot
entries=(0x17e570,0x17e698,0x17e728,0x17ea98)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-field-feedback",
                       callback_export=pilot.ROOT/"analysis/ghidra/cue-field-v1")
    export(run,entries,"field_feedback","generate_field_feedback_recomp.py")
