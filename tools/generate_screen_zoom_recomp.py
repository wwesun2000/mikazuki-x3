"""Translate the two original ScenePack viewport/texture zoom effects."""
from generate_sound_recomp import export,pilot

entries=(0x182308,0x1824c8,0x1825b8,0x1826a0,0x1826b8,0x182870,0x182908,0x1829f0)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-screen-zoom",
                       callback_export=pilot.ROOT/"analysis/ghidra/cue-zoom-v2")
    export(run,entries,"screen_zoom","generate_screen_zoom_recomp.py")
