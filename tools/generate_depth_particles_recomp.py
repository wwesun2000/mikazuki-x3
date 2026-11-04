"""Translate the original depth-projected particle effect and brightness reads."""
from generate_sound_recomp import export,pilot
entries=(0x135858,0x1358a8,0x183968,0x183820,0x183b10,0x183d30,0x183f78,0x1840a0)
if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-depth-particles",allow_padding=True,
                       callback_export={a:pilot.ROOT/('analysis/ghidra/post-effect-v1' if a<0x180000 else
                                                     'analysis/ghidra/remaining-cue-dependencies-v1') for a in entries})
    export(run,entries,"depth_particles","generate_depth_particles_recomp.py")
