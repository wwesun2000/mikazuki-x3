"""Translate original two-pass ScenePack cue 27, preserving source instructions."""
from generate_sound_recomp import export, pilot

entries = (0x17f670, 0x17f7f0, 0x17f878, 0x17f900, 0x17fe70, 0x17fe98)
if __name__ == '__main__':
    run = pilot.generate(
        pilot.ROOT / 'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso',
        pilot.EVAL / 'ee-pilot/build/ps2xRecomp/ps2_recomp.exe', entries=entries,
        work=pilot.ROOT / 'local/pc-core/ps2recomp-captured-blur',
        callback_export=pilot.ROOT / 'analysis/ghidra/remaining-cue-dependencies-v1')
    export(run, entries, 'captured_blur', 'generate_captured_blur_recomp.py')
