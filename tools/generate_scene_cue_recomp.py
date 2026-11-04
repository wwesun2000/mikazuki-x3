"""Build the original ScenePack command interpreter and its native device producers."""
import json
from generate_sound_recomp import export, pilot

if __name__ == "__main__":
    plan = json.loads((pilot.ROOT/"tools/ghidra/scene-cue-module.json").read_bytes())
    # The shared card/return module already links the original string initializer.
    entries = tuple(int(a["address"],16) for a in plan["anchors"] if a["address"] != "001b0068")
    run = pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                         pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe", entries=entries,
                         work=pilot.ROOT/"local/pc-core/ps2recomp-scene-cue",
                         callback_export=pilot.ROOT/"analysis/ghidra/scene-cue-module-v4",
                         reviewed_switches=(0x1397d8,))
    export(run, entries, "scene_cue", "generate_scene_cue_recomp.py")
    table = []
    for entry in entries:
        name = next((run/"generated").glob(f"*_0x{entry:x}.cpp")).stem
        table.append(f"KX3_MENU_ENTRY(0x{entry:x},{name})\n")
    (pilot.ROOT/"port/core/scene_cue_entries.hpp").write_text("".join(table),encoding="ascii")
