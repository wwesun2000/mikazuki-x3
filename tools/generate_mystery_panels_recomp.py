"""Recompile resident culprit/memory panel callbacks and sprite builders from the retail ELF."""
import json
from generate_sound_recomp import export, pilot

if __name__ == "__main__":
    plan=json.loads((pilot.ROOT/"tools/ghidra/mystery-panels.json").read_bytes())
    # The GS builders and the scene-level setter already run through the
    # linked staff and memory-card modules.
    shared={0x135cc0,0x135cf8,0x1363c8,0x136548,0x1358f8}
    # 145590 is the file service boundary. 147A48 tests the descriptor pointer.
    entries=tuple(a for r in plan["anchors"] if (a:=int(r["address"],16)) not in shared|{0x145590,0x147a48})
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-mystery-panels",
                       callback_export=pilot.ROOT/"analysis/ghidra/mystery-panels-v4",
                       reviewed_switches=(0x14a280,0x14be48))
    export(run,entries,"mystery_panels","generate_mystery_panels_recomp.py")
    table=[]
    for entry in entries:
        name=next((run/"generated").glob(f"*_0x{entry:x}.cpp")).stem
        table.append(f"KX3_MENU_ENTRY(0x{entry:x},{name})\n")
    (pilot.ROOT/"port/core/mystery_panels_entries.hpp").write_text("".join(table),encoding="ascii")
