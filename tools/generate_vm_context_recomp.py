"""Recompile frequently used ScenarioLink methods still missing in the three active context slots."""
import json
from generate_sound_recomp import export, pilot

if __name__=="__main__":
    data=json.loads((pilot.ROOT/"tools/ghidra/vm-context-batch.json").read_bytes())
    # 125F60 is a separate JR RA / zero-return entry in another Ghidra body.
    entries=tuple(int(a["address"],16) for a in data["anchors"] if a["address"]!="00125f60")
    if len(set(entries))!=len(entries):raise ValueError("Duplicate VM entry")
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-vm-context",
                       callback_export=pilot.ROOT/"analysis/ghidra/vm-context-batch-v1",
                       reviewed_switches=(0x112068,))
    export(run,entries,"vm_context","generate_vm_context_recomp.py")
    symbols={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (pilot.ROOT/"port/core/vm_context_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{symbols[a]})\n" for a in entries),encoding="ascii")
    (pilot.ROOT/"port/core/vm_context_handlers.hpp").write_text(
        "".join(f"KX3_VM_ENTRY(0x{a['address']})\n" for a in data["anchors"] if a["role"].startswith("Used ")),
        encoding="ascii")
