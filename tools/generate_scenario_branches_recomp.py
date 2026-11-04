"""Build the seven retail branch/variable opcodes and their shared table operations."""
from generate_sound_recomp import export, pilot
import re
import struct

entries = (0x100d78,0x100dd0,0x100e38,0x100e78,0x100ee0,0x100f18,0x100fd8,
           0x11a210,0x11a220,0x124d48,0x124e38,0x124f00,0x1253e8,0x12c0c0,0x12c1c8,
           0x12c1f8,0x12c318,0x12c330,0x12c428,0x12c5a8,0x12c5d8,0x12c6f8,0x12c710)

if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-scenario-branches",
                       callback_export=pilot.ROOT/"analysis/ghidra/scenario-branch-tables-v1",
                       reviewed_switches=(0x100f18,0x100fd8))
    symbols={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    elf=(run/"SLPM_664.52").read_bytes()
    for entry,table in [(0x100f18,0x227f80),(0x100fd8,0x227fc0)]:
        src=(run/"generated"/(symbols[entry]+".cpp")).read_bytes()
        switch=src.split(b"switch (jumpTarget)",1)[1].split(b"default:",1)[0]
        actual={int(v,16) for v in re.findall(rb"case 0x([0-9a-f]+)u:",switch,re.I)}
        if actual!=set(struct.unpack_from("<16I",elf,table-0xff000)):
            raise ValueError("Generated switch differs from original table")
    export(run,entries,"scenario_branches","generate_scenario_branches_recomp.py")
    (pilot.ROOT/"port/core/scenario_branches_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{symbols[a]})\n" for a in entries),encoding="ascii")
