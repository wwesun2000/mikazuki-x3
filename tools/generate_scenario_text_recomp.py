"""Recompile retail page dispatch, the primary/ruby text pump and its font layout calls."""
import re
from generate_sound_recomp import export,pilot

entries=(0x113148,0x113818,0x113888,0x1162d0,0x111738,0x1126e0,0x113578,0x1135c8,0x1135e8,
         0x120308,0x120528,0x1203e0,0x120410,0x11ec30,
         0x12f3c0,0x12f308,0x12f598,0x12f6c0,0x12f1a8,0x12f6e8,0x12f2c8,0x12f8d8,0x1050b8,
         0x1165b8,0x119e08,0x119e18,0x16a6b0,0x16a6f0,0x16a718,0x16ab38,0x16adc8,0x16b200,0x16bab0,
         0x16af68,0x16afa8,0x16bf88,0x168318,0x168340,0x1684f0,0x169e60,0x16aa98,0x16a9f0,0x1683a0,0x1683c8,
         0x116218,0x116298)

if __name__=="__main__":
    core=pilot.ROOT/"port/core"
    installed=set()
    for p in core.glob("*_entries.hpp"):
        if p.name!="scenario_text_entries.hpp":
            installed.update(int(x,16) for x in re.findall(r"KX3_MENU_ENTRY\(0x([0-9a-f]+),",p.read_text()))
    new=tuple(a for a in entries if a not in installed)
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=new,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-scenario-text")
    export(run,new,"scenario_text","generate_scenario_text_recomp.py")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in new}
    (core/"scenario_text_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in new),encoding="ascii")
