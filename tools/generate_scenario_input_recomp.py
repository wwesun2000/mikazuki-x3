"""Build the original input, readback, choice navigation and confirmation methods."""
import re
from generate_sound_recomp import export,pilot

entries=(0x112f78,0x112d40,0x116118,0x1173a8,0x121760,0x117840,0x117ad0,0x117e08,0x117e18,
         0x11e748,0x11e608,0x11e4e8,0x118bf8,0x118288,0x118d68,0x118250,0x117d28,0x117d40,
         0x117d60,0x117db8,0x117e30,0x117ee8,0x117f68,0x118010,0x118138,0x118150,0x118308,
         0x118e28,0x118e30,0x115d50,0x115e48,0x113430,0x17d3b8,0x179c40,0x179c80,0x119e70,
         0x19caa8,0x19cad8,0x11a3c8,0x1165d8,0x16cc50,0x16c898,0x16b780,0x16b798,
         0x16b870,0x16b888,0x16b8e0,0x16b8f8,0x1689a8,0x168ac8,0x168bc8,0x168c60,0x169cc0,0x16ba10,
         0x1600f8,0x141da8,0x15fec8,0x15fe30,0x15fde0,0x11a380,0x113328,0x118e20,0x1162d8,
         0x122620,0x1225b0,0x16cb10,0x16cb28,0x16cbe0,0x16cbc8,0x16cc38,0x16cc78,0x186050,
         0x101190,0x10eaa8,0x1126d8,0x1136f8,0x113778,0x116298,0x116840,0x1169c0,0x116a98,0x116e10,
         0x117a90,0x118088,0x1225d8,0x16c790,0x16c978,0x175e70,0x19cca8,0x15f040,0x15f168,0x10ead0,
         0x10dc80,0x10dfd8,0x116e78,0x10dde0,0x10e150,0x116908,0x10dbd8,0x19ce18,0x15f9e0,
         0x19c6b8,0x15ece0,0x101230,0x17aa90,0x17aad8,0x116b08,0x117ab0,0x1012d0,0x113738,0x1137b8,
         0x186020,0x19cd58,0x19cde8,0x11e6c8,0x11eb28,0x11f778,
         0x169d68,0x169d98,0x169db8,0x169df0,0x169cb8,0x169c40,
         0x11a470,0x11dba0) # Armed 7C confirmation and the provider's original phase reset.

if __name__=="__main__":
    core=pilot.ROOT/"port/core"
    installed=set()
    for p in core.glob("*_entries.hpp"):
        if p.name!="scenario_input_entries.hpp":
            installed.update(int(x,16) for x in re.findall(r"KX3_MENU_ENTRY\(0x([0-9a-f]+),",p.read_text()))
    new=tuple(a for a in entries if a not in installed)
    proof=pilot.ROOT/"analysis/ghidra"
    reviewed={a:proof/"choice-effects-v1" for a in (0x1173a8,0x1165d8)}
    reviewed.update({a:proof/"choice-presentation-v1" for a in (0x1689a8,0x168ac8,0x168bc8)})
    reviewed[0x10e150]=proof/"scriptdata-all-v1"
    exports={**reviewed,0x169d98:proof/"choice-iterator-vtable-v1"}
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=new,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-scenario-input",
                       callback_export=exports,reviewed_switches=tuple(reviewed))
    export(run,new,"scenario_input","generate_scenario_input_recomp.py")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in new}
    (core/"scenario_input_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in new),encoding="ascii")
