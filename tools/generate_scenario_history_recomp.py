"""Recompile ScenarioLink label lookup, history mutation and resource association."""
from generate_sound_recomp import export,pilot

entries=(0x10d868,0x10db48,0x10d830,0x10d700,0x10d738,0x10d740,0x10d748,0x10d780,0x10dae8,
         0x10e630,0x10e658,0x10e748,0x10e878,0x10eca0,0x10eea0,0x10eee8,0x10ef60,0x10f198,
         0x10f628,0x10f820,0x10f898,0x10fa48,0x10fa68,0x10fa88,0x113368,0x117560)

if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-scenario-history",
                       callback_export=pilot.ROOT/"analysis/ghidra/choice-transfer-v2",
                       reviewed_switches=(0x10d868,))
    export(run,entries,"scenario_history","generate_scenario_history_recomp.py")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (pilot.ROOT/"port/core/scenario_history_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in entries),encoding="ascii")
