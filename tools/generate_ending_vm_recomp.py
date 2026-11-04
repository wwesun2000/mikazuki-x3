"""Recompile the ScenarioLink 27/28 handlers and their original ending-table calls."""
from generate_sound_recomp import export, pilot

entries=(0x12c808,0x11a090,0x19c9e8,0x19ca48,0x10c7e0,0x19c4c0,0x19c538,0x1ab4a8,0x1132d8)

if __name__=="__main__":
    iso=pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso"
    run=pilot.generate(iso,pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",
                       entries=entries,work=pilot.ROOT/"local/pc-core/ps2recomp-ending-vm")
    export(run,entries,"ending_vm","generate_ending_vm_recomp.py")
    (pilot.ROOT/"port/core/ending_vm_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n" for a in entries),encoding="ascii")
