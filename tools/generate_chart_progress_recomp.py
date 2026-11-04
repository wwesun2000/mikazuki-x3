"""Build the retail chapter/time-chart label registrations and their callbacks."""
from generate_sound_recomp import export,pilot

# The epilogue, card and choice modules already own the four label helpers.
entries=(0x19c868,0x19c910,0x19cb50,
         0x1af188,0x1ac598,0x1fdf50)

if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-chart-progress",allow_padding=True)
    export(run,entries,"chart_progress","generate_chart_progress_recomp.py")
    symbols={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (pilot.ROOT/"port/core/chart_progress_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{symbols[a]})\n" for a in entries),encoding="ascii")
