"""Export the already recompiled original crash-wipe functions, checking every ELF word.

This reuses the existing PS2Recomp run. It neither reimports Ghidra nor runs a
new recompiler. The exported header is not linked until its native interfaces
have passed the original EE comparison.
"""
import argparse
from pathlib import Path
from generate_sound_recomp import export, pilot

ENTRIES = (0x1904d0, 0x190d98, 0x190ed8, 0x191168, 0x1912d8, 0x191418)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="Existing ps2recomp-screen-wipes run")
    args = parser.parse_args()
    run = args.run.resolve()
    expected = (pilot.ROOT / "local/pc-core/ps2recomp-screen-wipes").resolve()
    if run.parent != expected or not (run / "functions.csv").is_file():
        raise ValueError("Select one existing project-owned screen-wipes run")
    export(run, ENTRIES, "screen_mesh", "generate_screen_mesh_recomp.py", link_header=False)
    print(run / "screen_mesh_generated.hpp")

if __name__ == "__main__":
    main()
