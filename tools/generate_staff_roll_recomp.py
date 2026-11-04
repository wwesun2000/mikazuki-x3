"""Recover the staff-roll module from the mounted ELF for native integration."""
import json
import os
import struct
from generate_sound_recomp import export, pilot


if __name__ == "__main__":
    anchors = json.loads((pilot.ROOT / "tools/ghidra/staff-roll-module.json").read_bytes())
    entries = tuple(int(row["address"], 16) for row in anchors["anchors"])
    iso = pilot.ROOT / "Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso"
    # Four unreachable zero words split the parser body in the Ghidra database.
    # The generator requires each such gap to be exactly one zero instruction.
    run = pilot.generate(
        iso, pilot.EVAL / "ee-pilot/build/ps2xRecomp/ps2_recomp.exe", entries=entries,
        work=pilot.ROOT / "local/pc-core/ps2recomp-staff-roll",
        callback_export=pilot.ROOT / "analysis/ghidra/staff-roll-module-v3",
        reviewed_switches=(0x14d8c0,0x141f10))
    export(run, entries, "staff_roll", "generate_staff_roll_recomp.py")
    (pilot.ROOT/"port/core/staff_roll_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n" for a in entries),encoding="ascii")
    generated = run / "generated"
    unit = run / "staff_roll_module.cpp"
    sources = [next(generated.glob(f"*_0x{address:x}.cpp")) for address in entries]
    unit.write_text("".join(f'#include "generated/{s.name}"\n' for s in sources), encoding="ascii")
    obj = run / "staff_roll_module.obj"
    zig = pilot.EVAL / "toolchain/zig-x86_64-windows-0.15.2/zig.exe"
    args = [zig, "c++", "-std=c++20", "-target", "x86_64-windows-gnu", "-msse4.1",
            "-fno-fast-math", "-ffp-contract=off", "-c", unit, "-o", obj]
    for include in (pilot.UPSTREAM / "ps2xRuntime/include", pilot.UPSTREAM / "ps2xIOP/include",
                    pilot.UPSTREAM / "ps2xRuntime/src/lib/Kernel", generated):
        args.extend(["-I", include])
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(pilot.EVAL / "zig-global-cache"),
               ZIG_LOCAL_CACHE_DIR=str(pilot.EVAL / "ee-pilot/zig-local-cache"))
    pilot.call(args, run / "compile.log", run, env)
    if struct.unpack_from("<H", obj.read_bytes())[0] != 0x8664:
        raise ValueError("Expected x86-64 COFF machine type")
    report = {"functions": len(entries), "iso_elf_sha256": pilot.ELF_SHA,
              "compiler_sha256": pilot.sha(zig), "object_sha256": pilot.sha(obj),
              "source_directory": run.relative_to(pilot.ROOT).as_posix(),
              "status": "compiled-x86_64-object"}
    out = pilot.ROOT / "analysis/ps2recomp-staff_roll/native-object.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
