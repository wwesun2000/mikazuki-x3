"""Compile the original answer-record reader, editor vtables and keyboard navigation."""
import re
from generate_sound_recomp import export,pilot
from vm_handlers import Image

entries=(0x12ebf8,0x11a718,0x11a890,0x11aa60,0x11ac10,0x11ad50,0x11ad88,0x11af18,
         0x11b100,0x11b1b0,0x11b238,0x11b338,0x11b358,0x11b378,0x11b3c0,0x11b3d8,0x11b420,
         0x11b450,0x11b4b0,0x11b4e8,0x11b588,0x11bde0,0x11bdf8,0x11cb10,0x11d500,0x11d790,0x11d4c0,0x11c800,0x11c960,
         0x11caa0,0x11d2e0,0x11ce58,0x111870,0x115f88,0x115e58,0x179b58,0x179c40,0x179c80,
         0x184d18,0x184e58,0x184ea0,0x184f58,0x184fd8,0x184fe8,0x185990,0x185b68,0x10b278,
         0x11c7c0,0x11a990,0x11cbc0,0x11d078,0x11d5b0,0x11d840,0x11d018,0x11a8f0,
         0x160148,0x16a830,0x168968,0x169c38,0x17a8b0,0x17a6e8,0x184e68,0x184eb0,0x184ef8,0x185aa8,0x185b58)

if __name__=="__main__":
    core=pilot.ROOT/"port/core"
    image=Image((pilot.ROOT/"local/extracted/SLPM_664.52").read_bytes())
    methods={image.word(table+4*n) for table in (0x2236d0,0x2236f8,0x223720,0x223748) for n in range(7)}
    registered=set()
    for path in core.glob("*_entries.hpp"):
        if path.name!="answer_input_entries.hpp":
            registered.update(int(a,16) for a in re.findall(r"KX3_MENU_ENTRY\(0x([0-9a-f]+),",path.read_text()))
    selected=tuple(sorted((set(entries)|methods)-registered))
    switches=(0x11d2e0,0x11ce58,0x179b58)
    proof={a:pilot.ROOT/"analysis/ghidra/answer-methods-v1" for a in methods}
    proof.update({a:pilot.ROOT/"analysis/ghidra/answer-input-v1" for a in switches})
    proof[0x12ebf8]=pilot.ROOT/"analysis/ghidra/vm-dependencies-v1"
    proof.update({a:pilot.ROOT/"analysis/ghidra/pc-name-vtable-v1" for a in (0x11bde0,0x11bdf8)})
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=selected,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-answer-input",
                       callback_export=proof,reviewed_switches=switches+(0x12ebf8,0x11d668,0x11d8f8),
                       allow_padding=True,shared_returns={0x168968:0x169c38},
                       jump_tables=[(t,8) for t in (0x22a5b8,0x22a5d8,0x22a5f8,0x22a618)]+[(0x22eba8,5)])
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")) for a in selected}
    for fn,pc,table,count in [(0x11d2e0,0x11d310,0x22a5b8,8),(0x11d2e0,0x11d388,0x22a5d8,8),
                              (0x11d2e0,0x11d3f0,0x22a5f8,8),(0x11d2e0,0x11d448,0x22a618,8),
                              (0x179b58,0x179b78,0x22eba8,5)]:
        targets={image.word(table+4*n) for n in range(count)}
        site=names[fn].read_text().split(f"// 0x{pc:x}:",1)[1].split("dispatchGuestBranch",1)[0]
        emitted={int(a,16) for a in re.findall(r"case 0x([0-9a-f]+)u: goto label_",site,re.I)}
        if emitted!=targets:raise ValueError(f"Wrong in-function targets at original JR {pc:x}: {emitted} vs {targets}")
    export(run,selected,"answer_input","generate_answer_input_recomp.py")
    (core/"answer_input_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a].stem})\n" for a in selected),encoding="ascii")
