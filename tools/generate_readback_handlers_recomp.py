"""Link the opcode handlers actually selected by the three original readback tables."""
import json
import re
from generate_sound_recomp import export,pilot
from vm_handlers import Image

dependencies=(0x113448,0x115ce8,0x118200,0x1186e8,0x11a2a0,0x12f680,0x133930,0x133a40,0x168380,
              0x168388,0x168390,0x1686d0,0x16a430,0x16a490,0x16a4a0,0x16a570,0x16a640,0x16a650,
              0x16a668,0x16a680,0x16a698,0x16a740,0x16a758,0x16a788,0x16a860,0x16ab60,0x16af30,
              0x16bbe0,0x17d380,0x11e958,0x11e8b8,0x1375d8,0x137568,0x1373b8,
              0x146768,0x1467b8,0x1378b0,0x136a50,0x137b98,0x137ca8,0x137aa8,0x137a00,
              0x136630,0x1366a8,0x136718,0x136778,0x1fd750,0x135660,0x13ea88,0x13d048,
              0x137988,0x144a08,0x1437a0,0x144940,0x144a88,0x138d28,0x138d70,
              0x10c760,0x114598,0x113d08,0x13d080,0x143780,0x113488,0x1134c0,
              0x119de8,0x115bd8,0x19d7f0,0x1165b0,0x121aa8,0x121e50,0x122220,
              0x135738,0x135760,0x135770,0x137308,0x13f040,0x13f048,0x13f180,
              0x1125c8,0x1b1fd0) # Time-chart label restore and readback sound class.

if __name__=="__main__":
    core=pilot.ROOT/"port/core"
    im=Image((pilot.ROOT/"local/extracted/SLPM_664.52").read_bytes())
    data=json.loads((pilot.ROOT/"analysis/vm_handlers.json").read_bytes())
    classes={c["id"]:c for c in data["handler_classes"]}
    ops={op["opcode"]:op for op in data["opcode_entries"]}
    installed={0x133f60}
    for path in core.glob("*_entries.hpp"):
        if path.name!="readback_handlers_entries.hpp":
            installed.update(int(s,16) for s in re.findall(r"KX3_MENU_ENTRY\(0x([\da-f]+),",path.read_text()))
    for name in ("context_bridges.hpp","literal_returns.hpp"):
        installed.update(int(s,16) for s in re.findall(r"\{0x([\da-f]+),",(core/name).read_text()))
    installed.update(int(s,16) for s in re.findall(r"0x([\da-f]+)",(core/"zero_bindings.hpp").read_text()))
    tails={int(a,16):int(b,16) for a,b in re.findall(r"\{0x([\da-f]+),0x([\da-f]+),",(core/"tail_bindings.hpp").read_text())}
    selected=set(dependencies)
    mappings=[]
    for table,count,offset in [(0x205e20,40,0x20),(0x205ec0,41,0x24),(0x205f68,41,0x28)]:
        for i in range(count):
            op=im.word(table+4*i)
            handler=ops[op]
            if handler["class_id"] is None:
                if op!=0x26 or im.word(0x229784+4*op)!=0x110508:raise ValueError("Unknown null handler")
                mappings.append(dict(table=hex(table),op=hex(op),entry=None));continue
            field=int(classes[handler["class_id"]]["vtable_address"],16)+offset
            entry=im.word(field);target=entry
            while target in tails:target=tails[target]
            mappings.append(dict(table=hex(table),op=hex(op),vtable_word=hex(field),entry=hex(entry),target=hex(target)))
            if target not in installed:selected.add(target)
    auxiliary=[]
    for table in (0x225d48,0x225c48,0x225dc8,0x225cc8,0x225e48):
        for slot in range(25):
            at=table+4*slot;entry=im.word(at);target=entry
            while target in tails:target=tails[target]
            if target not in installed:selected.add(target)
            auxiliary.append(dict(vtable_word=hex(at),slot=slot,entry=hex(entry),target=hex(target)))
    entries=tuple(sorted(selected-installed))
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-readback-handlers",
                       reviewed_switches=(0x1375d8,),allow_padding=True,
                       callback_export={0x1686d0:pilot.ROOT/"analysis/ghidra/readback-font-setter-v1",
                                        0x1375d8:pilot.ROOT/"analysis/ghidra/answer-input-v1",
                                        0x122220:pilot.ROOT/"analysis/ghidra/menu-entry-conditions-v1"})
    export(run,entries,"readback_handlers","generate_readback_handlers_recomp.py")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (core/"readback_handlers_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in entries),encoding="ascii")
    pilot.record(pilot.ROOT/"analysis/ps2recomp-readback_handlers/source-tables.json",
                 dict(elf_sha256=pilot.ELF_SHA,slots=mappings,auxiliary_slots=auxiliary))
