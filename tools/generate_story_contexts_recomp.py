"""Compile nontrivial remaining methods of the 26 retail ScenarioLink contexts."""
import re
import struct
from generate_sound_recomp import export,pilot
from vm_handlers import Image

methods=(0x11e9e0,0x11eba8,0x11eda8,0x11efb0,0x11f118,0x11f290,0x11f440,0x11f5b8,0x11f800,
         0x11fa48,0x11fd10,0x11fe80,0x120030,0x120900,0x120b28,0x120c88,0x121160,0x1212d8,
         0x121550,0x1216c8)
dependencies=(0x112d80,0x113410,0x114bb0,0x1154e0,0x115548,0x1156d8,0x1157c0,0x115918,0x115998,
              0x1159c0,0x1159f8,0x115a08,0x115a48,0x1165a8,0x116d00,0x117090,0x1170f0,0x117200,
              0x1173a0,0x117b68,0x117c38,0x118f48,0x118f90,0x1195a8,0x1195b0,0x1196b0,0x119a10,
              0x11a868,0x1225e0,0x135c30,0x135c60,0x141538,0x141548,0x141550,0x141db8,0x141dc0,
              0x14d2d8,0x14d498,0x14d4b8,0x14d538,0x1601e0,0x16c8c8,0x16cce0,0x16ccf8,
              0x11f098,0x11f530,0x11f9c0,0x11f3c0,0x11f210,
              0x179c48,0x179c50,0x179c58,0x179c60,0x179c68,0x179c70)

if __name__=="__main__":
    core=pilot.ROOT/"port/core"
    image=Image((pilot.ROOT/"local/extracted/SLPM_664.52").read_bytes())
    getters=[int(a,16) for a in re.findall(r"\{0x([\da-f]{8}),0x00235f..,0x[\da-f]{8},0x[\da-f]{8}\}",(core/"manager_handler_bindings.hpp").read_text())]
    allocators={}
    constructors=[]
    for getter in getters:
        pc=getter+0x18
        if image.word(pc)!=(0x0c000000|(0x10fad0>>2)) or image.word(pc+4) not in (0x24040004,0x24040008):
            raise ValueError(f"Unexpected singleton allocation at {pc:x}")
        allocators[pc]=image.word(pc+4)&0xffff
        if image.word(pc+12)>>26!=3:raise ValueError("Expected original constructor call")
        constructors.append((image.word(pc+12)&0x03ffffff)<<2)
    other=set()
    for p in core.glob("*_entries.hpp"):
        if p.name!="story_contexts_entries.hpp":
            other.update(int(a,16) for a in re.findall(r"KX3_MENU_ENTRY\(0x([\da-f]+),",p.read_text()))
    entries=tuple(dict.fromkeys(methods+dependencies+tuple(a for a in getters+constructors if a not in other)))
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-story-contexts",
                       callback_export=pilot.ROOT/"analysis/ghidra/story-context-transfers-v1",
                       reviewed_switches=(0x11fa48,0x1195b0,0x115548,0x1157c0))
    core=pilot.ROOT/"port/core"
    vtables=re.findall(r"\{0x[\da-f]{8},0x00235f..,0x([\da-f]{8}),0x[\da-f]{8}\}",(core/"manager_handler_bindings.hpp").read_text())
    elf=(run/"SLPM_664.52").read_bytes()
    slots=[struct.unpack_from("<4I",elf,int(table,16)-0xff000) for table in vtables]
    if len(slots)!=26 or not set(methods)<=set(x for group in slots for x in group):
        raise ValueError("Context entry is absent from the retail vtables")
    export(run,entries,"story_contexts","generate_story_contexts_recomp.py")
    (core/"context_allocations.hpp").write_text("".join(
        f"KX3_CONTEXT_ALLOCATION(0x{pc:x},{size})\n" for pc,size in sorted(allocators.items())),encoding="ascii")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (core/"story_contexts_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in entries),encoding="ascii")
