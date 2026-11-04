"""Bind the original field-feedback effect and its three callbacks."""
import json
from pathlib import Path
from vm_handlers import Image,ROOT

image=Image((ROOT/"local/extracted/SLPM_664.52").read_bytes())
anchors=[]
for factory in (0x17e570,):
    anchors.append(dict(address=f"{factory:08x}",creation_candidate=True,role="Original cue 7 field-feedback factory"))
    for pc in range(factory,factory+128,4):
        word=image.word(pc)
        if word>>26!=3:
            continue
        destination=(word&0x3ffffff)*4
        if destination not in (0x179c40,0x179c48,0x179c58):
            continue
        delay=image.word(pc+4)
        if delay>>16 != 0x24a5:
            raise ValueError(f"Callback needs nonliteral recovery at {pc:x}")
        high_pc=next((a for a in range(pc-4,max(factory-4,pc-24),-4)
                   if image.word(a)>>16 == 0x3c05),None)
        if high_pc is None:
            raise ValueError(f"Missing callback LUI at {pc:x}")
        high=image.word(high_pc)
        low=((delay&0xffff)^0x8000)-0x8000
        target=((high&0xffff)<<16)+low
        anchors.append(dict(address=f"{target:08x}",creation_candidate=True,
                            role=f"Callback registered by {factory:08x}",
                            registration_pc=f"{pc:08x}",registration_callee=f"{destination:08x}",
                            lui_pc=f"{high_pc:08x}",lui_word=f"{high:08x}"))
out=ROOT/"tools/ghidra/cue-field-anchors.json"
out.write_text(json.dumps(dict(schema=1,elf_sha256=image.sha256,language_id="r5900:LE:32:default",
                               anchors=anchors),indent=2)+"\n")
print(len(anchors),"factory/callback anchors",str(out.relative_to(ROOT)))
