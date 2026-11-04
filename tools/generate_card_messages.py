"""Compile original chapter-card draw descriptor addresses, leaving textures in the ISO."""
import json
from pathlib import Path
from vm_handlers import ROOT, Image


def main():
    source=json.loads((ROOT/"analysis/ghidra/chapter-card-message-v1/messages.json").read_bytes())
    elf=Image((ROOT/"local/extracted/SLPM_664.52").read_bytes())
    assert source["elf_sha256"]==elf.sha256 and source["entry"]==0x1a3280
    draws=[]
    starts=[0]
    for i,row in enumerate(source["cases"]):
        assert i==row["message"] and 0<row["instructions"]<8000
        for command in row["draws"]:
            addr=command["descriptor"]
            assert command["draw"] in (0x19e308,0x19e638)
            assert 0x200000<=addr<0x230000
            draws.append(f"    {{0x{addr:x},{str(command['draw']==0x19e638).lower()}}},\n")
        starts.append(len(draws))
    assert len(starts)==41
    header=("// From 1A3280 on the original ELF, observed by ObserveCardMessages.java.\n#pragma once\n"
            "namespace kx3::platform::chapter_card {\nstruct Draw {unsigned descriptor;bool textured;};\n"
            "inline constexpr unsigned starts[]={"+",".join(map(str,starts))+"};\n"
            "inline constexpr Draw draws[]={\n"+"".join(draws)+"};\n}\n")
    (ROOT/"port/platform/chapter_card_messages.hpp").write_text(header,encoding="ascii")


if __name__=="__main__":main()
