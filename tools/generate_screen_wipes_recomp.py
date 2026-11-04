"""Recompile the original effect tables referenced by the six remaining literal screen commands."""
import json
import re
import struct
from generate_sound_recomp import export,pilot

if __name__=='__main__':
    root=pilot.ROOT
    anchors=json.loads((root/'analysis/native-core/screen-factories-83/anchors.json').read_bytes())
    assert anchors['elf_sha256']==pilot.ELF_SHA
    entries=tuple(int(row['address'],16) for row in anchors['anchors'])
    iso=root/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    tables=((0x18bc40,0x22f2f0),(0x18bef8,0x22f310))
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=root/'local/pc-core/ps2recomp-screen-wipes',
                       callback_export=root/'analysis/ghidra/screen-factories-83',allow_padding=True,
                       reviewed_switches=(0x18bef8,),jump_tables=tuple((table,8) for _,table in tables))
    elf=(run/'SLPM_664.52').read_bytes()
    for entry,table in tables:
        code=next((run/'generated').glob(f'*_0x{entry:x}.cpp')).read_bytes()
        switch=code.split(b'switch (jumpTarget)',1)[1].split(b'default:',1)[0]
        cases={int(a,16) for a in re.findall(rb'case 0x([0-9a-f]+)u:',switch,re.I)}
        assert cases==set(struct.unpack_from('<8I',elf,table-0xff000))
    # The polygonal command 119 has a separate projection and mesh pipeline.
    # Keep its generated C++ in this run until that interface is connected.
    active=tuple(entry for entry in entries if entry<0x1904d0)
    export(run,active,'screen_wipes','generate_screen_wipes_recomp.py')
    (root/'port/core/screen_wipe_entries.hpp').write_text(''.join(
        f'KX3_WIPE_ENTRY(0x{entry:x},FUN_{entry:08x}_0x{entry:x})\n' for entry in active),encoding='ascii')
