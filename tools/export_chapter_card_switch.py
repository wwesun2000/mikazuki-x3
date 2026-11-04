"""Recover the complete post-scenario card dispatcher for the next device binding."""
import hashlib
import json
import re
import struct

from generate_expandband_recomp import INSTRUCTION
import run_ps2recomp_pilot as pilot

if __name__=='__main__':
    entry=0x1a7c88
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    proof=pilot.ROOT/'analysis/ghidra/chapter-card-states-v1'
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=(entry,),work=pilot.ROOT/'local/pc-core/ps2recomp-chapter-card',
                       callback_export=proof,reviewed_switches=(entry,))
    elf=(run/'SLPM_664.52').read_bytes()
    item=json.loads((run/'generated.json').read_bytes())['functions'][hex(entry)]
    source=(run/item['source']).read_bytes()
    words={int(pc,16):int(word,16) for pc,word in INSTRUCTION.findall(source)}
    end=int(item['end_exclusive'],16)
    for pc in range(entry,end,4):
        if words.get(pc,0)!=struct.unpack_from('<I',elf,pc-0xff000)[0]:
            raise ValueError(f'Original word missing or altered at {pc:x}')
    table=elf[0x230d50-0xff000:0x230d50-0xff000+200]
    states=struct.unpack('<50I',table)
    switch=source.split(b'switch (jumpTarget)',1)[1].split(b'default:',1)[0]
    cases={int(v,16) for v in re.findall(rb'case 0x([0-9a-f]+)u:',switch,re.I)}
    if cases!=set(states):
        raise ValueError(f'Generated switch differs from the retail table: {cases^set(states)}')
    dest=pilot.ROOT/'analysis/ps2recomp-chapter-card'
    dest.mkdir(exist_ok=True)
    pilot.record(dest/'manifest.json',dict(entry=hex(entry),elf_sha256=pilot.ELF_SHA,
        ghidra_export=str(proof.relative_to(pilot.ROOT)),generated=str((run/item['source']).relative_to(pilot.ROOT)),
        generated_sha256=hashlib.sha256(source).hexdigest(),original_words=(end-entry)//4,
        table_sha256=hashlib.sha256(table).hexdigest(),states=[hex(x) for x in states],
        distinct_destinations=len(cases),scope='Original jump-table and instruction coverage. Device and input services not yet linked into the player.'))
