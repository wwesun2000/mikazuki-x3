"""Generate the original name/answer keyboard layout and source singleton constructors."""
import hashlib
import json
import struct
from generate_timechart_source import ROOT,SHA,translate

ENTRIES=[0x11a688,0x11a8f0,0x11b588,0x11b640,0x11be28,0x11c338,0x11c398,0x11c630,
         0x11c640,0x11c650,0x11c6a0,0x11c748,0x11c770,0x11cb10,0x11cbc0,0x11d018,
         0x11d500,0x11d5b0,0x11d790,0x11d840]
DIRECTIONS=[0x11b238,0x11b930,0x11bac0,0x11bc00,0x11bd20]
LEAVES={0x1007d8,0x10fad0,0x17a560,0x151f10,0x15fde0,0x1600f8}

def main():
    source=ROOT/'analysis/ghidra/pc-name-grid-v1'
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=SHA:raise ValueError('Source ELF identity changed')
    manifest=json.loads((source/'manifest.json').read_bytes())
    if manifest['source_sha256']!=SHA or manifest['status']!='export_completed':raise ValueError('Incomplete dossier')
    out=['// Generated from original SLPM_664.52 by tools/generate_name_constructor_source.py.','']
    entries=ENTRIES+DIRECTIONS
    tables={pc:struct.unpack_from('<8I',elf,table-0xff000) for pc,table in
            [(0x11b980,0x22a558),(0x11ba04,0x22a578)]}
    out.extend(f'static void name_{a:06x}(NameRegisters&);' for a in entries)
    for a in entries:
        folder=(ROOT/'analysis/ghidra/pc-name-cursor-v1') if a in DIRECTIONS else source
        units=json.loads((folder/'functions'/f'{a:08x}.json').read_bytes())['disassembly']['units']
        for u in units:
            f=u['canonical_elf_file_offset']
            if not u['matches_original_elf'] or elf[f:f+4].hex()!=u['raw_hex']:raise ValueError(u['address'])
        out.extend(['']+translate(a,units,entries,LEAVES,'name','NameRegisters',tables if a==0x11b930 else {}))
    (ROOT/'port/core/name_constructor_blocks.hpp').write_text('\n'.join(out)+'\n',encoding='utf-8')


if __name__=='__main__':main()
