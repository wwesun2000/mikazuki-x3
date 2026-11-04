"""Identify byte-identical original C++ virtual forwarding thunks in verified context vtables."""
import hashlib
import re
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
def context_methods(word):
    text=(ROOT/'port/core/manager_handler_bindings.hpp').read_text().split('struct Context')[1]
    vtables={int(hexadecimal,16) for pair in re.findall(r'\{0x[0-9a-f]+,0x[0-9a-f]+,0x([0-9a-f]+),0x([0-9a-f]+)\}',text)
             for hexadecimal in pair if int(hexadecimal,16)}
    return {word(v+i) for v in vtables for i in range(0,16,4)}

def main():
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=SHA:raise ValueError('Invalid ELF')
    u=lambda a:struct.unpack_from('<I',elf,a-0xff000)[0]
    reference=[u(0x11e860+i*4) for i in range(11)]
    bridges=[]
    for addr in sorted(context_methods(u)):
        if not 0x100000<=addr<0x204b38:continue
        if any(u(addr+4*i)!=word for i,word in enumerate(reference) if i!=5):continue
        load=u(addr+20)
        if load>>16!=0x8dc2 or load&3 or load&0x8000:continue
        bridges.append((addr,load&0xffff))
    out=['// Produced by tools/generate_context_bridges.py. The eleven source instructions',
         '// differ only in the LW displacement immediately before the original JALR.',
         '#pragma once','#include <array>','#include <cstdint>','namespace kx3 {',
         'struct ContextBridge { std::uint32_t entry, offset; };',
         'inline constexpr std::array<ContextBridge,'+str(len(bridges))+'> context_bridges{{']
    out.extend(f'    {{0x{a:06x},0x{off:02x}}},' for a,off in bridges)
    out+=['}};','}']
    (ROOT/'port/core/context_bridges.hpp').write_text('\n'.join(out)+'\n')
    print(len(bridges))

if __name__=='__main__':main()
