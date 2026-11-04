"""Generate exact tail wrappers from Ghidra dossiers and verified retail VM vtable pointers."""
import hashlib
import json
from pathlib import Path
from vm_handlers import Image

ROOT=Path(__file__).resolve().parents[1]
ELF_SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'

SHAPES={
    (0xffbf0000,0xdfbf0000):(1,2),
    (0x00c0282d,0xffbf0000,0xdfbf0000):(2,2),
    (0x00e0282d,0xffbf0000,0xdfbf0000):(3,2),
    (0x00c0282d,0xffbf0000,0x00e0302d,0xdfbf0000):(2,3),
}

def decode(entry,words):
    if len(words)<5 or words[0]!=0x27bdfff0 or words[-2]>>26!=2 or words[-1]!=0x27bd0010:
        return None
    args=SHAPES.get(tuple(words[1:-2]))
    if args is None:return None
    target=((entry+4*(len(words)-1))&0xf0000000)|((words[-2]&0x03ffffff)<<2)
    if target==entry:raise ValueError("Self-recursive wrapper")
    return dict(entry=entry,target=target,a1_from=args[0],a2_from=args[1])

def vm_methods(image):
    vm=json.loads((ROOT/"analysis/vm_handlers.json").read_bytes())
    for cls in vm["handler_classes"]:
        table=int(cls["vtable_address"],16)
        for row in cls["vtable_entries"][:25]:
            site=int(row["address"],16);entry=int(row["target"],16)
            if site!=table+4*row["slot"] or image.word(site)!=entry:raise ValueError("VM pointer differs from ISO ELF")
            if 0x100000<=entry<0x204b38 and not entry%4:yield entry,site
    # The manager creates five additional handlers outside the ordinary opcode
    # factory. Their readback slots use the same calling convention.
    for constructor in (0x134920,0x1345b8,0x134ae0,0x134780,0x134cf8):
        words=[image.word(constructor+4*i) for i in range(4)]
        if words[0]!=0x3c0f0022 or words[1]>>16!=0x25ef or words[2:]!=[0x03e00008,0xac8f0000]:
            raise ValueError("Changed auxiliary handler constructor")
        table=0x220000+(words[1]&0xffff)
        for slot in range(25):
            site=table+4*slot
            entry=image.word(site)
            if not 0x100000<=entry<0x204b38 or entry%4:raise ValueError("Unexpected auxiliary method")
            yield entry,site

def main():
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=ELF_SHA: raise ValueError('Wrong source ELF')
    index=json.loads((ROOT/'analysis/ghidra/vm-execution-index-v1.json').read_text())
    bindings=[]
    for anchor in index['primary_anchors']:
        path=ROOT/anchor['path']
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=anchor['sha256']: raise ValueError('Dossier changed')
        dossier=json.loads(raw)
        units=dossier['disassembly']['units']
        words=[]
        for unit in units:
            offset=unit.get('canonical_elf_file_offset')
            if unit.get('kind')!='instruction' or offset is None: break
            data=bytes.fromhex(unit['raw_hex'])
            if elf[offset:offset+len(data)]!=data: raise ValueError('Dossier/source mismatch')
            words.append(int.from_bytes(data,'little'))
        else:
            # Exact stack-only prologue/epilogue and argument moves. No jal,
            # omitted side effect, non-stack store, or guessed opcode semantics.
            entry=int(anchor['entry'],16)
            binding=decode(entry,words)
            if binding:bindings.append(dict(binding,dossier=anchor["path"],sha256=anchor["sha256"]))
    by_entry={b["entry"]:b for b in bindings}
    image=Image(elf)
    for entry,site in vm_methods(image):
        words=[image.word(entry+i*4) for i in range(7)]
        for length in (5,6,7):
            binding=decode(entry,words[:length])
            if not binding:continue
            item=by_entry.setdefault(entry,binding)
            if any(item[k]!=v for k,v in binding.items()):raise ValueError("Conflicting tail evidence")
            item.setdefault("vtable_word_addresses",[]).append(site)
            item["original_words"]=[f"{w:08x}" for w in words[:length]]
            break
    bindings=sorted(by_entry.values(),key=lambda b:b["entry"])
    targets={b['entry']:b['target'] for b in bindings}
    for entry in targets:
        seen=set()
        while entry in targets:
            if entry in seen: raise ValueError('Cyclic tail binding')
            seen.add(entry); entry=targets[entry]
    text='// Generated from source-byte-verified Ghidra function bodies.\n'
    text+='// These wrappers preserve unknown callees as errors, not success.\n#pragma once\n#include <array>\n#include <cstdint>\nnamespace kx3 {\n'
    text+='struct TailBinding { std::uint32_t entry, target; unsigned a1_from, a2_from; };\n'
    text+=f'inline constexpr std::array<TailBinding, {len(bindings)}> tail_bindings = {{{{\n'
    text+=''.join(f'    {{0x{b["entry"]:08x},0x{b["target"]:08x},{b["a1_from"]},{b["a2_from"]}}},\n' for b in bindings)
    text+='}};\n}\n'
    (ROOT/'port/core/tail_bindings.hpp').write_text(text,encoding='utf-8')
    output=ROOT/'analysis/native-core/tail-bindings.json'
    output.write_text(json.dumps(dict(schema=1,elf_sha256=ELF_SHA,bindings=bindings),indent=2)+'\n')
    print(f'Emitted {len(bindings)} source-verified tail wrappers')

if __name__=='__main__': main()
