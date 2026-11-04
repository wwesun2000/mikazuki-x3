"""Compile exact R5900 jr-ra / constant-v0 leaves from the known function map."""
import json
from pathlib import Path
from vm_handlers import Image
from generate_context_bridges import context_methods
from generate_tail_bindings import vm_methods

ROOT=Path(__file__).resolve().parents[1]
def main():
    source=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    analysis=ROOT/'analysis/ghidra/vm-shared-tail-remainder-v2'
    manifest=json.loads((analysis/'manifest.json').read_text())
    functions=json.loads((analysis/'functions-after.json').read_text())
    if manifest['source_sha256']!=source.sha256 or len(functions)!=manifest['functions_after']:
        raise ValueError('Original function database/ELF mismatch')
    candidates={address for address in context_methods(source.word) if 0x100000<=address<0x204b38}
    for item in functions:
        state=item['state']
        if item['address']!=state['entry'] or len(state['body'])!=1:continue
        address=int(state['entry'].split(':')[1],16)
        if state['body'][0]['bytes']!=8 or state['body'][0]['start']!=state['entry']:continue
        candidates.add(address)
    # The five manager predicate objects (+280..+290) dispatch source methods
    # from slot 0 (ordinary choice) through +112 (121700, system modal).
    for table in [0x225d48,0x225c48,0x225dc8,0x225cc8,0x225e48]:
        for offset in range(0,113,4):candidates.add(source.word(table+offset))
    # 121760's slot +0x20 at the first cold story menu. Ghidra's physical
    # xref from 223BD0 is retained even though the leaf has no function body.
    candidates.add(source.word(0x223bb0+0x20))
    candidates.update(entry for entry,_ in vm_methods(source))
    tails=json.loads((ROOT/"analysis/native-core/tail-bindings.json").read_bytes())
    if tails["elf_sha256"]!=source.sha256:raise ValueError("Wrong VM tail evidence")
    candidates.update(b["target"] for b in tails["bindings"])
    # Some helpers share Ghidra metadata with a neighboring entry. Accept a
    # direct edge only when its instruction matches the actual ELF word.
    for p in (ROOT/"analysis/ghidra/vm-context-batch-v1/functions").glob("*.json"):
        for unit in json.loads(p.read_bytes())["disassembly"]["units"]:
            if unit.get("mnemonic") not in ("j","jal"):continue
            pc=int(unit["address"].split(":")[1],16);word=source.word(pc)
            if not unit["matches_original_elf"] or word.to_bytes(4,"little").hex()!=unit["raw_hex"]:
                raise ValueError("VM code reference differs from ISO")
            candidates.add(((pc+4)&0xf0000000)|((word&0x3ffffff)<<2))
    output=[]
    for address in candidates:
        if source.word(address)!=0x03e00008:continue
        delay=source.word(address+4)
        if delay==0x0000102d:value=0 # daddu v0,zero,zero
        elif delay>>16==0x2402: # addiu v0,zero,s16
            low=delay&0xffff
            value=(low^0x8000)-0x8000
        elif delay>>16==0x3402:value=delay&0xffff # ori v0,zero,u16
        else:continue
        output.append((address,value))
    output.sort()
    header=['// Generated from verified two-instruction functions by generate_literal_returns.py.',
            '// Source ELF '+source.sha256,'#pragma once','#include <array>','#include <cstdint>',
            'namespace kx3 {','struct LiteralReturn {std::uint32_t entry; std::int32_t value;};',
            f'inline constexpr std::array<LiteralReturn,{len(output)}> literal_returns{{{{']
    header.extend(f'    {{0x{address:08x},{value}}},' for address,value in output)
    header+=['}};','}']
    (ROOT/'port/core/literal_returns.hpp').write_text('\n'.join(header)+'\n',encoding='utf-8')
    print(f'{len(output)} source-proven two-instruction returns')
if __name__=='__main__':main()
