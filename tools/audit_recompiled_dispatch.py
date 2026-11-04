"""Recover bounded JR tables from the retail ELF and check each compiled site."""
from collections import Counter
from pathlib import Path
import argparse
import json
import re

from vm_handlers import Image, ROOT

FUNCTION = re.compile(r"^// Address: 0x([0-9A-Fa-f]+) - 0x([0-9A-Fa-f]+)\s*$", re.M)
INSN = re.compile(r"^\s*// 0x([0-9a-f]+): 0x([0-9a-f]+)\s+(.*)$", re.M | re.I)
CASE = re.compile(r"case 0x([0-9a-f]+)u:\s*goto label_([0-9a-f]+)", re.I)


def signed16(word):
    return ((word & 0xffff) ^ 0x8000) - 0x8000


def written_gpr(word):
    # -1 denotes an unknown effect. Stores, ordinary branches and COP1
    # arithmetic do not write a GPR. Calls are barriers for this local slice.
    op,fn=word>>26,word&63
    if op in (2,4,5,6,7,20,21,22,23,40,41,43,57,63) or not word:
        return 0
    if (op==0 and fn==8) or (op==1 and (word>>16 & 31)<4):
        return 0
    if op==0 and fn in (0,2,3,33,35,36,37,38,39,42,43,45):
        return word>>11 & 31
    if op in (8,9,10,11,12,13,14,15,24,25,32,33,35,36,37,39,55):
        return word>>16 & 31
    if op==17 and (word>>21 & 31)>=16:
        return 0
    return -1


def recover(image, start, pc):
    # Only accept the fallthrough of a local unsigned range check. Model the
    # address as affine functions of that index; other register values are unknown.
    for guard in range(pc-4, max(start-1,pc-68), -4):
        w = image.word(guard)
        rs, rt = (w >> 21) & 31, (w >> 16) & 31
        branch = w >> 26
        if branch not in (4,20) or not (bool(rs) ^ bool(rt)): # BEQ / BEQL
            continue
        dest = guard+4+4*signed16(w)
        if guard < dest <= pc+4 or guard == start:
            continue
        cond=rs or rt
        definition=next((a for a in range(guard-4,start-1,-4)
                         if written_gpr(image.word(a)) in (-1,cond)),None)
        if definition is None:
            continue
        limit=image.word(definition)
        if limit >> 26 != 11 or (limit >> 16 & 31) != cond:
            continue
        index, count = (limit >> 21) & 31, signed16(limit)
        if not index or not 0 < count <= 256:
            continue
        first = guard+8 if branch==20 else guard+4 # BEQL annuls its slot on fallthrough.
        reload = None
        if index==cond:
            # 103870..103880 compares a GP-relative word, clobbers its own
            # register with SLTIU, then reloads that word on the fallthrough.
            # Restrict this to adjacent instructions with no intervening store.
            if branch!=20 or definition<start+4 or definition+4!=guard:continue
            prior=image.word(definition-4)
            if prior>>26!=35 or (prior>>21&31)!=28 or (prior>>16&31)!=index or index==28:continue
            if image.word(first)!=prior:continue
            reload=first
            first+=4
        if any(written_gpr(image.word(a)) in (-1,index) for a in range(definition+4,guard,4)):
            continue
        regs = {0:(0,0), index:(0,1)}
        loads = {}
        for at in range(first,pc,4):
            w = image.word(at)
            op,s,t,d = w>>26,(w>>21)&31,(w>>16)&31,(w>>11)&31
            if not w:
                continue
            if op == 15:
                target, value = t, ((w&0xffff)<<16,0)
            elif op == 9 and s in regs:
                target, value = t, (regs[s][0]+signed16(w),regs[s][1])
            elif op == 0 and (w&63) in (33,45) and s in regs and t in regs:
                target, value = d, (regs[s][0]+regs[t][0],regs[s][1]+regs[t][1])
            elif op == 0 and w&63 == 0 and t in regs:
                scale = 1 << (w>>6 & 31)
                target, value = d, (regs[t][0]*scale,regs[t][1]*scale)
            elif op == 35 and s in regs:
                loads[t] = ((regs[s][0]+signed16(w))&0xffffffff,regs[s][1])
                regs.pop(t, None)
                continue
            else:
                target=written_gpr(w)
                # Skip unrelated GPR writes and stores. Never follow an
                # unmodelled control transfer inside the address slice.
                if target<0 or op in (1,2,3,4,5,6,7,20,21,22,23) or (op==0 and (w&63)==8):
                    break
                if target:
                    regs.pop(target,None)
                    loads.pop(target,None)
                continue
            if target:
                regs[target] = (value[0]&0xffffffff,value[1])
                loads.pop(target,None)
        else:
            expr = loads.get(image.word(pc)>>21 & 31)
            if expr and expr[1] == 4 and expr[0]%4 == 0:
                table = expr[0]
                targets = [image.word(table+4*i) for i in range(count)]
                return dict(guard=guard,definition=definition,index=index,table=table,
                            targets=targets,delay=image.word(pc+4),reload=reload)
    return None


def scan(core):
    image = Image((ROOT/"local/extracted/SLPM_664.52").read_bytes())
    counts, sites, unresolved = Counter(), [], []
    for path in sorted(core.glob("*_generated.hpp")):
        header = path.read_text(encoding="utf-8")
        functions = list(FUNCTION.finditer(header))
        for i, fn in enumerate(functions):
            start,end = (int(x,16) for x in fn.groups())
            body = header[fn.end():functions[i+1].start() if i+1<len(functions) else len(header)]
            # The interval selects the audit scope; jump sites and target
            # entries come from ELF words, never from a generated case list.
            jumps = [p for p in range(start,end,4) if image.word(p)&0xfc1fffff == 8
                     and (image.word(p)>>21 & 31) != 31]
            if not jumps:
                continue
            emitted = {int(m[1],16):m for m in INSN.finditer(body) if "(Delay Slot)" not in m[3]}
            for pc in jumps:
                counts["raw_non_return_jr"] += 1
                source = recover(image,start,pc)
                if not source:
                    counts["unclassified_domain"] += 1
                    unresolved.append(dict(module=path.name,function=start,jr=pc))
                    continue
                counts["recovered_guarded_path"] += 1
                mark = emitted.get(pc)
                block = ""
                if mark:
                    next_start = min((m.start() for m in emitted.values() if m.start()>mark.start()),default=len(body))
                    block = body[mark.start():next_start]
                cases = {int(a,16) for a,b in CASE.findall(block) if int(a,16)==int(b,16)}
                local = {t for t in source["targets"] if start<=t<end}
                missing = sorted(local-cases)
                capture=re.search(r"const uint32_t jumpTarget = GPR_U32\(ctx, (\d+)\);",block)
                slot=block.lower().find(f"// 0x{pc+4:x}:")
                pre_slot=bool(capture and int(capture[1])==(image.word(pc)>>21 & 31) and
                              (not source["delay"] or slot>capture.start()) and "switch (jumpTarget)" in block)
                sites.append(dict(module=path.name, function=start, jr=pc, **source,pre_slot_dispatch=pre_slot,
                                  external=sorted(set(source["targets"])-local), emitted=sorted(cases),
                                  missing_local=missing, fallback="dispatchGuestBranch" in block))
    return dict(elf_sha256=image.sha256,counts=dict(counts),sites=sites,unresolved=unresolved,
                scope="Fallthrough-path table entries only. The linear slice does not prove whole-function guard dominance, actual index reachability, or the behavior of external fallback targets.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output",type=Path)
    parser.add_argument("--core",type=Path,default=ROOT/"port/core")
    args=parser.parse_args()
    result=scan(args.core)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    misses=[(s["module"],hex(s["jr"]),len(s["missing_local"])) for s in result["sites"] if s["missing_local"]]
    print(result["counts"],"candidate omissions:",misses)
