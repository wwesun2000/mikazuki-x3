"""Rank source VM targets without a named native case using the original vtable slots and script counts."""
from collections import Counter
import json
from pathlib import Path
import re
from build_full_localization import ROOT, NAMES, PROGRAM_DIR, read_program


def main():
    core=ROOT/"port/core"
    cases=set()
    for p in core.glob("*.cpp"):
        if p.name!="scenario_return.cpp":
            text=p.read_text(encoding="utf-8")
            cases.update(int(a,16) for a in re.findall(r"case\s+0x([\da-fA-F]+)\s*:",text))
            cases.update(int(a,16) for a in re.findall(r"\b(?:entry|e)\s*==\s*0x([\da-fA-F]+)",text))
    for name in ("literal_returns.hpp","context_bridges.hpp"):
        cases.update(int(a,16) for a in re.findall(r"\{0x([\da-f]+),",(core/name).read_text()))
    cases.update(int(a,16) for a in re.findall(r"KX3_VM_ENTRY\(0x([\da-f]+)\)",(core/"vm_context_handlers.hpp").read_text()))
    # Only count an exported table here if invoke_recovered routes its entries
    # to the runtime. A generated file alone is insufficient.
    dispatcher=(core/"recovered.cpp").read_text(encoding="utf-8")
    for name in re.findall(r'#include "([a-z_]+_entries\.hpp)"',dispatcher):
        cases.update(int(a,16) for a in re.findall(r"KX3_MENU_ENTRY\(0x([\da-f]+),",(core/name).read_text()))
    cases.update(int(a,16) for a in re.findall(r"0x([\da-f]+)\s*[,}]",(core/"zero_bindings.hpp").read_text()))
    tails={int(a,16):int(b,16) for a,b in re.findall(r"\{0x([\da-f]+),0x([\da-f]+),",(core/"tail_bindings.hpp").read_text())}
    counts=Counter()
    for name in NAMES:
        data,_,_=read_program(PROGRAM_DIR/f"{name}.program.json",ROOT/f"local/assets/SCENARIO/{name}.sn4")
        for b in data["blocks"]:counts.update(ins["op"] for ins in b["instructions"])
    vm=json.loads((ROOT/"analysis/vm_handlers.json").read_bytes())
    classes={c["id"]:c for c in vm["handler_classes"]}
    results={}
    for slot in (15,3,16):
        missing=[]
        for op in vm["opcode_entries"]:
            if not op.get("default_context_allowlist_member") or not op.get("class_id"):continue
            start=int(classes[op["class_id"]]["vtable_entries"][slot]["target"],16)
            target=start;visited=set()
            while target not in cases and target in tails:
                if target in visited:raise ValueError("Cyclic VM tail")
                visited.add(target);target=tails[target]
            if target not in cases:
                missing.append(dict(op=op["opcode_hex"],entry=hex(start),target=hex(target),uses=counts[op["opcode"]]))
        results[str(slot)]=sorted(missing,key=lambda r:-r["uses"])
    report={"scope":"Static triage only. Counts are script occurrences across all branches, not visits to a context. "
                    "Switch cases, zero bodies and tail bindings are textual candidates, not semantic coverage.",
            "slots":results}
    (ROOT/"analysis/native-core/vm-entry-triage.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    for slot,rows in results.items():print(slot,len(rows),rows[:5])


if __name__=="__main__":main()
