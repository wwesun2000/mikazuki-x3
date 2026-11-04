"""Carry an English draft into repeated branches with the same sentence and adjacent dialogue."""
import argparse
from bisect import bisect_left, bisect_right
from collections import defaultdict
import json
from build_full_localization import ROOT, NAMES, PROGRAM_DIR, read_program

BASE=ROOT/"localization/full-source"

def signature(row):
    return (row.get("kind",""),row["ja"],row["zh"],tuple(row["ruby"]))

def source_contexts(path,block,script):
    book=json.loads(path.read_bytes())["entries"]
    rows=sorted(book.items(),key=lambda item:int(item[0].rsplit(":",1)[1],16))
    locations={r["entry_id"]:r["location"] for r in
               json.loads((BASE/path.parent.name/(path.stem+".baseline.json")).read_bytes())["entries"]}
    instructions=block["instructions"]
    offsets=[r["offset"] for r in instructions]
    labels=sorted(block["labels"].values())
    for n in range(1,len(rows)-1):
        gid,row=rows[n]
        around=[r for _,r in rows[n-1:n+2]]
        if not row["ja"].strip() or any(r.get("kind") or r.get("before_live_name") for r in around):
            continue
        members=[locations[mid] for r in around for mid in r["members"]]
        start=members[0]["container_offset"]
        end=members[-1]["container_offset"]+members[-1]["container_length"]
        if bisect_right(labels,start)!=bisect_left(labels,end):continue
        commands=instructions[bisect_left(offsets,start):bisect_left(offsets,end)]
        # The neighbouring sentences may be separated by identical original
        # page/wait instructions. The target sentence itself must be uncut.
        if not commands or any(r["op"] not in (2,4,6,9,0x0b,0x15,0x1e,0x32,0x46,0x4c,0x50,0x55) for r in commands):continue
        own=[locations[mid] for mid in row["members"]]
        own_end=own[-1]["container_offset"]+own[-1]["container_length"]
        if any(r["op"] not in (2,4,6,0x46,0x4c,0x55) for r in commands
               if own[0]["container_offset"]<=r["offset"]<own_end):continue
        family=tuple(label.rsplit("_",1)[0] for label in row["label"])
        if not family:continue
        key=(family,script[start:end],tuple(signature(r) for r in around),
             tuple((m["offset"]-start,m["length"]) for m in members))
        yield gid,row,key

def run(write):
    added={}
    for program in NAMES:
        source,_,script=read_program(PROGRAM_DIR/f"{program}.program.json",ROOT/f"local/assets/SCENARIO/{program}.sn4")
        blocks={b["selector"]:b for b in source["blocks"]}
        contexts={}
        documents={}
        memory=defaultdict(dict)
        for path in sorted((BASE/"zh-Hans"/program).glob("block-*.json")):
            target=BASE/"en"/program/path.name
            doc=json.loads(target.read_bytes()) if target.exists() else dict(locale="en",status="draft",release_allowed=False,entries={})
            assert doc["status"]=="draft" and not doc["release_allowed"]
            documents[target]=doc
            for gid,row,key in source_contexts(path,blocks[int(path.stem[6:])],script):
                contexts[gid]=(target,row["binding"],key)
                entry=doc["entries"].get(gid)
                if entry and "parallel_source" not in entry:
                    if entry["binding"]!=row["binding"]:raise ValueError("Changed source "+gid)
                    memory[key][gid]=entry["en"]
        changed=set()
        for gid,(path,binding,key) in contexts.items():
            entries=documents[path]["entries"]
            if gid in entries or key not in memory:continue
            options=memory[key]
            if len(set(options.values()))!=1:continue
            original=min(options)
            entries[gid]=dict(binding=binding,en=options[original],parallel_source=original)
            added[gid]=original
            changed.add(path)
        for path in sorted(changed) if write else ():
            path.parent.mkdir(parents=True,exist_ok=True)
            doc=documents[path];doc["entries"]=dict(sorted(doc["entries"].items()))
            path.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("New source-bound English draft occurrences:",len(added),"(written)" if write else "(preview)")

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview",action="store_true")
    run(not parser.parse_args().preview)
