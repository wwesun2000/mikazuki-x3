"""Import edited English for exact Japanese/Chinese manuscript variants at their individual source IDs."""
import hashlib
import json
from pathlib import Path
import sys
from build_full_localization import ROOT, NAMES

def apply(candidates,phrases):
    raw=candidates.read_bytes()
    batch=json.loads(phrases.read_bytes())
    if hashlib.sha256(raw).hexdigest()!=batch["source_sha256"]:raise ValueError("Wrong editorial worklist")
    rows=json.loads(raw)
    base=ROOT/"localization/full-source"
    books={}
    targets={}
    changes=0
    for index,en in batch["phrases"].items():
        row=rows[int(index)]
        if not en.strip():raise ValueError("Empty English draft")
        for gid in row["ids"]:
            program,block,_=gid.split(":")
            if program not in NAMES:raise ValueError("Unknown scenario")
            rel=Path(program)/f"block-{int(block,16):02}.json"
            if rel not in books:
                books[rel]=json.loads((base/"zh-Hans"/rel).read_bytes())["entries"]
                path=base/"en"/rel
                targets[rel]=json.loads(path.read_bytes()) if path.is_file() else dict(locale="en",status="draft",release_allowed=False,entries={})
            source=books[rel][gid];doc=targets[rel]
            if any(source[k]!=row[k] for k in ("ja","zh","ruby")) or source.get("kind") or source.get("before_live_name"):
                raise ValueError("Changed phrase "+gid)
            if doc["status"]!="draft" or doc["release_allowed"]:raise ValueError("Expected draft target")
            entry=dict(binding=source["binding"],en=en)
            old=doc["entries"].get(gid)
            if old and old!=entry:raise ValueError("Another English draft already owns "+gid)
            if not old:
                doc["entries"][gid]=entry
                changes+=1
    for rel,doc in targets.items():
        dst=base/"en"/rel
        dst.parent.mkdir(parents=True,exist_ok=True)
        doc["entries"]=dict(sorted(doc["entries"].items()))
        data=json.dumps(doc,ensure_ascii=False,indent=2)+"\n"
        if not dst.is_file() or dst.read_text(encoding="utf-8")!=data:dst.write_text(data,encoding="utf-8")
    print(f"{len(batch['phrases'])} edited variants, {changes} new English occurrences")

if __name__=="__main__":
    apply(Path(sys.argv[1]),Path(sys.argv[2]))
