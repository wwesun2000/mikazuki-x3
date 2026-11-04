"""Cross-check all exported draft groups against the retail scripts and line catalogs."""
import json
from collections import Counter
import build_full_localization as full
from localization_groups import BASE,PACKS,binding_digest,member_units


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def audit():
    source={}
    for name in full.NAMES:
        _,index_sha,script=full.read_program(full.PROGRAM_DIR/f"{name}.program.json",full.ROOT/f"local/assets/SCENARIO/{name}.sn4")
        source[name]=(index_sha,full.sha(script),script)
    ids=set();group_ids=set();tuples=set();packs=[];scopes=Counter();per_program=Counter();catalogs={};single_drafts=0
    for path in sorted(PACKS.rglob("*-groups.json")):
        envelope=read(path);payload=envelope["payload"];p=json.loads(payload)
        full.require(full.sha(payload.encode())==envelope["sha256"],"Damaged pack envelope")
        counts=Counter()
        for group in p["groups"]:
            gid=group["group_id"];program=group["program"];selector=group["selector"];key=(program,selector)
            full.require(gid not in group_ids and group["source_binding_hash"]==binding_digest(group["members"]),"Duplicate group or changed members")
            group_ids.add(gid)
            per_program[program]+=1
            index_sha,script_sha,raw=source[program]
            full.require((p["program_sha256"],p["script_sha256"])==(index_sha,script_sha),"Wrong source program")
            if key not in catalogs:
                catalogs[key]={e["entry_id"]:e for e in read(BASE/program/f"block-{selector:02d}.catalog.json")["entries"]}
            decoded=[]
            for m in group["members"]:
                eid=m["entry_id"];off=m["offset"];data=raw[off:off+m["length"]];entry=catalogs[key][eid]
                full.require(eid not in ids and data.hex()==m["raw_hex"] and full.sha(data)==m["raw_sha256"]
                    and m["source_hash"]==entry["source_hash"] and entry["grouping"]["group_id"]==gid,"Draft/catalog source differs")
                ids.add(eid);counts[m["record_kind"]]+=1;scopes[key]+=1;decoded.extend(member_units(m,data))
            full.require(decoded==group["source_units"],"Glyph occurrence mismatch")
            targets=group["targets"]
            full.require(all(targets[lang]["text"].strip() and targets[lang]["status"]=="draft" and targets[lang]["source_binding_hash"]==group["source_binding_hash"] for lang in ("zh-Hans","en")),"Changed draft binding")
            tuples.add((group["source_text"],targets["zh-Hans"]["text"],targets["en"]["text"]))
            single_drafts+=len(group["ordered_primary_ids"])==1
            counts["groups_with_original50"]+=bool(group["retained_timed_pauses"]);counts["original50_count"]+=len(group["retained_timed_pauses"])
        packs.append(dict(path=path.relative_to(full.ROOT).as_posix(),sha256=full.sha(path.read_bytes()),
            payload_sha256=envelope["sha256"],size_bytes=path.stat().st_size,groups=len(p["groups"]),
            primary_records=counts["primary_text"],ruby_records=counts["ruby"],groups_with_original50=counts["groups_with_original50"],
            original50_count=counts["original50_count"]))
    overview=read(BASE/"overview.json");lines=overview["translation_counts"]
    full.require(lines["en"]==lines["zh-Hans"] and not overview["release_allowed"],"Unexpected release or coverage state")
    full.require(lines["zh-Hans"]["draft"]==single_drafts,"Rebuild overview after updating draft packs")
    return dict(groups=len(group_ids),primary_records=sum(p["primary_records"] for p in packs),ruby_records=sum(p["ruby_records"] for p in packs),
        targets_per_locale=len(group_ids),unique_source_zh_en_tuples=len(tuples),total_bound_source_ids=len(ids),
        groups_by_program=dict(sorted(per_program.items())),
        global_catalog_target_counts_per_locale=lines["zh-Hans"],covered_records_by_program_selector={f"{a}:{b}":v for (a,b),v in sorted(scopes.items())},
        full_source_digest=overview["full_source_digest"],whole_project_proofreading_complete=False,packs=packs)


if __name__=="__main__":
    summary=audit()
    path=BASE/"validation.json";report=read(path);report["current_group_drafts"]=summary
    path.write_bytes(full._encoded(report))
    counts=summary["global_catalog_target_counts_per_locale"]
    paragraph=(f"三作脚本共有 {sum(counts.values()):,} 条带原盘字节证据的源记录。目前 {summary['groups']:,} 组简中和英文初稿"
        f"绑定 {summary['total_bound_source_ids']:,} 个源 ID，其中正文 {summary['primary_records']:,} 条、注音 {summary['ruby_records']:,} 条。"
        f"按日中英合句去重有 {summary['unique_source_zh_en_tuples']:,} 种。每种语言有 {counts['draft']:,} 条可直接逐条绑定的正文初稿，"
        f"已复审 {counts['reviewed']:,} 条。")
    begin,end="<!-- group-coverage -->","<!-- /group-coverage -->"
    for path in (full.ROOT/"localization/README.md",BASE/"groups/README.md"):
        text=path.read_text(encoding="utf-8");full.require(text.count(begin)==1 and text.count(end)==1,"Missing coverage markers")
        left,middle=text.split(begin);_,right=middle.split(end)
        updated=left+begin+"\n"+paragraph+"\n"+end+right
        if text!=updated:path.write_text(updated,encoding="utf-8")
    print(json.dumps({k:v for k,v in summary.items() if k!="packs"}))
