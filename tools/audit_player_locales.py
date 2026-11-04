"""Measure indexed narrative coverage against the exact table compiled into the PC player."""
from collections import Counter
from bisect import bisect_left
import hashlib
import json
from pathlib import Path
import re
import sys

from localization_groups import member_units
from build_full_localization import ROOT, NAMES, PROGRAM_DIR, read_program


def rows(section, kind, name):
    header = f"constexpr {kind} {name}[] = {{\n"
    body = section.split(header, 1)[1].split("};\n", 1)[0]
    return (json.loads("[" + line.strip()[1:-2] + "]") for line in body.splitlines())


def story_review_digest(table, language):
    """Fingerprint one player's text, source ownership and reveal cuts independently of the other translation."""
    if language not in ("zh","en"):
        raise ValueError("Expected a compiled Chinese or English locale")
    english = int(language=="en")
    digest = hashlib.sha256()
    def add(kind, value):
        digest.update(json.dumps([kind,value],ensure_ascii=False,separators=(",",":")).encode()+b"\n")
    add("schema",["story-review-v1",language])
    for name in NAMES:
        section=re.search(r"namespace "+name+r" \{\n(.*?)constexpr Lookup lookup",table,re.S)[1]
        add("program",name)
        for g in rows(section,"Group","groups"):
            add("group",[*g[:3],g[3+english],*g[5:]])
        for end,zh,en in rows(section,"Segment","segments"):
            add("segment",[end,en if english else zh])
        for kind,label in (("Unit","units"),("Record","records"),("DirectRecord","direct")):
            for row in rows(section,kind,label):add(kind,row)
        prefixes=re.search(r"std::array<NamePrefix,(\d+)> prefixes=\{\{\n(.*?)\}\};",section,re.S)
        names=[json.loads("["+line.strip()[1:-2]+"]") for line in prefixes[2].splitlines()]
        assert len(names)==int(prefixes[1])
        for at,owner,zh,en in names:add("name",[at,owner,en if english else zh])
        if english:
            # Completed English sentences may reorder words around the live
            # original name. Their final wording is part of the reviewed text,
            # even though it is not stored in a Group or Segment row.
            sentences=re.search(r"std::array<NameSentence,(\d+)> name_sentences=\{\{\n(.*?)\}\};",section,re.S)
            assert sentences is not None,"Missing compiled name sentence table"
            rules=[json.loads("["+line.strip()[1:-2]+"]") for line in sentences[2].splitlines()]
            assert len(rules)==int(sentences[1])
            for rule in rules:add("english_name_sentence",rule)
    for row in rows(table,"ChartTitle","chart_titles"):
        add("chart",[*row[:4],row[4+english]])
    return digest.hexdigest()


def system_review_digest(table, language):
    if language not in ("zh","en"):
        raise ValueError("Expected a compiled Chinese or English locale")
    digest=hashlib.sha256()
    decoder=json.JSONDecoder()
    counts={}
    for kind,label,n in (("SystemString","system_strings",3),("StaffLabel","staff_labels",2)):
        body=table.split(f"constexpr {kind} {label}[]={{\n",1)[1].split("};\n",1)[0]
        lines=body.splitlines()
        for line in lines:
            source,wide=line.split(",L",1)
            values=[]
            for i in range(n):
                s,end=decoder.raw_decode(wide)
                if not isinstance(s,str):raise ValueError("Malformed compiled system label")
                values.append(s)
                tail=wide[end:]
                if i+1<n:
                    if not tail.startswith(",L"):raise ValueError("Missing compiled system label")
                    wide=tail[2:]
                elif tail!="},":raise ValueError("Unexpected compiled system label suffix")
            row=[label,source,*values[:-2],values[-1 if language=="en" else -2]]
            digest.update(json.dumps(row,ensure_ascii=False,separators=(",",":")).encode()+b"\n")
        counts[label]=len(lines)
    return dict(sha256=digest.hexdigest(),counts=counts)


def report_program(name, section):
    groups = list(rows(section, "Group", "groups"))
    units = {offset: group for offset, _, group, _, _ in rows(section, "Unit", "units")}
    direct = {start: group for start, _, group, _, _, _ in rows(section, "DirectRecord", "direct")}
    counts = {lang: Counter() for lang in ("zh", "en")}
    gaps = {lang: Counter() for lang in counts}
    primaries = {lang: Counter() for lang in counts}
    base = ROOT / "localization/full-source"
    program, _, _ = read_program(PROGRAM_DIR / f"{name}.program.json", ROOT / f"local/assets/SCENARIO/{name}.sn4")
    blocks = {b["selector"]: b for b in program["blocks"]}
    missing_features = Counter()
    examples = {}
    missing_zh_groups = []
    missing_primary = []
    for baseline in sorted((base / name).glob("block-*.baseline.json")):
        records = json.loads(baseline.read_bytes())["entries"]
        block = blocks[int(baseline.name[6:8])]
        offsets = [r["offset"] for r in block["instructions"]]
        locations = {r["entry_id"]: r["location"] for r in records}
        owners_by_id = {}
        for row in records:
            if row["record_kind"] != "primary_text":
                continue
            loc = row["location"]
            start = loc["offset"]
            if start in direct:
                owners = [direct[start]]
            else:
                original = member_units(dict(row, offset=start), bytes.fromhex(loc["raw_hex"]))
                owners = [units.get(u["offset"]) for u in original]
            owners_by_id[row["entry_id"]] = owners
            for lang, field in (("zh", 3), ("en", 4)):
                state=coverage(owners,groups,field)
                primaries[lang][state] += 1
                if lang=="zh" and state!="full":
                    missing_primary.append(dict(id=row["entry_id"],selector=block["selector"],offset=start,
                                                bytes=loc["length"],state=state))
        draft = base / "zh-Hans" / name / baseline.name.replace(".baseline.json", ".json")
        if not draft.exists():
            continue
        for gid, entry in json.loads(draft.read_bytes())["entries"].items():
            if entry.get("kind"):
                continue
            owners = [g for rid in entry["members"] for g in owners_by_id.get(rid, ())]
            for lang, field in (("zh", 3), ("en", 4)):
                state = coverage(owners, groups, field)
                counts[lang][state] += 1
                if state != "full":
                    gaps[lang][draft.stem] += 1
                    if lang == "zh":
                        missing_zh_groups.append(gid)
                        locs = [locations[k] for k in entry["members"]]
                        lo = min(r["container_offset"] for r in locs)
                        hi = max(r["offset"] + r["length"] for r in locs)
                        ops = {r["op"] for r in block["instructions"][bisect_left(offsets, lo):bisect_left(offsets, hi)]}
                        extra = ops - {2, 6, 0x46, 0x4c, 0x50, 0x55}
                        feature = ("additional ops " + " ".join(f"{op:02X}" for op in sorted(extra)) if extra else
                                   "contains timed wait" if 0x50 in ops else "other")
                        missing_features[feature] += 1
                        sample = examples.setdefault(feature, [])
                        if len(sample) < 3:
                            sample.append(gid)
    return {"all_primary_records": primaries, "manuscript_groups_without_kind": sum(counts["zh"].values()), "by_language": counts,
            "blocks_with_partial_or_missing_groups": gaps, "missing_zh_source_features": missing_features,
            "missing_zh_examples": examples,"missing_zh_groups":missing_zh_groups,"incomplete_zh_primary":missing_primary}


def coverage(owners, groups, field):
    bound = [g is not None and bool(groups[g][field]) for g in owners]
    return "full" if bound and all(bound) else "partial" if any(bound) else "missing"


if __name__ == "__main__":
    table = Path(sys.argv[1]).read_bytes()
    source = table.decode("utf-8")
    programs = {}
    for name in NAMES:
        section = re.search(r"namespace " + name + r" \{\n(.*?)constexpr Lookup lookup", source, re.S)
        if section is None:
            raise ValueError(f"No compiled lookup for {name}")
        programs[name] = report_program(name, section[1])
    result = {"table_sha256": hashlib.sha256(table).hexdigest(), "scope":
              "All primary records in the three indexed scripts, and separately the Chinese manuscript groups with no kind tag. Full means all primary source glyphs have "
              "target text in the compiled table. This does not measure proofreading, playability, ruby correctness, "
              "non-narrative text, or the timing of individual cuts.", "programs": programs}
    result["story_review_sha256"]={lang:story_review_digest(source,lang) for lang in ("zh","en")}
    system=Path(sys.argv[1]).with_name("system_locale_data.inc")
    if system.exists():
        labels=system.read_text(encoding="utf8")
        result["system_review"]={lang:system_review_digest(labels,lang) for lang in ("zh","en")}
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for name, row in programs.items():
        print(name, row["manuscript_groups_without_kind"], row["all_primary_records"])
