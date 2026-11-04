"""Compile the native player's text lookup from the original script and checked translation packs."""
from pathlib import Path
from bisect import bisect_left,bisect_right
import json
import re
import struct
import sys
import unicodedata
import build_full_localization as full
from localization_groups import PACKS, binding_digest, member_units
from zh_timed_clauses import clauses, load_alignment
from completed_text_notes import apply_completed_notes


def cpp(value):
    return json.dumps(value,ensure_ascii=False) if isinstance(value,str) else str(value)


def emit(kind,name,rows):
    return f"constexpr {kind} {name}[] = {{\n"+"".join(
        " {"+",".join(cpp(v) for v in row)+"},\n" for row in rows)+"};\n"


def chart_titles():
    rows=[]
    for name,kind,programs in (("ending","end",full.NAMES),("chapter","chap",("sn2","sn4"))):
        data=json.loads((full.ROOT/f"localization/system/{name}-titles.json").read_text(encoding="utf-8"))
        for program in programs:
            drafts=data["programs"][program];raw=(full.ROOT/f"local/assets/CHART/{program}_{kind}.dat").read_bytes()
            full.require(full.sha(raw)==drafts["source_sha256"] and len(drafts["records"])==raw[0],"Wrong original chart file")
            off=2
            for i,(index,offset,label,ja,zh,en) in enumerate(drafts["records"]):
                end=raw.index(0,off+14);title=raw[off+14:end]
                full.require(raw[off] and i==index and offset==off and raw[off+1:off+14].split(b'\0',1)[0].decode("ascii")==label and
                             title.decode("cp932")==ja and zh.strip() and en.strip(),"Chart title/label mismatch")
                rows.append((program+"-"+kind,i,title.hex(),ja,zh,en));off=end+2
    timetable=json.loads((full.ROOT/"localization/system/time-chart.json").read_text(encoding="utf-8"))
    raw=(full.ROOT/"local/assets/CHART/sn4g_tim.dat").read_bytes()
    full.require(full.sha(raw)==timetable["source_sha256"] and raw.startswith(b"SN4G tc ver4\0"),"Wrong original time chart")
    off=16
    def count():
        nonlocal off
        value=int.from_bytes(raw[off:off+2],"little");off+=2;return value
    def collect(table,key):
        nonlocal off
        for i,(pos,ja,zh,en) in enumerate(timetable[key]):
            end=raw.index(0,off);title=raw[off:end]
            full.require(off==pos and ja==title.decode("cp932") and ((not title and not zh and not en) or (zh and en)),"Time chart disagrees with source")
            rows.append((table,i,title.hex(),ja,zh,en));off=end+2
    times=count();off+=2*times
    full.require(count()==len(timetable["titles"]),"Wrong time-chart title count")
    collect("sn4g-time","titles")
    for size in (16,14,14):
        n=count();off+=size*n
    collect("sn4g-head","headers")
    return emit("ChartTitle","chart_titles",rows)


def add_poem_stanzas(script, groups, units, segments):
    directory = full.ROOT / "localization/full-source/zh-Hans"
    cuts = json.loads((directory / "poem-reveal.json").read_bytes())["groups"]
    stanzas = json.loads((full.ROOT / "localization/reveal/sn4-song-en.json").read_bytes())["stanzas"]
    used = []
    for selector in ("00","01"):
        block = "sn4/block-"+selector
        drafts = json.loads((directory / (block+".json")).read_bytes())["entries"]
        records = json.loads((full.OUTPUT / (block+".baseline.json")).read_bytes())["entries"]
        index = {r["entry_id"]:r for r in records}
        for alignment in (a for a in cuts if a["group"].split(":")[1]==selector):
            draft = drafts[alignment["group"]]
            source = full.sha(draft["ja"].encode())
            english = stanzas[source]
            add_poem_stanza(script,groups,units,segments,alignment,draft,index,english)
            used.append(source)
    full.require(len(used)==len(cuts)==10 and all(used.count(s)==2 for s in stanzas),"Unpaired poem reprise")


def add_poem_stanza(script, groups, units, segments, alignment, draft, index, english):
    gid = alignment["group"]
    members = [index[key] for key in draft["members"]]
    binding = full.sha(" ".join(r["entry_id"]+"/"+r["location"]["raw_sha256"] for r in members).encode())
    full.require(binding == alignment["source_binding"] == draft["binding"], "Poem source binding changed")
    full.require(full.sha(draft["zh"].encode()) == alignment["target_sha256"], "Poem translation changed")
    channels = [[], []]
    boundaries = {}
    for record in members:
        loc = record["location"]
        raw = script[loc["offset"]:loc["offset"]+loc["length"]]
        full.require(full.sha(raw) == loc["raw_sha256"], "Poem source bytes changed")
        decoded = member_units(dict(record, offset=loc["offset"]), raw)
        if record["record_kind"] == "primary_text":
            begin = len(channels[0])
            channels[0].extend(decoded)
            boundaries[record["entry_id"]] = (begin, len(channels[0]))
        else:
            full.require(record["record_kind"] == "ruby", "Unexpected poem record kind")
            channels[1].extend(decoded)
    for ordinal, unit in enumerate(channels[0]+channels[1]):
        units.append((unit["offset"],unit["unit"],len(groups),ordinal,unit["channel"]))
    first = len(segments)
    previous = 0
    for span, line in zip(alignment["spans"], english[:-1], strict=True):
        begin = boundaries[span["first_primary_id"]][0]
        end = boundaries[span["last_primary_id"]][1]
        full.require(begin == previous and end > begin, "Noncontiguous poem cuts")
        segments.append((end, span["zh"], line))
        previous = end
    note = alignment["end_note"]
    full.require(previous == len(channels[0]) and note["after_primary_id"] == alignment["spans"][-1]["last_primary_id"],
                 "Poem note precedes the original final word")
    end, zh, en = segments[-1]
    segments[-1] = (end, zh+note["zh"], en+english[-1])
    zh = "".join(s[1] for s in segments[first:])
    full.require(zh == draft["zh"], "Poem cuts no longer reconstruct the manuscript")
    groups.append((gid,len(channels[0]),len(channels[1]),zh,"".join(s[2] for s in segments[first:]),
                   first,len(alignment["spans"]),1))


def timed_targets(gid,draft,parts,alignment):
    source=["".join(r["original"] for r in part) for part in parts]
    specific=alignment["groups"].get(gid)
    if specific:
        whole=specific.get("final_zh","".join(specific["zh"]))
        full.require(source==specific["source"] and whole==draft["zh"] and
                     len(source)==len(specific["en"])==len(specific["zh"]),f"Stale timed translation {gid}")
        return specific["zh"],specific["en"],"final_zh" in specific or "final_en" in specific
    remaining=draft["zh"]
    chunks=[]
    for phrase in source[:-1]:
        matches={s for s in alignment["prefixes"].get(phrase,[]) if remaining.startswith(s)}
        if not matches:break
        # Every candidate is an approved rendering of this exact original
        # clause. Include its punctuation when the manuscript contains it.
        text=max(matches,key=len);chunks.append(text);remaining=remaining[len(text):]
    if len(chunks)==len(source)-1 and remaining:
        return chunks+[remaining],[""]*len(parts),False
    # Chinese word order can put a clue earlier in the finished sentence.
    # Independently translate what has arrived at each wait. The player
    # switches to the manuscript sentence only after its final glyph and ruby.
    glosses=alignment["glosses"]
    if any(phrase not in glosses for phrase in source[:-1]):return None
    early_en=[alignment["english_glosses"].get(p,"") for p in source[:-1]]
    return [glosses[p] for p in source[:-1]]+[""],early_en+[""],True


def special_english(draft,endings):
    if draft.get("kind")=="typography":
        if not all(c in "“”‘’！？。、，：…・" for c in draft["zh"]):return ""
        return draft["zh"].translate(str.maketrans("！？。、，：","!?.,,:")).replace("……","…")
    if draft.get("kind")=="ending-title":
        if draft["ja"]=="終":return "The End"
        match=re.fullmatch(r"Ｎｏ．([０-９]+)　(.+)",draft["ja"])
        if match:
            number=int(unicodedata.normalize("NFKC",match[1]))
            if 1<=number<=len(endings) and endings[number-1][3]==match[2]:
                return f"No. {number}  "+endings[number-1][5]
    return ""


def add_direct_groups(script,block,entries,drafts,english,endings,alignment,positioned,covered,groups,direct,segments,prefixes):
    index={r["entry_id"]:r for r in entries}
    ordered=sorted(entries,key=lambda r:r["location"]["offset"])
    positions=[r["location"]["offset"] for r in ordered]
    instructions=block["instructions"]
    pcs=[r["offset"] for r in instructions]
    labels=sorted(block["labels"].values())
    totals=[0,0,0,0]
    def valid_english(k,v):
        if k not in drafts or v["binding"]!=drafts[k]["binding"]:return False
        if v["en"].strip():return True
        # Only two explicitly approved sourceと quote links may be oneASCII
        # space. Keep their original bound Group and completion gate.
        if k not in {"sn4:01:000762ed","sn4:01:0009d278"} or v["en"]!=" ":return False
        handoff=full.ROOT/"local/translation-work/claude-handoff"
        if str(handoff) not in sys.path:sys.path.insert(0,str(handoff))
        from sealed_name_review132 import blank_name_link_allowed
        return blank_name_link_allowed(k,drafts[k],v,script)
    full.require(all(valid_english(k,v) for k,v in english.items()),"English manuscript disagrees with original source binding")
    for gid,draft in drafts.items():
        if draft.get("kind") not in (None,"typography","ending-title","system-text"):
            continue
        ids=draft["members"]
        members=[index[key] for key in ids]
        start=min(r["location"]["container_offset"] for r in members)
        end=max(r["location"]["offset"]+r["location"]["length"] for r in members)
        layout=positioned.get(gid)
        prose_wrap=False
        waits=[]
        if len(ids)>1:
            commands=instructions[bisect_left(pcs,start):bisect_left(pcs,end)]
            within=ordered[bisect_left(positions,start):bisect_left(positions,end)]
            ops={r["op"] for r in commands}
            # Default 04 can advance the line or redirect a readback cursor.
            # A short prose sentence can reflow on PC only after all its
            # actual primary and ruby events arrive. Never cross an input,
            # timed pause, coordinate instruction or label to complete it.
            prose_wrap=(4 in ops and ops<={2,4,6,0x46,0x4c,0x55} and not draft.get("kind")
                       and not draft.get("before_live_name") and 2<=len(ids)<=5
                       and re.fullmatch(r'[^。！？]{1,140}[。！？][」』）]*',draft["ja"]) is not None)
            if ([r["entry_id"] for r in within]!=ids or bisect_right(labels,start)!=bisect_left(labels,end)
                    or not prose_wrap and any(r["op"] not in (2,6,0x46,0x4c,0x50,0x55) and
                           not (layout and r["op"] in (4,0x66)) for r in commands)):
                continue
            waits=[r["offset"] for r in commands if r["op"]==0x50]
        binding=full.sha(" ".join(r["entry_id"]+"/"+r["location"]["raw_sha256"] for r in members).encode())
        full.require(binding==draft["binding"],f"Translation binding changed: {gid}")
        rows=[]
        for r in members:
            loc=r["location"];at=loc["offset"];raw=script[at:at+loc["length"]]
            full.require(full.sha(raw)==loc["raw_sha256"],"Direct record changed")
            decoded=member_units(dict(r,offset=at),raw)
            # 14DD8C's line continuation and centered controller symbols have
            # separate drawing semantics. Ordinary fullwidth spaces are
            # committed advances with node_address==0 in the text driver.
            # These two redactions and the combat tip were reached through
            # their retail label, with ordinary FNT nodes for every symbol.
            # The timeline checklist follows an unconditional 6A in its label.
            # The isolated original text entry drew all 16 units with FNT.
            plain_symbols=gid in {"sn4g:00:00004614","sn4g:00:00004633","sn4g:0d:00090281","sn4g:11:000b0343"}
            if not decoded or len(raw)!=2+2*len(decoded) or any(
                    u["offset"] in covered or u["unit"]==0x818f or
                    not plain_symbols and u["unit"] in (0x817e,0x81a0,0x81a2) for u in decoded):
                break
            checksum=2166136261
            for byte in raw:checksum=((checksum^byte)*16777619)&0xffffffff
            rows.append((at,at+len(raw),checksum,len(decoded),r["record_kind"]=="ruby",raw[1:-1].decode("cp932")))
        if len(rows)!=len(ids):continue
        primary=sum(row[3] for row in rows if not row[4])
        if not primary:continue
        full.require("".join(row[5] for row in rows if not row[4])==draft["ja"] and draft["zh"].strip()
                     and [row[5] for row in rows if row[4]]==draft["ruby"],f"Draft text differs: {gid}")
        first=len(segments)
        en=english.get(gid,{}).get("en","") or special_english(draft,endings)
        english_waits=english.get(gid,{}).get("waits")
        if english_waits is not None:
            full.require(waits and not layout,f"English waits outside a timed source group: {gid}")
        prefix=draft.get("before_live_name")
        english_prefix=english.get(gid,{}).get("before_live_name")
        if english_prefix:
            full.require(prefix and all(english_prefix.get(k)==prefix[k] for k in ("offset","op","raw_hex"))
                         and english_prefix.get("en","").strip(),f"Unbound English name insertion {gid}")
        if prefix:
            site=prefix["offset"]
            full.require(prefix["op"]==0x0e and prefix["raw_hex"]=="0e" and site+1==start and script[site]==0x0e
                         and site in pcs and prefix["zh"].strip(),f"Unbound name insertion {gid}")
        if layout:
            full.require(draft["ja"]=="".join(layout["source"]) and draft["zh"]==layout.get("final_zh","".join(layout["zh"])) and
                         len(layout["zh"])==len(layout["en"])==len(layout["source"]),"Changed positioned text "+gid)
            en="".join(layout["en"])
            count=0
            for source,zh_line,en_line in zip(layout["source"],layout["zh"],layout["en"],strict=True):
                full.require(source,"Empty positioned source cut")
                count+=len(source);segments.append((count,zh_line,en_line))
            full.require(count==primary,"Positioned source count differs")
            boundaries={s[0] for s in segments[first:]}
            for wait in waits:
                ordinal=sum(len(r["original"]) for r in members if r["record_kind"]=="primary_text" and r["location"]["offset"]<wait)
                full.require(ordinal in boundaries or ordinal==0,"Positioned text crosses an original timed wait "+gid)
        elif waits:
            parts=clauses(members,waits)
            if len(parts)<2:continue
            cut=timed_targets(gid,draft,parts,alignment)
            if not cut:continue
            zh_parts,en_parts,replace_at_end=cut
            # The manuscript owns the last reveal. A clause-only draft can also
            # supply a whole sentence if it translates through the final wait.
            specific=alignment["groups"].get(gid)
            if specific and "final_en" in specific:
                full.require(en and en==specific["final_en"],f"Stale final English translation {gid}")
            if not en and specific and en_parts[-1]:en="".join(en_parts)
            if not en:en_parts=[""]*len(parts)
            if english_waits is not None:
                source=["".join(r["original"] for r in part) for part in parts]
                target=english_waits["en"]
                full.require(en and english_waits["source"]==source and len(target)==len(parts)
                             and all(isinstance(t,str) for t in target)
                             and all(not old or old==new for old,new in zip(en_parts,target)),
                             f"English segments disagree with the original wait or an existing translation: {gid}")
                en_parts=target
            count=0
            for part,zh_line,en_line in zip(parts,zh_parts,en_parts,strict=True):
                count+=sum(len(r["original"]) for r in part)
                segments.append((count,zh_line,en_line))
            full.require(count==primary and (replace_at_end or "".join(zh_parts)==draft["zh"]),
                         "Timed cuts did not exhaust the source")
        next_ordinal=[0,primary]
        for at,end,checksum,count,ruby,_ in rows:
            direct.append((at,end,len(groups),checksum,next_ordinal[ruby],int(ruby)))
            next_ordinal[ruby]+=count
        groups.append((gid,primary,next_ordinal[1]-primary,draft["zh"],en,first,len(segments)-first,1))
        if prefix:prefixes.append((site,len(groups)-1,prefix["zh"],english_prefix["en"] if english_prefix else ""))
        totals[3 if layout or prose_wrap else 2 if waits else int(len(ids)>1)]+=1
    return totals


def add_simultaneous_lines(program,script,groups,units,segments):
    # Original 66 moves each voice to its own Y coordinate before a glyph.
    # Include the second punctuation/closing quote records which the manuscript
    # indexes separately. Every displayed target still owns its own source unit.
    for row in json.loads((full.ROOT/"localization/reveal/simultaneous.json").read_bytes())["lines"]:
        for gid in row["ids"]:
            name,selector,offset=gid.split(":")
            if name!=row["program"] or name!=program["name"]:continue
            block=next(b for b in program["blocks"] if b["selector"]==int(selector,16))
            code=block["instructions"]
            at=bisect_left([r["offset"] for r in code],int(offset,16))
            full.require(at>0 and code[at]["offset"]==int(offset,16) and code[at-1]["op"]==0x66,
                         "Missing original simultaneous text position "+gid)
            lanes={y:[] for y in row["y"]}
            lane=None
            for ins in code[at-1:]:
                p=ins["offset"];op=ins["op"]
                if op==0x66:
                    lane=int.from_bytes(script[p+3:p+5],"big")
                    full.require(lane in lanes,"Unexpected original voice position "+gid)
                elif op==2:
                    raw=script[p:p+4]
                    full.require(len(raw)==4 and raw[0]==2 and raw[3]==3 and lane is not None,"Changed simultaneous glyph "+gid)
                    lanes[lane].append((p+1,int.from_bytes(raw[1:3],"big"),raw[1:3].decode("cp932")))
                    lane=None
                elif op not in (4,0x46,0x50):raise ValueError("Unexpected simultaneous text command "+hex(op))
                if all(len(a)==len(row["source"]) for a in lanes.values()):break
            for voice,stream in enumerate(lanes.values()):
                full.require("".join(r[2] for r in stream)==row["source"] and
                             len(stream)==len(row["zh"])==len(row["en"]),"Incomplete original parallel line "+gid)
                first=len(segments)
                for ordinal,(p,c,_) in enumerate(stream):
                    units.append((p,c,len(groups),ordinal,0))
                    segments.append((ordinal+1,row["zh"][ordinal],row["en"][ordinal]))
                groups.append((gid+f"/voice-{voice+1}",len(stream),0,"".join(row["zh"]),row["final_en"],first,len(stream),1))

def program_lookup(name):
    program, index_sha, script=full.read_program(full.PROGRAM_DIR/f"{name}.program.json",full.ROOT/f"local/assets/SCENARIO/{name}.sn4")
    source_sha=full.sha(script)
    authored={}
    zh_waits={}
    alignment_path=full.ROOT/f"localization/reveal/{name}-opening.json"
    if alignment_path.exists():
        alignment=json.loads(alignment_path.read_text(encoding="utf-8"))
        full.require(alignment["script_sha256"]==source_sha,"Wrong alignment source")
        authored=alignment["groups"]
        zh_waits=alignment.get("zh_waits",{})
        full.require(not authored.keys() & zh_waits.keys(),"Two reveal maps for the same source group")
    legacy=json.loads((full.ROOT/'localization/reveal/legacy-waits.zh.json').read_bytes())
    full.require(legacy['script_sha256'][name]==source_sha,'Wrong legacy wait script')
    legacy={k:v for k,v in legacy['groups'].items() if k.startswith(name+':')}
    full.require(not legacy.keys() & (authored.keys()|zh_waits.keys()),'Duplicate legacy alignment')
    en_wait_path=full.ROOT/'localization/reveal/legacy-waits.en.json'
    en_waits=json.loads(en_wait_path.read_bytes())['groups'] if en_wait_path.exists() else {}
    en_waits={k:v for k,v in en_waits.items() if k.startswith(name+':')}
    full.require(en_waits.keys() <= (legacy.keys()|zh_waits.keys()),'English wait with no verified source cuts')
    groups=[];units=[];segments=[];seen=set()
    pack_dir=PACKS if name=="sn4g" else PACKS/name
    for file in sorted(pack_dir.glob("*-groups.json")):
        envelope=json.loads(file.read_text(encoding="utf-8"))
        full.require(full.sha(envelope["payload"].encode())==envelope["sha256"],"Invalid draft envelope")
        data=json.loads(envelope["payload"])
        full.require(data["script_sha256"]==source_sha and data["program_sha256"]==index_sha,"Draft source identity")
        for group in data["groups"]:
            gid=group["group_id"];members=group["members"]
            full.require(all(c["opcode"]!=0x75 for c in group["original_controls"]),
                         f"Split the translation at the original font color change in {gid}")
            full.require(gid not in seen and binding_digest(members)==group["source_binding_hash"],"Ambiguous draft binding")
            seen.add(gid)
            decoded=[]
            for m in members:
                raw=script[m["offset"]:m["offset"]+m["length"]]
                full.require(raw.hex()==m["raw_hex"] and full.sha(raw)==m["raw_sha256"],"Draft source record changed")
                decoded.extend(member_units(m,raw))
            full.require(group["source_units"]==decoded,"Glyph order or channel differs from the bound source records")
            prim=[u for u in group["source_units"] if u["channel"]==0]
            ruby=[u for u in group["source_units"] if u["channel"]==1]
            for ordinal,unit in enumerate(prim+ruby):
                at=unit["offset"]
                full.require(int.from_bytes(script[at:at+2],"big")==unit["unit"],"Glyph differs from source")
                units.append((at,unit["unit"],len(groups),ordinal,unit["channel"]))
            full.require(prim and all(group["targets"][lang]["source_binding_hash"]==group["source_binding_hash"]
                                      for lang in ("zh-Hans","en")),"Invalid target binding")
            zh,en=(group["targets"][k]["text"] for k in ("zh-Hans","en"))
            first=len(segments)
            if gid in authored:
                chunks=authored[gid]
                full.require(not group["pending_vm_dependencies"],"Alignment crossing an unresolved source command")
                for key,whole in (("source",group["source_text"]),("zh-Hans",zh),("en",en)):
                    full.require("".join(c[key] for c in chunks)==whole,"Alignment changed original or translated text")
                full.require(len(group["source_text"])==len(prim),"Alignment primary units disagree")
                done=0
                ends=set()
                for chunk in chunks:
                    done+=len(chunk["source"])
                    ends.add(done)
                    segments.append((done,chunk["zh-Hans"],chunk["en"]))
                for wait in group["retained_timed_pauses"]:
                    prior=sum(u["offset"]<wait["offset"] for u in prim)
                    full.require(prior in ends and 0<prior<len(prim),"Target clause crosses an original timed pause")
            elif gid in zh_waits or gid in legacy:
                # 55 sets line spacing. For groups containing original 73/74
                # scene/cue commands, bind their raw bytes as well. The VM
                # still executes every command; only arriving glyphs reveal text.
                spacing=data.get("recovered_vm_dependencies",{}).get("85",{})
                dependencies=group["pending_vm_dependencies"]
                cue_controls=legacy.get(gid,{}).get('controls',[])
                if cue_controls:
                    expected=[[c['offset'],c['raw_hex']] for c in dependencies]
                    observed_waits=[[c['offset'],c['raw_hex']] for c in group['retained_timed_pauses']]
                    full.require(cue_controls==expected and observed_waits==legacy[gid]['waits'],
                                 'Scene or cue changed in Chinese wait: '+gid)
                    for at,raw in cue_controls+observed_waits:
                        full.require(script[at:at+len(raw)//2].hex()==raw,'Original wait/cue bytes changed: '+gid)
                resolved=all((c["opcode"]==0x55 and spacing.get("entry")=="0x001284f8") or
                             (cue_controls and c["opcode"] in (0x73,0x74)) for c in dependencies)
                full.require(resolved and group["retained_timed_pauses"],
                             "Chinese wait alignment requires resolved original waits: "+gid)
                ends=[sum(u["offset"]<wait["offset"] for u in prim) for wait in group["retained_timed_pauses"]]+[len(prim)]
                if cue_controls:
                    # A cue may sit between two waits with no intervening glyph.
                    ends=list(dict.fromkeys(ends))
                if gid in legacy:
                    row=legacy[gid]
                    full.require(row['binding']==group['source_binding_hash'] and row['final_zh']==zh,
                                 'Stale legacy Chinese reading: '+gid)
                    sources=row['source'];readings=[*row['early'],'']
                else:
                    chunks=zh_waits[gid]
                    sources=[c['source'] for c in chunks];readings=[c['zh'] for c in chunks]
                    full.require(''.join(readings)==zh,'Chinese final text changed: '+gid)
                full.require(len(sources)==len(readings)==len(ends) and all(readings[:-1]) and
                             len(group["source_text"])==len(prim),"Chinese wait count changed: "+gid)
                english_parts=['']*len(ends)
                if gid in en_waits:
                    row=en_waits[gid]
                    if 'previous_full' in row:
                        full.require(en==row['previous_full'],'Changed previous complete English reading: '+gid)
                        en=row['full']
                    full.require(row['binding']==group['source_binding_hash'] and row['source']==sources
                                 and row['full']==en and len(row['early'])+1==len(ends)
                                 and all(isinstance(t,str) and t.strip() for t in row['early']),
                                 'Stale English wait or changed complete translation: '+gid)
                    english_parts=[*row['early'],'']
                previous=0
                for source,reading,en_part,end in zip(sources,readings,english_parts,ends,strict=True):
                    full.require(previous<end and source==group["source_text"][previous:end],
                                 "Chinese segment disagrees with source wait: "+gid)
                    segments.append((end,reading,en_part))
                    previous=end
            elif len(group["ordered_primary_ids"])==1 and not group["retained_timed_pauses"] and not group["pending_vm_dependencies"]:
                # A single source record has no later primary clause or wait to
                # reveal here. Use scalar-safe partial display within this unit.
                segments.append((len(prim),zh,en))
            group_row=(gid,len(prim),len(ruby),zh,en,first,len(segments)-first)
            groups.append((*group_row,1) if gid in zh_waits or gid in legacy else group_row)
    full.require(set(authored)<=seen,"Alignment without a matching draft")
    full.require(zh_waits.keys()<=seen,"Chinese wait without a matching draft")
    full.require(legacy.keys()<=seen,"Unbound legacy Chinese wait")
    if name == "sn4":
        add_poem_stanzas(script,groups,units,segments)
    add_simultaneous_lines(dict(program,name=name),script,groups,units,segments)
    units.sort()
    full.require(len({r[0] for r in units})==len(units),"Source glyph belongs to multiple groups")
    records=[]
    direct=[]
    prefixes=[]
    covered={row[0] for row in units}
    aligned=len(groups)
    totals=[0,0,0,0]
    timed=load_alignment()
    positioned={}
    for file in ("positioned.json","wrapped-dialogue.json"):
        for variant in json.loads((full.ROOT/"localization/reveal"/file).read_bytes())["variants"]:
            for gid in variant["ids"]:
                full.require(gid not in positioned,"Ambiguous positioned source "+gid)
                positioned[gid]=variant
    endings=json.loads((full.ROOT/"localization/system/ending-titles.json").read_bytes())["programs"][name]["records"]
    for block in program["blocks"]:
        p=full.OUTPUT/name/f"block-{block['selector']:02d}.baseline.json"
        baseline=json.loads(p.read_text(encoding="utf-8"))
        manuscript=full.OUTPUT/"zh-Hans"/name/p.name.replace(".baseline","")
        drafts=json.loads(manuscript.read_bytes())["entries"] if manuscript.exists() else {}
        en_file=full.OUTPUT/"en"/name/manuscript.name
        english=json.loads(en_file.read_bytes())["entries"] if en_file.exists() else {}
        for item in baseline["entries"]:
            loc=item["location"];at=loc["offset"];raw=bytes.fromhex(loc["raw_hex"])
            full.require(script[at:at+len(raw)]==raw,"Untranslated record source differs")
            records.append((at,at+len(raw),block["selector"]))
        result=add_direct_groups(script,block,baseline["entries"],drafts,english,endings,timed,positioned,covered,groups,direct,segments,prefixes)
        for i in range(len(totals)):totals[i]+=result[i]
    records.sort()
    direct.sort()
    prefixes.sort()
    full.require(len({p[0] for p in prefixes})==len(prefixes),"Duplicate name insertion site")
    name_sentences=[]
    lookup_groups={row[0]:row for row in groups}
    rules=json.loads((full.ROOT/'localization/reveal/name-sentences.en.json').read_bytes()).get(name,[])
    for rule in rules:
        early=lookup_groups[rule['before']];ending=lookup_groups[rule['after']]
        at=rule['insert'];left=int(early[0].split(':')[-1],16);right=int(ending[0].split(':')[-1],16)
        end=right+2*ending[1]+2
        full.require(at+1==right and at==left+2*early[1]+2 and
                     script[left]==script[right]==2 and script[at-1:at+1]==b'\x03\x0e' and script[end-1]==3 and
                     full.sha(script[left:end])==rule['raw_sha256'] and
                     early[4]==rule['early'] and ending[4]==rule['ending'],'Stale live-name sentence: '+ending[0])
        name_sentences.append((at,early[0],ending[0],rule['ending'],rule['final_before'],rule['final_after']))
    full.require(all(left[1]<=right[0] for left,right in zip(direct,direct[1:])), "Overlapping translation ranges")
    # Pronunciation annotations belong only to the completed sentence; leave
    # original scalar fragments and wait-aligned Segment text unchanged.
    apply_completed_notes(full.ROOT,name,script,groups,units,direct,segments)
    count_en=sum(bool(row[4]) for row in groups[aligned:])
    print(f"{name}: {totals[0]} single-record, {totals[1]} contiguous, {totals[2]} timed and {totals[3]} positioned groups, including {len(prefixes)} live-name prefixes ({count_en} new English), {aligned} aligned groups")
    return ("namespace "+name+" {\n"+emit("Group","groups",groups)+emit("Unit","units",units)
            +emit("Segment","segments",segments)+emit("Record","records",records)
            +emit("DirectRecord","direct",direct)
            +f"constexpr std::array<NamePrefix,{len(prefixes)}> prefixes={{{{\n"
            +"".join(" {"+",".join(cpp(v) for v in row)+"},\n" for row in prefixes)+"}};\n"
            +f"constexpr std::array<NameSentence,{len(name_sentences)}> name_sentences={{{{\n"
            +"".join(" {"+",".join(cpp(v) for v in row)+"},\n" for row in name_sentences)+"}};\n"
            +f'constexpr Lookup lookup{{"{name}",{len(script)},groups,units,segments,records,direct,prefixes,name_sentences}};\n'+"}\n")


def generate():
    return ("// Generated from retail scripts and source-bound bilingual drafts.\n"
            +"".join(program_lookup(name) for name in full.NAMES)+chart_titles())

def system_labels():
    from vm_handlers import Image
    image=Image((full.ROOT/"local/extracted/SLPM_664.52").read_bytes())
    folder=full.ROOT/"localization/system"
    zh=json.loads((folder/"elf-text.zh-Hans.json").read_bytes())
    en=json.loads((folder/"elf-text.en.json").read_bytes())
    full.require(image.sha256==zh["source_sha256"]==en["source_sha256"],"Wrong system text ELF")
    full.require(set(en["records"])=={r["id"] for r in zh["records"]},"System text source IDs differ")
    # 141070 -> 140FF0(207258,23DD20,11). The first atlas entry contains
    # the digits; entries 1..10 point to the help and the brightness scale.
    brightness=set()
    cursor=0x207258
    for i in range(11):
        start=image.offset(cursor,1)
        end=image.data.index(0,start,start+0x2072f8-cursor)
        if i:brightness.add(cursor)
        else:full.require(image.data[start:end].decode("cp932")=="０１２３４５６７８９","Wrong brightness digit table")
        cursor+=end-start+1
    full.require(cursor==0x2072f7 and image.data[image.offset(cursor,1)]==0,
                 "Brightness label table padding differs before the controls table")
    # 189898 draws seven {text pointer, x, y} descriptors with stride 12.
    interval={struct.unpack_from('<I',image.data,image.offset(0x20d698+i*12,4))[0] for i in range(7)}
    full.require(len(interval)==7,"Autoplay text table differs")
    rows=[]
    for r in zh["records"]:
        addr=int(r["address"],16);size=r["length"];start=image.offset(addr,size)
        raw=image.data[start:start+size];target=en["records"][r["id"]]
        full.require(start==r["file_offset"] and full.sha(raw)==r["raw_sha256"]==target["raw_sha256"]
                     and raw.decode("cp932")==r["ja"] and target["en"].strip(),"System text binding differs")
        # 11C960 uses the name prompts. 141B28 passes the eight consecutive
        # CP932 strings beginning at 2072F8 to the original help rasterizer.
        if addr in (0x205d90,0x205da0,0x205db8,0x235ed8,0x235ee0,0x20d728,0x20d768,0x229738,0x238220) or addr in brightness or addr in interval or 0x2072f8<=addr<=0x20737d:
            rows.append("{"+",".join([hex(addr),'"'+''.join(f'\\x{b:02x}' for b in raw)+'"',
                                     *["L"+cpp(s) for s in (r["ja"],r["zh"],target["en"])]])+"},")
    full.require(len(rows)==34,"Missing original name, brightness, autoplay, notice, replay, chapter or control-help label")
    names="constexpr SystemString system_strings[]={\n"+"\n".join(rows)+"\n};\n"
    staff=json.loads((folder/"staff-roll.zh-Hans.json").read_bytes())
    english=json.loads((folder/"staff-roll.en.json").read_bytes())
    full.require(english["source_iso_sha256"]==staff["iso_sha256"],"Wrong credit source disc")
    labels=[]
    for member in staff["members"]:
        raw=(full.ROOT/"local/assets"/member["path"]).read_bytes()
        full.require(full.sha(raw)==member["sha256"],"Wrong ISO staff list")
        program=Path(member["path"]).stem.split("_")[0]
        for r in member["records"]:
            if r["kind"]!="translated-label":continue
            start=r["offset"];line=raw[start:start+r["length"]]
            full.require(full.sha(line)==r["source_sha256"] and line.decode("cp932")==r["ja"],"Wrong original credit line")
            if line.endswith(b"\x81\x8f"):line=line[:-2]
            encoded='"'+''.join(f'\\x{b:02x}' for b in line)+'"'
            labels.append("{"+",".join([cpp(program),str(start),encoded,"L"+cpp(r["zh"]),
                                       "L"+cpp(english["labels"][r["ja"]])])+"},")
    return names+"constexpr StaffLabel staff_labels[]={\n"+"\n".join(labels)+"\n};\n"

def system_table_for_story(story):
    from audit_player_locales import story_review_digest, system_review_digest
    labels=system_labels()
    path=full.ROOT/"localization/review/player-zh-Hans.json"
    reviewed=False
    if path.is_file():
        receipt=json.loads(path.read_bytes())
        evidence=full.ROOT/receipt['evidence']
        reviewed=(receipt['locale']=='zh-Hans' and receipt['status']=='reviewed' and evidence.is_file()
                  and full.sha(evidence.read_bytes())==receipt['evidence_sha256']
                  and story_review_digest(story,'zh')==receipt['story_review_sha256']
                  and system_review_digest(labels,'zh')['sha256']==receipt['system_review_sha256'])
    return labels+'constexpr bool chinese_text_reviewed='+('true' if reviewed else 'false')+';\n'


if __name__=="__main__":
    dst=Path(sys.argv[1]);story=generate();data=story.encode("utf-8")
    if not dst.exists() or dst.read_bytes()!=data:
        dst.write_bytes(data)
    if len(sys.argv)>2:
        dst=Path(sys.argv[2]);data=system_table_for_story(story).encode("utf-8")
        if not dst.exists() or dst.read_bytes()!=data:dst.write_bytes(data)
