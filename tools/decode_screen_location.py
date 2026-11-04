"""Resolve the small code on the player's sidebar against the original script index."""
import argparse
import json
from pathlib import Path, PureWindowsPath
import re

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = {"11": "sn2", "12": "sn4", "13": "sn4g"}
SCREENSHOT = re.compile(r"(?P<location>.+?)-(?P<language>ja|zh-Hans|en)-"
                        r"(?P<scale>2x|smooth|nearest)(?P<scan>-scan)?"
                        r"(?:-(?:v[0-9]+|\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}))?\.png",re.I)


def decode(code):
    fields = code.strip().upper().split("-")
    if (len(fields) not in (4, 7) or fields[0] not in (*PROGRAMS, "10") or
            any(not re.fullmatch(r"[0-9A-Z]{1,7}", s) for s in fields[1:])):
        raise ValueError("Expected a code such as 13-F-1ZM-ABC, optionally with three menu fields")
    values = [int(s, 36) for s in fields[1:]]
    if max(values) > 0xffffffff:
        raise ValueError("Field exceeds the size of a PS2 word")
    if fields[0] == "10":
        screens = {1:"home", 2:"new_game", 3:"load_game", 4:"slots", 5:"new_note"}
        if len(values) != 3 or values[0] not in screens:
            raise ValueError("Invalid title menu location")
        return dict(title_menu=screens[values[0]], focus=values[1], edition_index=values[2])
    selector, label, offset = values[:3]
    name = PROGRAMS[fields[0]]
    index = ROOT / "analysis/script-programs" / (name + ".program.json")
    blocks = json.loads(json.loads(index.read_bytes())["payload"])["blocks"]
    block = next((b for b in blocks if b["selector"] == selector), None)
    result = dict(program=name, selector=selector, label_id=label, script_offset=hex(offset))
    if block:
        result["label_candidates"] = [k for k,v in block["label_metadata"].items() if v["id"] == label]
        instructions=block["instructions"]
        pos=next((n for n,i in enumerate(instructions) if i["offset"] <= offset < i["next"]),None)
        if pos is not None:
            instruction=instructions[pos]
            result["instruction_offset"] = hex(instruction["offset"])
            result["opcode"] = hex(instruction["op"])
            if pos and offset==instruction["offset"] and instructions[pos-1]["next"]==offset:
                previous=instructions[pos-1]
                result["previous_instruction"]={"offset":hex(previous["offset"]),"opcode":hex(previous["op"])}
            # Identify a nearby text record in file order only. A cursor cannot
            # identify which route was taken or which glyphs are on screen.
            for n in range(pos-1,-1,-1):
                row=instructions[n]
                if row["op"]==2:
                    result["preceding_text_record_in_file"]=f"{name}:{selector:02x}:{row['offset']:08x}"
                    break
                if row["op"] in (0x22,0x6a,0x6b,0x6c,0x70,0x71,0x85):break
    if len(values) == 6:
        result["system_menu"] = dict(zip(("screen", "focus", "subfocus"), values[3:]))
    return result


def decode_input(value):
    name=PureWindowsPath(value).name
    if not name.lower().endswith(".png"):
        return decode(value)
    match=SCREENSHOT.fullmatch(name)
    if not match:
        raise ValueError("This PNG filename has no player location. Enter the code visible on the screenshot.")
    location=match["location"]
    tick=re.fullmatch(r"scene-(\d+)",location,re.I)
    result={"logical_tick":int(tick[1])} if tick else decode(location)
    language=match["language"].lower()
    result["capture"]={"language":"zh-Hans" if language=="zh-hans" else language,
                       "scaling":match["scale"].lower(),"scanlines":bool(match["scan"])}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code",help="Sidebar code or an original F12 PNG filename or path")
    args = parser.parse_args()
    try:
        print(json.dumps(decode_input(args.code), ensure_ascii=False, indent=2))
    except ValueError as exc:
        parser.error(str(exc))
