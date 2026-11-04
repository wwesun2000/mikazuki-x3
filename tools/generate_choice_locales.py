"""Build draft text bindings for completed ordinary choice pages. No branch destinations are executed here."""
from collections import defaultdict
import json
from pathlib import Path
import sys
import build_full_localization as full
from localization_groups import PACKS, bind_choice_preview, binding_digest


def cpp(value):
    return json.dumps(value, ensure_ascii=False) if isinstance(value, str) else str(value)


def generate():
    program, program_digest, source = full.read_program(
        full.PROGRAM_DIR / "sn4g.program.json", full.ROOT / "local/assets/SCENARIO/sn4g.sn4")
    blocks = {b["selector"]: b for b in program["blocks"]}
    previews = defaultdict(dict)
    single = {}
    for path in sorted(PACKS.glob("*-groups.json")):
        env = json.loads(path.read_text(encoding="utf-8"))
        full.require(full.sha(env["payload"].encode()) == env["sha256"], "Changed translation envelope")
        data = json.loads(env["payload"])
        full.require(data["script_sha256"] == full.sha(source) and data["program_sha256"] == program_digest,
                     "Translation pack belongs to another source")
        for g in data["groups"]:
            if len(g["members"]) != 1 or g["has_unobservable_space"] or g["pending_vm_dependencies"]:
                continue
            m = g["members"][0]
            if m["record_kind"] != "primary_text":
                continue
            offset = m["offset"]
            raw = source[offset:offset + m["length"]]
            full.require(raw.hex() == m["raw_hex"] and full.sha(raw) == m["raw_sha256"] and
                         binding_digest([m]) == g["source_binding_hash"] and
                         all(g["targets"][lang]["source_binding_hash"] == g["source_binding_hash"]
                             for lang in ("en", "zh-Hans")), "Changed source binding")
            full.require(offset not in single, "Ambiguous source record")
            single[offset] = g
            if ref := g.get("choice_preview"):
                full.require(ref == bind_choice_preview(program, blocks[g["selector"]], ref, g),
                             "Choice target and preview record disagree")
                previews[ref["source_selector"], ref["source_offset"]][ref["option_index"]] = g

    rows, pages = [], []
    for (selector, offset), options in sorted(previews.items()):
        instructions = blocks[selector]["instructions"]
        end = next(i for i, r in enumerate(instructions) if r["offset"] == offset)
        setup = instructions[end]
        if set(options) != set(range(setup["operands"]["option_count"])):
            continue
        # This native snapshot viewer can identify a complete, ordinary page
        # with single-record dialogue, explicit waits and no intervening flow.
        first = end
        while first and instructions[first - 1]["op"] in (0x02, 0x04, 0x09):
            first -= 1
        if first < 2 or [r["op"] for r in instructions[first - 2:first]] != [0x85, 0x22]:
            continue
        label = instructions[first - 2]["operands"]["label"]
        texts = [r for r in instructions[first:end] if r["op"] == 0x02]
        if any(r["offset"] not in single or single[r["offset"]]["public_label"] != label for r in texts):
            continue
        groups = [(-1, single[r["offset"]]) for r in texts] + sorted(options.items())
        pages.append([selector, setup["next"], label, offset, setup["raw_hex"], len(rows), len(groups)])
        for option, g in groups:
            m = g["members"][0]
            rows.append([option, g["selector"], g["public_label"], m["offset"], m["raw_hex"],
                         len(g["source_units"]), g["group_id"], g["targets"]["zh-Hans"]["text"],
                         g["targets"]["en"]["text"]])
    full.require(pages and rows, "No fully bound ordinary choice pages")
    def array(name, kind, records):
        return f"inline constexpr {kind} {name}[] = {{\n" + "".join(
            "    {" + ", ".join(cpp(v) for v in row) + "},\n" for row in records) + "};\n"
    return "// Derived exclusively from original scenario bytes and source-bound draft packs.\n" + \
           array("draft_choice_pages", "ChoicePageBinding", pages) + array("draft_choice_rows", "ChoiceRowBinding", rows)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    contents = generate().encode("utf-8")
    if not path.exists() or path.read_bytes() != contents:
        path.write_bytes(contents)
