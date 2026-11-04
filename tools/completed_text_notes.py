"""Bind reviewed pronunciation notes to whole-text completion, never partial cuts.

The native renderer already selects Group.whole only when all primary and ruby
events are present. Keep every Segment byte unchanged, including scalar reveals.
"""
import hashlib
import json
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False,
                                    separators=(",", ":")).encode()).hexdigest()


def source_units(script, group_index, units, direct):
    result = [[at, code, ordinal, ruby]
              for at, code, owner, ordinal, ruby in units if owner == group_index]
    for at, end, owner, checksum, ordinal, ruby in direct:
        if owner != group_index:
            continue
        for i, pos in enumerate(range(at + 1, end - 1, 2)):
            result.append([pos, int.from_bytes(script[pos:pos + 2], "big"),
                           ordinal + i, ruby])
    result.sort()
    if len({row[0] for row in result}) != len(result):
        raise ValueError("Duplicate original units in completed text note")
    return result


def apply_completed_notes(root, name, script, groups, units, direct, segments):
    indexes = {g[0]: i for i, g in enumerate(groups)}
    if len(indexes) != len(groups):
        raise ValueError("Ambiguous completed text group")
    source_sha = hashlib.sha256(script).hexdigest()
    for language, column in (("zh", 3), ("en", 4)):
        path = Path(root) / "localization/reveal" / f"completed-notes.{language}.json"
        data = json.loads(path.read_bytes())
        if data["schema"] != 1 or data["language"] != language:
            raise ValueError("Invalid completed text note schema")
        if set(data["source_scripts"]) != {"sn2", "sn4", "sn4g"}:
            raise ValueError("Unknown original script in completed text notes")
        if data["source_scripts"][name] != source_sha:
            raise ValueError("Completed text notes belong to a different original script")
        seen = set()
        for note in data["groups"]:
            gid = note["group_id"]
            if gid in seen:
                raise ValueError("Duplicate completed text note: " + gid)
            seen.add(gid)
            if gid.split(":", 1)[0] not in data["source_scripts"]:
                raise ValueError("Unknown completed text group program: " + gid)
            if gid.split(":", 1)[0] != name:
                continue
            index = indexes[gid]
            row = list(groups[index])
            guard = [row[1], row[2], row[6], row[7] if len(row) > 7 else 0]
            if guard != note["guard"] or row[column] != note["before"]:
                raise ValueError("Changed completed text or reveal guard: " + gid)
            if digest(source_units(script, index, units, direct)) != note["source_units_sha256"]:
                raise ValueError("Changed original glyph binding: " + gid)
            partials = [[p[0], p[1 if language == "zh" else 2]]
                        for p in segments[row[5]:row[5] + row[6]]]
            if digest(partials) != note["segments_sha256"]:
                raise ValueError("Changed original partial translations: " + gid)
            if not isinstance(note["after"], str) or not note["after"].strip():
                raise ValueError("Empty completed text note: " + gid)
            row[column] = note["after"]
            groups[index] = tuple(row)
