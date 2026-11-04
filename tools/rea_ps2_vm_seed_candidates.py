"""Build a reviewable, byte-verified VM vtable function-seeding manifest.

This does not run Ghidra or create functions. Function starts are evidence-guided
candidates, not claims of automatic discovery or recovered opcode semantics.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"
MAP_SHA = "8063a89ae6b9bc4c158ee8e51bf5f85e77b6d6e47cce280d326cc0ee1aa2104f"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def address(value: str) -> int:
    return int(value.rsplit(":", 1)[-1], 16)


def hx(value: int) -> str:
    return f"0x{value:08x}"


def build(elf_path: Path, map_path: Path, baseline: Path) -> tuple[dict, dict]:
    raw, map_raw = elf_path.read_bytes(), map_path.read_bytes()
    if digest(raw) != ELF_SHA or digest(map_raw) != MAP_SHA:
        raise ValueError("ELF or reviewed VM map identity changed")
    report = json.loads(map_raw)
    if report["source"]["sha256"] != ELF_SHA:
        raise ValueError("VM map is bound to another artifact")
    if raw[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<HH", raw, 16) != (2, 8):
        raise ValueError("Expected executable ELF32 LE MIPS")
    if struct.unpack_from("<I", raw, 36)[0] != 0x20920001:
        raise ValueError("Unexpected R5900 header flags")
    phoff, shoff = struct.unpack_from("<II", raw, 28)
    phsize, phnum, shsize, shnum = struct.unpack_from("<HHHH", raw, 42)
    if phsize != 32 or shsize != 40:
        raise ValueError("Unexpected ELF table sizes")
    loads = [struct.unpack_from("<IIIIIIII", raw, phoff + i * 32) for i in range(phnum)]
    loads = [p for p in loads if p[0] == 1]
    sections = [struct.unpack_from("<IIIIIIIIII", raw, shoff + i * 40) for i in range(shnum)]
    executable = [s for s in sections if s[1] != 8 and s[2] & 6 == 6 and s[5] > 0]

    def offset(va: int, size: int, code: bool = False) -> int:
        matches = [p[1] + va - p[2] for p in loads if p[2] <= va and va + size <= p[2] + p[4]]
        if len(matches) != 1 or matches[0] + size > len(raw):
            raise ValueError(f"No unique file-backed address: {hx(va)}")
        if code and not any(s[3] <= va and va + size <= s[3] + s[5] for s in executable):
            raise ValueError(f"Target outside allocated executable section: {hx(va)}")
        return matches[0]

    def proof(va: int, size: int, code: bool = False) -> dict:
        off = offset(va, size, code)
        return {"address": hx(va), "file_offset": off, "bytes": size, "raw_hex": raw[off:off + size].hex()}

    classes, candidates, seen = [], [], set()
    if len(report["handler_classes"]) != 72:
        raise ValueError("Expected 72 reviewed classes")
    for item in report["handler_classes"]:
        ctor, vt, factory = map(address, (item["constructor"], item["vtable_address"], item["factory_case"]))
        a, b, c, d = struct.unpack_from("<IIII", raw, offset(ctor, 16, True))
        signed_low = (b & 0xffff) - (0x10000 if b & 0x8000 else 0)
        if a & 0xffff0000 != 0x3c0f0000 or b & 0xffff0000 != 0x25ef0000 or c != 0x03e00008 or d != 0xac8f0000 or ((a & 0xffff) << 16) + signed_low != vt:
            raise ValueError(f"Constructor no longer establishes vtable: {hx(ctor)}")
        f = struct.unpack_from("<IIIII", raw, offset(factory, 20, True))
        call_target = ((factory + 16) & 0xf0000000) | ((f[3] & 0x03ffffff) << 2)
        if f[0] != 0x0c043eb4 or f[1] & 0xffff0000 != 0x24040000 or f[2] != 0x0040802d or f[3] >> 26 != 3 or f[4] != 0x0040202d or call_target != ctor:
            raise ValueError(f"Factory no longer calls constructor: {hx(factory)}")
        entries = item["vtable_entries"]
        if len(entries) != 28 or [v["slot"] for v in entries] != list(range(28)):
            raise ValueError("Unexpected vtable entry ordering")
        cls = {"id": item["id"], "opcodes": item["opcodes"], "factory": proof(factory, 20, True),
               "constructor": proof(ctor, 16, True), "vtable": proof(vt, 112), "targets": []}
        for slot, entry in enumerate(entries):
            table_off = offset(vt + slot * 4, 4)
            value = struct.unpack_from("<I", raw, table_off)[0]
            if entry["file_offset"] != table_off or address(entry["address"]) != vt + slot * 4 or entry["raw_hex"] != raw[table_off:table_off + 4].hex() or address(entry["target"]) != value or int(entry["raw_word"], 16) != value:
                raise ValueError("Vtable proof differs from original ELF bytes")
            if slot >= 25:
                if value != 0:
                    raise ValueError("Expected three zero padding words")
                continue
            if value & 3 or value in seen:
                raise ValueError("Expected distinct aligned executable targets")
            seen.add(value)
            entry_proof = proof(value, 16, True)
            cls["targets"].append(hx(value))
            candidates.append({"class_id": item["id"], "opcodes": item["opcodes"], "slot": slot,
                               "role": "default-slot15" if slot == 15 else "preview-slot1" if slot == 1 else "other-vtable-slot",
                               "pointer_address": hx(vt + slot * 4), "pointer_file_offset": table_off,
                               "pointer_raw_hex": raw[table_off:table_off + 4].hex(), "entry": entry_proof})
        classes.append(cls)
    if len(candidates) != 1800:
        raise ValueError("Expected 1800 unique reviewed targets")

    baseline_raw = baseline.read_bytes()
    known, ranges = {}, []
    with baseline.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["external"] == "true" or not row["entry"].startswith("ram:"):
                continue
            entry = address(row["entry"])
            known[entry] = row["name"]
            for part in json.loads(row["body_ranges_json"]):
                if part["min"].startswith("ram:"):
                    ranges.append((address(part["min"]), address(part["max_inclusive"]), entry))
    counts = {"classes": 72, "unique_vtable_targets": 1800, "baseline_existing": 0,
              "baseline_containing_conflict": 0, "baseline_unclaimed_candidates": 0}
    for candidate in candidates:
        va = address(candidate["entry"]["address"])
        owners = sorted({start for lo, hi, start in ranges if lo <= va <= hi})
        status = "existing" if va in known else "containing-conflict" if owners else "unclaimed-candidate"
        candidate["baseline"] = {"status": status, "containing_entries": [hx(v) for v in owners], "name": known.get(va)}
        counts[{"existing": "baseline_existing", "containing-conflict": "baseline_containing_conflict", "unclaimed-candidate": "baseline_unclaimed_candidates"}[status]] += 1
    candidates.sort(key=lambda c: address(c["entry"]["address"]))
    manifest = {"schema": 1, "kind": "evidence-guided-function-seed-candidates", "elf_sha256": ELF_SHA,
                "language_id": "r5900:LE:32:default", "vm_handlers_sha256": MAP_SHA,
                "vm_handlers_evidence_id": report["evidence_id"], "baseline_functions_sha256": digest(baseline_raw),
                "counts": counts, "classes": classes, "candidates": candidates,
                "limits": ["No original bytes or Ghidra database were modified by this generator.",
                           "Baseline inventory is historical. The Java script must recheck current memory and containing functions.",
                           "Candidate provenance does not establish opcode semantics, complete function boundaries or automatic discovery."]}
    selected = [c for c in candidates if c["slot"] in (15, 1)]
    anchors = {"schema": 1, "elf_sha256": ELF_SHA, "language_id": "r5900:LE:32:default",
               "anchors": [{"address": c["entry"]["address"][2:], "role": f'{c["class_id"]} {c["role"]}',
                            "entry_confidence": "verified constructor-installed table pointer; evidence-guided function boundary requires Ghidra confirmation",
                            "creation_candidate": True, "evidence": ["analysis/vm_handlers.json"]} for c in selected],
               "scope": "72 slot15 plus 72 slot1 entries; actual call/tail dependencies are selected only after Ghidra export"}
    return manifest, anchors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "analysis/ghidra/vm-seed-review-v1")
    parser.add_argument("--baseline", type=Path, default=ROOT / "analysis/ghidra/baseline-v2/functions.csv")
    args = parser.parse_args()
    manifest, anchors = build(ROOT / "local/extracted/SLPM_664.52", ROOT / "analysis/vm_handlers.json", args.baseline)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in (("candidates.json", manifest), ("anchors.json", anchors)):
        (args.output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (args.output / "review.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["class_id", "opcodes", "slot", "role", "pointer_address", "target", "entry_file_offset", "baseline_status", "containing_entries"])
        for c in manifest["candidates"]:
            writer.writerow([c["class_id"], ",".join(map(str, c["opcodes"])), c["slot"], c["role"], c["pointer_address"], c["entry"]["address"], c["entry"]["file_offset"], c["baseline"]["status"], ",".join(c["baseline"]["containing_entries"])])
    print(json.dumps({"output": str(args.output), "counts": manifest["counts"], "primary_anchors": len(anchors["anchors"])}))


if __name__ == "__main__":
    main()
