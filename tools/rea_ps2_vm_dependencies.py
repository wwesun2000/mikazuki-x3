"""Select one-hop call/tail dependencies from actual, byte-matched Ghidra listings."""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "analysis/ghidra/vm-primary-v1"
OUTPUT = ROOT / "analysis/ghidra/vm-dependency-review-v2"
SHA = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"


def addr(text: str) -> int:
    return int(text.rsplit(":", 1)[-1], 16)


def hashed(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inside(value: int, ranges: list[dict]) -> bool:
    return any(r["min"].startswith("ram:") and addr(r["min"]) <= value <= addr(r["max_inclusive"]) for r in ranges)


def main() -> None:
    raw = (ROOT / "local/extracted/SLPM_664.52").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError("Original ELF changed")
    manifest = json.loads((SOURCE / "manifest.json").read_text())
    if manifest["status"] != "export_completed" or manifest["source_sha256"] != SHA:
        raise ValueError("A completed matching Ghidra export is required")
    functions = {}
    with (SOURCE / "functions.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["entry"].startswith("ram:") and row["external"] == "false":
                row["ranges"] = json.loads(row["body_ranges_json"])
                functions[addr(row["entry"])] = row
    primary = {addr(row["requested_address"]) for row in manifest["selected"] if row["status"] == "existing_function"}
    reusable = {}
    for directory in (ROOT / "analysis/ghidra").iterdir():
        if not directory.is_dir() or not (directory / "manifest.json").exists():
            continue
        other = json.loads((directory / "manifest.json").read_text(encoding="utf-8-sig"))
        if other.get("source_sha256") != SHA or other.get("status") != "export_completed":
            continue
        for selected in other.get("selected", []):
            if selected.get("decompilation_status") == "completed" and selected.get("file"):
                reusable[addr(selected["requested_address"])] = directory / selected["file"]
    edges, unknown, required = [], [], set()
    for selected in manifest["selected"]:
        if not selected.get("file"):
            continue
        path = SOURCE / selected["file"]
        item = json.loads(path.read_text())
        caller = addr(item["function"]["entry"])
        for unit in item["disassembly"]["units"]:
            if unit.get("kind") != "instruction":
                continue
            flow = unit["flow_type"]
            if "CALL" not in flow and "JUMP" not in flow:
                continue
            off = unit.get("canonical_elf_file_offset")
            if off is None or not unit.get("matches_original_elf") or bytes.fromhex(unit["raw_hex"]) != raw[off:off + unit["length"]]:
                raise ValueError("Flow instruction bytes do not match the original ELF")
            destinations = [addr(v) for v in unit.get("flows", []) if v.startswith("ram:")]
            if not destinations and "COMPUTED" in flow:
                unknown.append({"caller": f"0x{caller:08x}", "site": unit["address"], "flow_type": flow, "reason": "computed-flow-without-resolved-target"})
            for target in destinations:
                if "JUMP" in flow and inside(target, item["function"]["body_ranges"]):
                    continue
                edge = {"caller": f"0x{caller:08x}", "site": unit["address"], "raw_hex": unit["raw_hex"],
                        "target": f"0x{target:08x}", "kind": "call" if "CALL" in flow else "outside-body-jump-candidate",
                        "source_file": str(path.relative_to(ROOT)), "source_file_sha256": hashed(path)}
                if target in functions:
                    edge["target_status"] = "exact-existing-function-entry"
                    required.add(target)
                else:
                    edge["target_status"] = "no-function-at-target"
                    edge["containing_entries"] = [row["entry"] for row in functions.values() if inside(target, row["ranges"])]
                    unknown.append(edge)
                edges.append(edge)
    explicit_core = {0x1fdb50, 0x1fda0c, 0x1fc524}
    if not explicit_core <= functions.keys():
        raise ValueError("Requested core dependency is not an exact existing function entry")
    observed_required = set(required)
    required |= explicit_core
    fresh = sorted(required - primary - reusable.keys())
    reused = [{"entry": f"0x{a:08x}", "file": str(reusable[a].relative_to(ROOT)), "sha256": hashed(reusable[a])} for a in sorted(required - primary) if a in reusable]
    applied = json.loads((ROOT / "analysis/ghidra/vm-seed-apply-v1/manifest.json").read_text())
    conflicts = []
    for row in applied["outcomes"]:
        if row["status"] != "conflict_body_overlaps_function":
            continue
        overlapping = []
        for part in row["inferred_body"]:
            lo, hi = addr(part["start"]), addr(part["end_inclusive"])
            for function in functions.values():
                for r in function["ranges"]:
                    rlo, rhi = addr(r["min"]), addr(r["max_inclusive"])
                    if max(lo, rlo) <= min(hi, rhi):
                        overlapping.append({"owner_entry": function["entry"], "owner_name": function["name"],
                                            "overlap_start": f"0x{max(lo,rlo):08x}", "overlap_end": f"0x{min(hi,rhi):08x}"})
        conflicts.append({"entry": row["entry"], "class_id": row["class_id"], "slot": row["slot"], "overlaps": overlapping})
    output = {"schema": 1, "elf_sha256": SHA, "selection_policy": "one-hop actual byte-matched Ghidra flow targets plus three explicitly requested core dependencies; exact existing entries only; not transitive closure",
              "counts": {"primary_completed": len(primary), "observed_edges": len(edges), "exact_dependency_entries": len(required),
                         "already_primary": len(required & primary), "reused_exports": len(reused), "new_export_entries": len(fresh),
                         "unresolved_flow_records": len(unknown), "seed_body_conflicts": len(conflicts)},
              "explicit_core_dependencies": [{"entry": f"0x{a:08x}", "also_observed_from_primary": a in observed_required} for a in sorted(explicit_core)],
              "observed_edges": edges, "reused_exports": reused, "unresolved": unknown, "seed_conflicts_with_owners": conflicts}
    anchors = {"schema": 1, "elf_sha256": SHA, "language_id": "r5900:LE:32:default",
               "anchors": [{"address": f"{a:08x}", "role": "VM primary observed call/outside-body-jump dependency" if a in observed_required else "explicitly requested core standard-library dependency",
                            "entry_confidence": "exact existing Ghidra function entry; incoming edge provenance is recorded separately",
                            "creation_candidate": False, "evidence": [str((OUTPUT / "selection.json").relative_to(ROOT))]} for a in fresh]}
    OUTPUT.mkdir(exist_ok=False)
    for name, value in (("selection.json", output), ("anchors.json", anchors)):
        (OUTPUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "counts": output["counts"]}))


if __name__ == "__main__":
    main()
