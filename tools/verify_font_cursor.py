"""Build the recovered 16C540 leaf and compare persistent RAM to original R5900 execution."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "analysis/ghidra/oracle-font-pointer-v1"
SOURCES = ("port/core/font_cursor.cpp", "port/tests/font_cursor_probe.cpp")
HEADERS = ("port/core/font_cursor.hpp", "port/core/guest_memory.hpp")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def patch(image, region):
    start = int(region["address"], 16)
    data = bytes.fromhex(region["hex"])
    check(0 <= start <= len(image) - len(data), "Region outside guest RAM")
    image[start:start + len(data)] = data


def main():
    manifest_bytes = (ORACLE / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    plan_bytes = (ORACLE / "input-plan.json").read_bytes()
    cases_bytes = (ORACLE / "cases.jsonl").read_bytes()
    check(manifest["status"] == "oracle_completed", "Incomplete original oracle")
    check(digest(cases_bytes) == manifest["cases_sha256"], "Changed oracle case")
    check(digest(plan_bytes) == manifest["source_plan_sha256"], "Changed oracle plan")
    plan = json.loads(plan_bytes)
    check(digest((ROOT / "local/extracted/SLPM_664.52").read_bytes()) == manifest["source_elf_sha256"],
          "Changed original ELF")
    check(digest((ORACLE / "EmulateKamaitachiControlTransfer.java").read_bytes()) == manifest["harness_sha256"],
          "Changed original-instruction harness")
    ram = Path(plan["ram_input_path"]).read_bytes()
    check(digest(ram) == plan["ram_sha256"] == manifest["source_ram_sha256"], "Changed original RAM")
    cases = [json.loads(line) for line in cases_bytes.splitlines()]
    check(len(cases) == manifest["case_count"] == manifest["returned_count"] == len(plan["cases"]) > 0,
          "Missing returning oracle cases")

    toolchain = ROOT / "local/dependencies/ps2recomp/_evaluation"
    compiler = toolchain / "toolchain/zig-x86_64-windows-0.15.2/zig.exe"
    out_dir = ROOT / "local/pc-core/font-cursor-verify"
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = out_dir / "font_cursor_probe.exe"
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(toolchain / "zig-global-cache"),
               ZIG_LOCAL_CACHE_DIR=str(out_dir / "zig-cache"))
    def source_hashes():
        return {path: digest((ROOT / path).read_bytes()) for path in SOURCES + HEADERS}
    hashes = source_hashes()
    flags = ["c++", "-std=c++20", "-target", "x86_64-windows-gnu", "-O2", "-g"]
    subprocess.run([str(compiler), *flags, *SOURCES, "-o", str(exe)], cwd=ROOT, env=env, check=True, timeout=180)
    checks = []
    for case, expected_case in zip(cases, plan["cases"]):
        check(case["id"] == expected_case["id"] and case["input"] == expected_case["input"] and
              int(case["function_address"], 16) == 0x16c540 and case["status"] == "returned", "Wrong case")
        before = bytearray(ram)
        for region in case["input"]["memory"]:
            patch(before, region)
        expected = bytearray(before)
        for region in case["tracked_writes"]:
            check(region["role"] in ("persistent", "stack"), "Unclassified original store")
            if region["role"] == "persistent":
                patch(expected, region)
        reference_bytes = 0
        for region in case["output"]["memory"]:
            if region["name"] != "stack":
                start = int(region["address"], 16)
                evidence = bytes.fromhex(region["hex"])
                check(evidence == expected[start:start + len(evidence)], "Oracle window and writes disagree")
                reference_bytes += len(evidence)
        result = subprocess.run([str(exe), case["input"]["registers"]["a0"]], input=before,
                                capture_output=True, check=True, timeout=30)
        check(result.stdout == expected, "Native persistent RAM differs from instruction oracle")
        checks.append(dict(id=case["id"], source_steps=case["steps"], oracle_window_bytes=reference_bytes,
                           full_ram_bytes=len(expected), expected_ram_sha256=digest(expected),
                           actual_ram_sha256=digest(result.stdout)))
    check(hashes == source_hashes(), "Sources changed during verification")
    now = datetime.now(timezone.utc)
    report = dict(status="passed", verified_utc=now.isoformat(), function_address="0x0016C540",
                  oracle=str(ORACLE.relative_to(ROOT)), oracle_manifest_sha256=digest(manifest_bytes),
                  source_elf_sha256=manifest["source_elf_sha256"], source_hashes=hashes,
                  compiler_sha256=digest(compiler.read_bytes()), flags=flags,
                  executable_sha256=digest(exe.read_bytes()), cases=checks,
                  comparison="Complete RAM. Original ABI stack stores excluded when constructing expected image.")
    output = ROOT / "analysis/native-core" / f"font-cursor-differential-{now:%Y%m%d-%H%M%S}.json"
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(status=report["status"], cases=checks, report=str(output.relative_to(ROOT)))))


if __name__ == "__main__":
    main()
