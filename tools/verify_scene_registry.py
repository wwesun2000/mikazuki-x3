"""Compare all resident SPKs and both indexes to original 101420 and sampled retail RAM."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return sha256(raw).hexdigest()


def main():
    manifest_path=ROOT/"analysis/ghidra/oracle-cold-scene-registry-v1/manifest.json"
    manifest=json.loads(manifest_path.read_text())
    check(manifest["status"]=="oracle_completed" and manifest["source_entry"]=="0x00101420","Incomplete oracle")
    check(sha((ROOT/"local/extracted/SLPM_664.52").read_bytes())==manifest["source_elf_sha256"],"Different ELF")
    check(sha((ROOT/"tools/ghidra/EmulateKamaitachiSceneRegistry.java").read_bytes())==manifest["harness_sha256"],
          "Different reference harness")
    units=["port/core/scene_registry.cpp","port/tests/scene_registry_probe.cpp"]
    inputs=units+["port/core/scene_registry.hpp","port/core/guest_memory.hpp"]
    def hashes():
        return {p:sha((ROOT/p).read_bytes()) for p in inputs}
    before=hashes()
    toolchain=ROOT/"local/dependencies/ps2recomp/_evaluation"
    compiler=toolchain/"toolchain/zig-x86_64-windows-0.15.2/zig.exe"
    out=ROOT/"local/pc-core/scene-registry-verify"
    out.mkdir(parents=True,exist_ok=True)
    exe=out/"scene_registry_probe.exe"
    flags=["c++","-std=c++20","-target","x86_64-windows-gnu","-O2","-g"]
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(toolchain/"zig-global-cache"),ZIG_LOCAL_CACHE_DIR=str(out/"zig-cache"))
    subprocess.run([str(compiler),*flags,*units,"-o",str(exe)],cwd=ROOT,env=env,check=True,timeout=180)
    def probe(spk,registry,base,table,capacity):
        raw=subprocess.run([str(exe),*map(str,(registry,base,table,capacity)),"--provider"],input=spk,capture_output=True,
                           timeout=30,check=True).stdout
        return raw[:144],raw[144:144+len(spk)],raw[144+len(spk):]
    comparisons=[]
    check([r["program"] for r in manifest["programs"]]==["sn2","sn4","sn4g"],"Missing original program")
    for row in manifest["programs"]:
        name=row["program"]
        spk=(ROOT/f"local/assets/SCENARIO/{name}.spk").read_bytes()
        check(sha(spk)==row["source_sha256"],"Different original SPK")
        registry,resident,table=probe(spk,manifest["registry"],manifest["file_base"],
                                      manifest["cue_table"],row["cue_table_bytes"])
        check((sha(registry),sha(resident),sha(table)) ==
              (row["registry_sha256"],row["resident_sha256"],row["cue_table_sha256"]),f"{name}: divergence")
        comparisons.append(dict(program=name,block_count=struct.unpack_from("<I",registry,0x84)[0],
                                cue_count=len(table)//4,compared_bytes=len(registry)+len(resident)+len(table)))
    ram=(ROOT/"local/ghidra-oracle-inputs/choice-slot7-ee.bin").read_bytes()
    check(sha(ram)=="acc9bf38c3ce3b4d8a4a375f2851425a4bde549881614b40214a474a2e61550c","Different live sample")
    def word(at):
        return struct.unpack_from("<I",ram,at)[0]
    registry=word(word(0x23daf0-0x7bf4)+4)
    base,table=word(registry),word(registry+0x8c)
    capacity=4*word(registry+0x88)
    spk=(ROOT/"local/assets/SCENARIO/sn4g.spk").read_bytes()
    captures=probe(spk,registry,base,table,capacity)
    sampled=[]
    for field,at,data in zip(("registry","resident","cue_table"),(registry,base,table),captures):
        observed=ram[at:at+len(data)]
        check(observed==data,f"Retail slot7 differs in {field} at {at:#x}")
        sampled.append(dict(field=field,address=hex(at),bytes=len(data),sha256=sha(data)))
    check(before==hashes(),"Sources changed during test")
    report=dict(status="passed",source_elf_sha256=manifest["source_elf_sha256"],oracle=str(manifest_path.relative_to(ROOT)),
                oracle_sha256=sha(manifest_path.read_bytes()),native_sources=before,compiler_sha256=sha(compiler.read_bytes()),
                flags=flags,probe_sha256=sha(exe.read_bytes()),programs=comparisons,retail_slot7=sampled,
                retail_slot7_ram_sha256=sha(ram))
    now=datetime.now(timezone.utc)
    path=ROOT/"analysis/native-core"/f"scene-registry-differential-{now:%Y%m%d-%H%M%S}.json"
    with path.open("x",encoding="utf-8") as stream:
        stream.write(json.dumps(report,indent=2)+"\n")
    print(json.dumps(dict(status=report["status"],programs=comparisons,receipt=str(path.relative_to(ROOT)))))


if __name__=="__main__":
    main()
