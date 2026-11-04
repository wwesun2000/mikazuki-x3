"""Compare the native projection leaves with independently executed retail EE code."""
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "local/pc-core/screen-projection"
ELF = ROOT / "local/extracted/SLPM_664.52"
ORACLE = ROOT / "analysis/ghidra/oracle-screen-projection-v1/manifest.json"
VU = ROOT / "analysis/ghidra/oracle-screen-projection-vu-v1"

def bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]

def number(word):
    return struct.unpack("<f", struct.pack("<I", word))[0]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def prepare_vu():
    # Reuse the independently implemented VU micro-op white list and original
    # slot-7 RAM fixture. Only the angle, output buffer and registers are inputs.
    base=ROOT/"analysis/ghidra"
    plan=json.loads((base/"oracle-screen-transition-plan.json").read_bytes())
    dest=0x360100
    angles=[i*math.pi/180 for i in range(-180,181,10)]+[-.5,.5,-.0001,.0001,-0.0]
    plan.update(case_kind="Original finite angle screen projections from 1925F8",
                observed_regions=[dict(name="homogeneous-point",address=hex(dest),size=16)],cases=[])
    for i,a in enumerate(angles):
        plan["cases"].append(dict(id=f"angle-{i:02}",function_address="0x1925f8",return_defined=False,
            input=dict(registers=dict(a0=hex(dest),a1="0",a2="0",a3="0",f12=hex(bits(a)),fcsr="0"),
                       memory=[dict(address=hex(dest),hex="a5"*16,reason="Only output xy is consumed by 192478 and the four screen meshes")])))
    (base/"oracle-screen-projection-vu-plan.json").write_text(json.dumps(plan,indent=2)+"\n",encoding="utf-8")

def main():
    e = json.loads(ORACLE.read_text(encoding="utf-8"))
    assert e["elf_sha256"] == sha(ELF) and e["status"] == "oracle_completed"
    assert e["original_tangent_bits"] == 0x3fddb3d8
    OUT.mkdir(parents=True, exist_ok=True)
    kit=ROOT/"local/dependencies/ps2recomp/_evaluation"
    exe=OUT/"screen_projection_probe.exe"
    src=[ROOT/"port/tests/screen_projection_probe.cpp", ROOT/"port/core/screen_projection.cpp"]
    subprocess.run([kit/"toolchain/zig-x86_64-windows-0.15.2/zig.exe","c++","-std=c++20","-O2",
                    "-o",exe,*src],check=True,cwd=ROOT,env=dict(os.environ,
                    ZIG_LOCAL_CACHE_DIR=str(OUT/"zig-cache"),ZIG_GLOBAL_CACHE_DIR=str(kit/"zig-global-cache")))
    cases=[("c",bits(x),bits(y)) for x,y,*_ in e["clip"]]
    cases += [("s",bits(angle),bits(y)) for angle,y,_ in e["sectors"]]
    angles=[i*math.pi/180 for i in range(-180,181)]
    cases += [("p",bits(angle),0) for angle in angles]
    lines=subprocess.run([exe,ELF],input="".join(f"{k} {a} {b}\n" for k,a,b in cases),capture_output=True,
                         check=True,text=True).stdout.splitlines()
    assert len(lines)==len(cases)
    for index,(_,_,x,y) in enumerate(e["clip"]):
        assert list(map(int,lines[index].split()))==[bits(x),bits(y)],("clip",index,lines[index],x,y)
    cut=len(e["clip"])
    for line,(_,_,sector) in zip(lines[cut:],e["sectors"]):
        assert int(line)==sector
    sweep=[]
    for angle,line in zip(angles,lines[cut+len(e["sectors"]):]):
        x,y,sector=map(int,line.split());px,py=number(x),number(y)
        assert 0<=px<=640 and 0<=py<=224 and (px in (0,640) or py in (0,224))
        sweep.append([bits(angle),x,y,sector])
    result=dict(source_elf_sha256=e["elf_sha256"],oracle_sha256=sha(ORACLE),
                source_sha256={str(p.relative_to(ROOT)):sha(p) for p in src},executable_sha256=sha(exe),
                matched_native_original_clip=len(e["clip"]),matched_native_original_sector=len(e["sectors"]),
                original_tangent_bits=e["original_tangent_bits"],native_angle_sweep=sweep,
                note="Full angular sweep here validates screen bounds only. Nonzero VU matrix coordinates require the separate geometry oracle.")
    if (VU/"manifest.json").exists():
        manifest=json.loads((VU/"manifest.json").read_text(encoding="utf-8"))
        original=[json.loads(line) for line in (VU/"cases.jsonl").read_text(encoding="utf-8").splitlines()]
        assert manifest["returned_count"]==manifest["case_count"]==len(original) and not manifest["failed"]
        inputs=[int(case["input"]["registers"]["f12"],16) for case in original]
        native=subprocess.run([exe,ELF],input="".join(f"p {a} 0\n" for a in inputs),text=True,check=True,capture_output=True)
        checked=0
        for case,line in zip(original,native.stdout.splitlines(),strict=True):
            observed=case["output"]["memory"][0]
            assert observed["name"]=="homogeneous-point" and case["status"]=="returned"
            x,y=struct.unpack_from("<II",bytes.fromhex(observed["hex"]))
            xx,yy,_=map(int,line.split());assert (x,y)==(xx,yy),(case["id"],hex(x),hex(y),hex(xx),hex(yy))
            checked+=1
        result.update(matched_1925F8_original_projection_xy=checked,vu_oracle_sha256=sha(VU/"manifest.json"),
                      note="Finite R5900/VU projections use the documented bounded VU macro instruction semantics; the 361-point native sweep checks bounds only.")
    path=ROOT/"analysis/native-core/screen-projection.json"
    path.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(f"{cut} original clip XY pairs, {len(e['sectors'])} original sectors, {len(sweep)} native boundary points")

if __name__=="__main__":
    if sys.argv[1:]==["--prepare-vu"]:prepare_vu()
    else:main()
