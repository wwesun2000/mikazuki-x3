"""Compare recovered C++ to actual Ghidra/SLEIGH state outputs, no formulas."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def sha(b):return hashlib.sha256(b).hexdigest()


def main():
    oracle=ROOT/(sys.argv[1] if len(sys.argv)>1 else 'analysis/ghidra/oracle-choice-transfer-scalar-v1')
    manifest=json.loads((oracle/'manifest.json').read_text())
    if manifest['status']!='oracle_completed':raise ValueError('Refuse failed oracle as expected values')
    plan=json.loads((oracle/'input-plan.json').read_text())
    if sha((oracle/'input-plan.json').read_bytes())!=manifest['source_plan_sha256']:raise ValueError('Plan hash mismatch')
    if sha((oracle/'cases.jsonl').read_bytes())!=manifest['cases_sha256']:raise ValueError('Oracle cases hash mismatch')
    source=ROOT/plan['archive']
    if sha(source.read_bytes())!=plan['archive_sha256']:raise ValueError('Original archive hash mismatch')
    with zipfile.ZipFile(source) as z:base=z.read('eeMemory.bin')
    if sha(base)!=manifest['source_ram_sha256']:raise ValueError('Original RAM hash mismatch')
    core=ROOT/'port/core'
    files=[p.relative_to(ROOT).as_posix() for p in sorted(core.glob('*.cpp'))]+['port/tests/choice_transfer_probe.cpp']
    headers=[p.relative_to(ROOT).as_posix() for p in sorted(core.glob('*.hpp'))]
    before={p:sha((ROOT/p).read_bytes()) for p in files+headers}
    compiler=ROOT/'local/dependencies/ps2recomp/_evaluation/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    exe=ROOT/'local/pc-core/choice_transfer_probe.exe'
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'local/dependencies/ps2recomp/_evaluation/zig-global-cache');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'local/pc-core/zig-local-cache-choice')
    flags=['c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-fno-fast-math','-ffp-contract=off']
    build=subprocess.run([str(compiler),*flags,*files,'-o',str(exe)],cwd=ROOT,env=env,capture_output=True,timeout=360)
    if build.returncode:raise RuntimeError(build.stderr.decode(errors='replace'))
    rows=[]
    for line in (oracle/'cases.jsonl').read_text().splitlines():
        case=json.loads(line)
        if case['status']!='returned':raise ValueError('Non-returned oracle case')
        image=bytearray(base)
        for p in case['input']['memory']:
            a=int(p['address'],16);b=bytes.fromhex(p['hex']);image[a:a+len(b)]=b
        outputs=[dict(r) for r in case['output']['memory'] if r['name']!='stack']
        # Also compare every observed persistent write, including any outside
        # the complete object windows; stack is a host ABI exclusion only.
        outputs.extend(dict(r,name='tracked-write') for r in case['tracked_writes'] if r['role']=='persistent')
        args=[str(exe),*[case['input']['registers'][r] for r in ['a0','a1','a2','a3']]]
        for r in outputs:args.extend([r['address'],str(len(bytes.fromhex(r['hex'])))])
        result=subprocess.run(args,input=image,cwd=ROOT,capture_output=True,timeout=15)
        offset=0;differences=[]
        for region in outputs:
            expected=bytes.fromhex(region['hex']);actual=result.stdout[offset:offset+len(expected)];offset+=len(expected)
            if actual!=expected:
                differing=[i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b]
                differences.append(dict(name=region['name'],address=region['address'],expected_size=len(expected),actual_size=len(actual),first_differences=differing[:16]))
        if len(result.stdout)!=offset:differences.append(dict(extra_output_bytes=len(result.stdout)-offset))
        rows.append(dict(id=case['id'],passed=result.returncode==0 and not differences,returncode=result.returncode,
                         compared_bytes=offset,original_steps=case['steps'],differences=differences,stderr=result.stderr.decode(errors='replace')))
    after={p:sha((ROOT/p).read_bytes()) for p in files+headers}
    if before!=after:raise ValueError('Source changed during build/test')
    report=dict(schema=1,status='passed' if all(r['passed'] for r in rows) else 'failed',
                oracle=str(oracle.relative_to(ROOT)),oracle_manifest_sha256=sha((oracle/'manifest.json').read_bytes()),
                cases=len(rows),passed=sum(r['passed'] for r in rows),source_sha256=before,
                compiler_sha256=sha(compiler.read_bytes()),flags=flags,executable_sha256=sha(exe.read_bytes()),rows=rows,
                comparison='All complete observed persistent object windows and every tracked persistent write; no expected values calculated in Python/C++',
                exclusions=['Temporary EE stack in reserved native guest RAM','v0, because10D868 has path-dependent incidental values and callers use it as void'],
                engine=manifest['engine'],string_alignment_adaptation=plan.get('string_alignment_adaptation',False),
                limitations=['Oracle is not PCSX2/hardware execution',
                             'Scalar family relocates previous-name bytes if declared in input plan; enhanced family adds separately audited MMI semantics, not original Ghidra support'])
    name='choice-transfer-scalar-diff.json' if plan.get('string_alignment_adaptation',False) else 'choice-transfer-diff.json'
    out=ROOT/'analysis/native-core'/name;out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(report=str(out),status=report['status'],cases=len(rows),passed=report['passed'],failed=[r for r in rows if not r['passed']])))
    if report['status']!='passed':raise SystemExit(1)


if __name__=='__main__':main()
