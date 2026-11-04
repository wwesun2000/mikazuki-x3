"""Differential original-state calls without duplicating whole-RAM fixtures on disk."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def number(value):return int(value,16) if isinstance(value,str) else value

def main():
    parser=argparse.ArgumentParser();parser.add_argument('oracle',type=Path)
    parser.add_argument('--build',type=Path,default=ROOT/'local/pc-core/core_probe.build.json')
    args=parser.parse_args()
    oracle=args.oracle.resolve()
    manifest=json.loads((oracle/'manifest.json').read_text())
    if manifest['status']!='oracle_completed':raise ValueError('Original oracle incomplete')
    plan=json.loads((oracle/'input-plan.json').read_text())
    ram=Path(plan['ram_input_path']).read_bytes()
    if len(ram)!=32*1024*1024 or sha(ram)!=plan['ram_sha256']:raise ValueError('Original RAM fixture changed')
    cases_path=oracle/'cases.jsonl';raw_cases=cases_path.read_bytes()
    if sha(raw_cases)!=manifest['cases_sha256']:raise ValueError('Oracle cases changed')
    build=json.loads(args.build.read_text())
    exe=Path(build['state_call_output'])
    if sha(exe.read_bytes())!=build['state_call_sha256']:raise ValueError('State-call probe changed')
    def stable():return all(sha(Path(p).read_bytes())==h for p,h in build['sources'].items())
    if not stable():raise ValueError('Sources changed after build')
    results=[]
    for line in raw_cases.splitlines():
        case=json.loads(line)
        if case['status']!='returned':raise ValueError('Nonreturning oracle case')
        memory=bytearray(ram)
        for patch in case['input']['memory']:
            start=number(patch['address']);raw=bytes.fromhex(patch['hex'])
            if not 0<=start<=len(memory)-len(raw):raise ValueError('Patch outside RAM')
            memory[start:start+len(raw)]=raw
        observed=[r for r in case['output']['memory'] if r['name']!='stack']
        # Every persistent source write is compared, including writes outside
        # the originally selected object windows. Duplicate observations are OK.
        observed += [r for r in case['tracked_writes'] if r['role']=='persistent']
        regs=case['input']['registers']
        payload=b'KX3C'+struct.pack('<IIIQQQI',1,number(case['function_address']),number(regs.get('a0',0))&0xffffffff,
            number(regs.get('a1',0))&0xffffffffffffffff,number(regs.get('a2',0))&0xffffffffffffffff,
            number(regs.get('a3',0))&0xffffffffffffffff,len(observed))
        payload+=b''.join(struct.pack('<II',number(r['address']),len(bytes.fromhex(r['hex']))) for r in observed)
        payload+=memory
        child=subprocess.run([str(exe)],input=payload,capture_output=True,timeout=60,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        differences=[];out=child.stdout
        if child.returncode or len(out)<16 or out[:8]!=b'KX3E\x01\x00\x00\x00':
            differences.append(dict(kind='probe_error',exit_code=child.returncode,error=child.stderr.decode(errors='replace')))
        else:
            if case.get('return_defined') and struct.unpack_from('<Q',out,8)[0]!=number(case['output']['registers']['v0']):
                differences.append(dict(kind='return_value'))
            pos=16
            for region in observed:
                expected=bytes.fromhex(region['hex']);actual=out[pos:pos+len(expected)];pos+=len(expected)
                if actual!=expected:
                    first=next((i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b),min(len(actual),len(expected)))
                    differences.append(dict(kind='memory',address=region['address'],first_difference=first))
            if pos!=len(out):differences.append(dict(kind='response_length'))
        results.append(dict(id=case['id'],function_address=case['function_address'],passed=not differences,differences=differences))
    if not results or not stable():raise ValueError('Empty cases or source changed during differential')
    passed=sum(r['passed'] for r in results)
    report=dict(schema=1,oracle=str(oracle),oracle_manifest=manifest,build=build,cases=len(results),passed=passed,
                all_passed=passed==len(results),results=results,exclusions=['Guest ABI stack; no persistent writes excluded'])
    path=ROOT/'analysis/native-core'/f'state-calls-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:6]}.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),cases=len(results),passed=passed,first_failures=[r for r in results if not r['passed']][:2])))
    return 0 if report['all_passed'] else 1

if __name__=='__main__':raise SystemExit(main())
