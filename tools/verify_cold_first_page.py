"""Compare the complete first default-context call to R5900 execution on identical cold RAM."""
import hashlib
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
RAM_SIZE = 32 * 1024 * 1024
ELF = ROOT / 'local/extracted/SLPM_664.52'
EXT = ROOT / 'local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC/Ghidra/Extensions/ghidra-emotionengine-reloaded'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def word(data, address):
    return struct.unpack_from('<I', data, address)[0]


def difference(actual, expected):
    # Bound the report size while retaining the total divergent byte count.
    runs = []
    count = 0
    for page in range(0, RAM_SIZE, 4096):
        a, b = actual[page:page+4096], expected[page:page+4096]
        if a == b:
            continue
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                count += 1
                if len(runs) < 32:
                    runs.append(dict(address=hex(page + i), native=x, source=y))
    return dict(differing_bytes=count, first_differences=runs)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--project-location',type=Path,default=ROOT/'local/ghidra-projects')
    args=parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid4().hex[:6]
    build_path = ROOT / 'local/pc-core/manager_bootstrap_probe.build.json'
    build_bytes = build_path.read_bytes()
    build = json.loads(build_bytes)
    exe = Path(build['output'])
    def verify_build():
        check(sha(exe.read_bytes()) == build['output_sha256'] and build_path.read_bytes() == build_bytes,
              'Native executable or its build manifest changed during verification')
    verify_build()
    elf_sha = sha(ELF.read_bytes())
    check(elf_sha == '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160', 'Unexpected source ELF')
    oracle_dir = ROOT / 'analysis/ghidra' / ('oracle-cold-page-' + stamp)
    result_path = ROOT / 'analysis/native-core' / ('cold-page-differential-' + stamp + '.json')
    archive = json.loads((ROOT / 'analysis/fad_manifest.json').read_bytes())
    disc = next(a for a in archive['archives'] if a['name']=='DISC.FAD')
    entries = {r['path']: r['sha256'] for r in disc['records'] if r['kind']=='file'}
    with tempfile.TemporaryDirectory(dir=ROOT/'local/pc-core') as scratch:
        scratch = Path(scratch)
        plan, native = [], {}
        for program in ('sn2', 'sn4', 'sn4g'):
            script = ROOT / f'local/assets/SCENARIO/{program}.sn4'
            sources = {}
            for p in (script, script.with_suffix('.fnt')):
                asset = p.relative_to(ROOT / 'local/assets').as_posix()
                sources[asset] = sha(p.read_bytes())
                check(sources[asset] == entries[asset], 'Source differs from FAD manifest')
            for fill in (0, 165):
                case = f'{program}-{fill}'
                before, after = scratch / (case+'-before.bin'), scratch / (case+'-after.bin')
                run = subprocess.run([str(exe),str(ELF),str(script),str(fill),str(before),str(after)],
                                     capture_output=True, text=True, timeout=60, check=True)
                cold = json.loads(run.stdout)
                pre = before.read_bytes()
                check(len(pre)==RAM_SIZE and after.stat().st_size==RAM_SIZE, 'Invalid probe snapshot')
                plan.append(dict(id=case, pre_path=str(before), pre_sha256=sha(pre), heap_fill=fill,
                                 source_files=sources))
                native[case] = cold
        pp = scratch/'plan.json'
        pp.write_text(json.dumps(dict(schema=1, elf_sha256=elf_sha, cases=plan), indent=2))
        command = [sys.executable, str(ROOT/'tools/run_ghidra_analysis.py'), '--process',
                   '--project-location',str(args.project_location),
                   '--post-script','EmulateKamaitachiColdPage.java','--script-args',str(oracle_dir),
                   str(ELF),str(pp),str(EXT),'--timeout','180']
        child = subprocess.run(command, cwd=ROOT)
        oracle_file = oracle_dir / 'manifest.json'
        check(oracle_file.is_file(), 'Missing Ghidra manifest at '+str(oracle_dir))
        oracle = json.loads(oracle_file.read_bytes())
        check(oracle['plan_sha256']==sha(pp.read_bytes()) and oracle['elf_sha256']==elf_sha,'Oracle inputs changed')
        check([c['id'] for c in oracle['cases']]==list(native),'Incomplete oracle case set')
        output = []
        for src, seed in zip(oracle['cases'], plan):
            case = src['id']
            cpp = native[case]
            row = dict(id=case, source_files=seed['source_files'], native=cpp, steps=src['steps'], passed=False)
            if src['status'] != 'returned':
                row['source_error'] = src.get('reason')
            else:
                expected = bytearray(Path(seed['pre_path']).read_bytes())
                check(sha(expected)==src['input_sha256']==seed['pre_sha256'],'Cold input changed')
                for write in src['persistent_writes']:
                    a, n = write['address'], write['size']
                    data=bytes.fromhex(write['hex'])
                    check(0<=a<=RAM_SIZE-n and len(data)==n,'Invalid persistent source write')
                    expected[a:a+n]=data
                check(sha(expected)==src['persistent_ram_sha256'],'Untracked original persistent write')
                actual = (scratch/(case+'-after.bin')).read_bytes()
                script = cpp['script']
                row.update(native_ram_sha256=sha(actual), source_ram_sha256=src['persistent_ram_sha256'],
                           source_return=src['return_v0_u64'], source_cursor=src['cursor_after'],
                           changed_regions=len(src['persistent_writes']),
                           observed_source_write_bytes=sum(w['size'] for w in src['persistent_writes']),
                           source_selector=src['selector_after'], source_label=src['label_after'])
                row['passed'] = (cpp['first_opcode_completed'] and row['native_ram_sha256']==row['source_ram_sha256']
                                 and cpp['first_result']==int(src['return_v0_u64'])
                                 and cpp['final_cursor']==word(actual,script+0xd8)==src['cursor_after']
                                 and word(actual,script+0xd0)==src['selector_after']
                                 and word(actual,script+0xd4)==src['label_after'])
                if not row['passed']:
                    row.update(difference(actual,expected))
            output.append(row)
        verify_build()
        report = dict(schema=1, status='passed' if child.returncode==0 and all(r['passed'] for r in output) else 'failed',
                      native_build=build, native_build_sha256=sha(build_bytes), elf_sha256=elf_sha,
                      oracle=oracle_file.relative_to(ROOT).as_posix(), oracle_sha256=sha(oracle_file.read_bytes()),
                      verifier_sha256=sha(Path(__file__).read_bytes()), bytes_compared_per_return=RAM_SIZE,
                      scope='Same C++-constructed from-file cold RAM for both executions; Ghidra executes original default context until return. Only exact source CPU-stack writes are normalized to their original bytes.',
                      results=output)
        result_path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(report=str(result_path),status=report['status'],
                              cases=[(r['id'],r['passed'],r.get('first_differences',[])[:2],r.get('source_error')) for r in output])))
        return int(report['status']!='passed')


if __name__ == '__main__':
    raise SystemExit(main())
