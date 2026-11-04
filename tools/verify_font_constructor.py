"""Build the C++ constructor, compare complete native RAM with the R5900 source oracle."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT/'local/dependencies/ps2recomp/_evaluation'
CORE = ROOT/'port/core'
OUT = ROOT/'local/pc-core/font-constructor'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    source = ROOT/'local/extracted/SLPM_664.52'
    oracle_path = ROOT/'analysis/ghidra/oracle-font-constructor-v1/manifest.json'
    oracle = json.loads(oracle_path.read_bytes())
    if (oracle['status'] != 'oracle_completed' or oracle['source_elf_sha256'] != digest(source.read_bytes()) or
            oracle['harness_sha256'] != digest((ROOT/'tools/ghidra/EmulateKamaitachiFontConstructor.java').read_bytes())):
        raise RuntimeError('Original ELF or constructor oracle identity mismatch')
    OUT.mkdir(parents=True, exist_ok=True)
    compiler = TOOLCHAIN/'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    exe = OUT/'font_constructor_probe.exe'
    env = {**os.environ, 'ZIG_GLOBAL_CACHE_DIR': str(TOOLCHAIN/'zig-global-cache'),
           'ZIG_LOCAL_CACHE_DIR': str(OUT/'zig-cache')}
    test = ROOT/'port/tests/font_constructor_probe.cpp'
    sources = [*sorted(CORE.glob('*.cpp')), test]
    tracked = [*sources, *sorted(CORE.glob('*.hpp'))]
    def source_hashes():
        return {p.relative_to(ROOT).as_posix():digest(p.read_bytes()) for p in tracked}
    before = source_hashes()
    subprocess.run([str(compiler),'c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g',
                    '-fno-fast-math','-ffp-contract=off',*map(str,sources),'-o',str(exe)],
                   cwd=ROOT,env=env,check=True,timeout=240)
    rows = []
    if [(c['program'],c['fill']) for c in oracle['cases']] != [
            (game,fill) for game in ('sn2','sn4','sn4g') for fill in (0,165)]:
        raise RuntimeError('Unexpected constructor coverage')
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        result = Path(tmp)/'memory.bin'
        for case in oracle['cases']:
            file = ROOT/f"local/assets/SCENARIO/{case['program']}.fnt"
            if digest(file.read_bytes()) != case['source_file_sha256']:
                raise RuntimeError('Original font changed')
            probe = subprocess.run([str(exe),str(source),str(file),str(case['fill']),str(result)],
                                   capture_output=True,check=True,text=True,timeout=60)
            status = json.loads(probe.stdout)
            ram = result.read_bytes()
            if (len(ram) != 32*1024*1024 or digest(ram) != case['ram_without_abi_stack_sha256'] or
                    status['arena_used_end'] != case['arena_used_end'] or not status['rollback_matches']):
                raise RuntimeError(f"Source/native disagreement: {case['program']}, fill {case['fill']}, "
                                   f"arena hash {digest(ram[0x600000:0x640000])}, RAM hash {digest(ram)}")
            rows.append({**case, 'native_verified': True, 'native_rollback_verified': True})
    if before != source_hashes():
        raise RuntimeError('Native source changed during build or verification')
    now = datetime.now(timezone.utc)
    report = dict(status='passed', verified_utc=now.isoformat(), oracle=str(oracle_path.relative_to(ROOT)),
                  oracle_sha256=digest(oracle_path.read_bytes()), compiler_sha256=digest(compiler.read_bytes()),
                  native_sha256=digest(exe.read_bytes()), native_sources=before,
                  excluded=oracle['excluded'], cases=rows)
    path = ROOT/'analysis/native-core'/f'font-constructor-{now:%Y%m%d-%H%M%S}.json'
    with path.open('x',encoding='utf-8') as out:
        out.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'passed','cases':len(rows),'bytes_per_case':len(ram),'report':str(path)}))


if __name__ == '__main__':
    main()
