"""Compile and verify the ordinary choice context against original slot7 RAM.

Requires Python3.14 ZIP ZSTD support. Full EE RAM exists only in process memory
and subprocess stdin, never a new fixture file. This is a native contract test,
not a Ghidra/PCSX2 execution oracle.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA = '46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    core=ROOT/'port/core'
    sources=[p.relative_to(ROOT).as_posix() for p in sorted(core.glob('*.cpp'))]+['port/tests/choice_pipeline_test.cpp']
    headers=[p.relative_to(ROOT).as_posix() for p in sorted(core.glob('*.hpp'))]
    before = {p:sha((ROOT/p).read_bytes()) for p in sources+headers}
    elf = (ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if sha(elf) != ELF_SHA:
        raise ValueError('Original ELF changed')
    state = ROOT/'analysis/observations/OBS-001/pcsx2/sstates/SLPM-66452 (0D03C0A3).07.p2s'
    if sha(state.read_bytes()) != STATE_SHA:
        raise ValueError('Original slot7 archive changed')
    with zipfile.ZipFile(state) as archive:
        ram = archive.read('eeMemory.bin')
    if len(ram) != 32*1024*1024:
        raise ValueError('Unexpected EE memory size')
    if ram[0x100000:0x204b38] != elf[0x1000:0x105b38]:
        raise ValueError('Actual-state code does not match original ELF .text')
    compiler = ROOT/'local/dependencies/ps2recomp/_evaluation/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    exe = ROOT/'local/pc-core/choice_pipeline_test.exe'
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT/'local/dependencies/ps2recomp/_evaluation/zig-global-cache')
    env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT/'local/pc-core/zig-local-cache-choice')
    flags = ['c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g','-fno-fast-math','-ffp-contract=off']
    build = subprocess.run([str(compiler),*flags,*sources,'-o',str(exe)],cwd=ROOT,env=env,
                           capture_output=True,timeout=360)
    if build.returncode:
        raise RuntimeError(build.stderr.decode(errors='replace'))
    result = subprocess.run([str(exe)],input=ram,capture_output=True,cwd=ROOT,timeout=60)
    after = {p:sha((ROOT/p).read_bytes()) for p in sources+headers}
    if before != after:
        raise ValueError('Source changed during compilation/test')
    report = dict(schema=1,created_utc=datetime.datetime.now(datetime.UTC).isoformat(),
                  kind='native source-bound headless contract; not original-machine execution',
                  source_elf_sha256=ELF_SHA,source_state_sha256=STATE_SHA,
                  original_text_sha256=sha(ram[0x100000:0x204b38]),
                  no_new_ram_dump=True,compiler_sha256=sha(compiler.read_bytes()),
                  flags=flags,source_sha256=before,executable_sha256=sha(exe.read_bytes()),
                  returncode=result.returncode,stdout=result.stdout.decode(errors='replace'),
                  stderr=result.stderr.decode(errors='replace'),
                  limitations=['Input masks are scripted native test inputs, not newly observed PCSX2 interactions.',
                               'Logical glyph event/ready model only, no graphical frontend is implemented by this test.',
                               'Pending task effects are retained; the original GS callback rounding/rendering is not reproduced.',
                               'Normal10D868 transfer executes; full readback1165D8 is still required and unsupported source callbacks roll back.'])
    if result.returncode == 0:
        report['result'] = json.loads(result.stdout)
    name=Path(sys.argv[1]).name if len(sys.argv)>1 else 'choice-pipeline-slot7.json'
    output = ROOT/'analysis/native-core'/name
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(output),returncode=result.returncode,stdout=report['stdout'],stderr=report['stderr'])))
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
