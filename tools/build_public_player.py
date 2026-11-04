"""Build the Windows player from this tree and locally prepared generated inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True,
                        help='A local tree containing the relative paths from local-build-inputs.json.')
    parser.add_argument('--zig', type=Path, help='Path to Zig 0.15.2 (Windows x86-64).')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    manifest = json.loads((ROOT/'local-build-inputs.json').read_bytes())
    local = args.inputs.resolve()
    private = manifest['private_inputs']
    problems = []
    for name, expected in private.items():
        p = local/name
        if not p.is_file() or digest(p)!=expected:
            problems.append(name)
    if problems:
        raise SystemExit('Missing or mismatched local inputs:\n'+'\n'.join(problems))
    print(f'{len(private)} local compile inputs verified.', flush=True)
    if args.check_only:
        return
    if not args.zig or not args.zig.is_file():
        raise SystemExit('Supply --zig with a path to the Windows Zig compiler.')
    zig = args.zig.resolve()
    if subprocess.check_output([zig,'version'],text=True).strip()!='0.15.2':
        raise SystemExit('This build was tested with Zig 0.15.2.')
    dest = ROOT/'local/pc-core/player'
    dest.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='source-build-',dir=dest) as temp:
        work=Path(temp)
        shutil.copytree(ROOT/'port',work/'port')
        for name,expected in private.items():
            target=work/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(local/name,target)
            if digest(target)!=expected:
                raise ValueError(f'Input changed during build: {name}')
        output=work/'KamaitachiX3.exe'
        command=[str(zig),'c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-g',
                 '-I',str(work/'local/pc-core/player'),'-fno-fast-math','-ffp-contract=off',
                 '-DUNICODE','-D_UNICODE','-municode','-Wl,--subsystem,windows',
                 *manifest['sources'],*manifest['libraries'],'-o',str(output)]
        env=os.environ.copy()
        env.setdefault('ZIG_GLOBAL_CACHE_DIR',str(dest/'zig-global-cache'))
        env.setdefault('ZIG_LOCAL_CACHE_DIR',str(dest/'zig-cache'))
        subprocess.run(command,cwd=work,env=env,check=True)
        os.replace(output,dest/output.name)
    print('Built',dest/'KamaitachiX3.exe')

if __name__=='__main__':
    main()
