"""Compile the public Windows translation units for the local final link."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ['-std=c++20', '-target', 'x86_64-windows-gnu', '-O2', '-g',
         '-fno-fast-math', '-ffp-contract=off', '-DUNICODE', '-D_UNICODE']

def public_dependencies(path, seen):
    if path in seen:
        return True
    seen.add(path)
    if not path.is_file():
        return False
    includes = re.findall(r'^\s*#\s*include\s+"([^"]+)"', path.read_text(encoding='utf-8-sig'), re.M)
    return all(public_dependencies((path.parent / item).resolve(), seen) for item in includes)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    inputs = json.loads((ROOT/'local-build-inputs.json').read_bytes())
    objects = {}
    for name in inputs['sources']:
        path = ROOT/name
        if not public_dependencies(path.resolve(), set()):
            continue
        obj = args.output/(path.stem+'.obj')
        subprocess.run([args.zig.resolve(), 'c++', *FLAGS, '-c', path, '-o', obj], check=True)
        objects[name] = hashlib.sha256(obj.read_bytes()).hexdigest()
    if not {'port/core/story_frame.cpp','port/platform/windows/story_text_layout.cpp'} <= objects.keys():
        raise RuntimeError('Gameplay modules missing from public build')
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    (args.output/'objects.json').write_text(json.dumps({'revision':revision,'objects':objects},indent=2))
    subprocess.run([args.zig.resolve(),'c++',*FLAGS,'-municode','-Wl,--subsystem,windows',
                    ROOT/'port/platform/windows/portable_launcher.cpp','-luser32','-o',args.output/'MikazukiX3.exe'],check=True)

if __name__ == '__main__':
    main()
