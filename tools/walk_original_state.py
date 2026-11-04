"""Invoke recovered C++ context methods on a verified original RAM fixture.

Development evidence only: does not emulate the CPU, run GS/audio, or claim a
complete game frame. Entire RAM travels over stdin; no new 32 MiB dump on disk.
Python 3.14 is needed for the existing PCSX2 ZIP/ZSTD evidence files.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
import uuid
import zipfile
from inspect_pcsx2_states import elf_sections, ELF_SHA

ROOT=Path(__file__).resolve().parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--slot',type=int,required=True)
    parser.add_argument('--steps',type=int,default=100)
    args=parser.parse_args()
    if args.slot not in range(1,8) or not 0<args.steps<=10000:
        raise ValueError('Invalid bounded observation test parameters')
    evidence=ROOT/'analysis/observations/OBS-001/state-analysis/report.json'
    report=json.loads(evidence.read_text(encoding='utf-8'))
    state=next(s for s in report['states'] if s['slot']==args.slot)
    archive_path=ROOT/state['archive']
    if sha(archive_path.read_bytes())!=state['archive_sha256']:
        raise ValueError('Observation archive changed')
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if sha(elf)!=ELF_SHA: raise ValueError('Original executable identity mismatch')
    with zipfile.ZipFile(archive_path) as archive:
        if archive.getinfo('eeMemory.bin').file_size!=32*1024*1024:
            raise ValueError('Unexpected original RAM size')
        ram=archive.read('eeMemory.bin')
    section=next(s for s in elf_sections(elf) if s['name']=='.text')
    if ram[section['address']:section['address']+section['size']]!=elf[section['offset']:section['offset']+section['size']]:
        raise ValueError('Original snapshot code differs from decompiled source')
    build=json.loads((ROOT/'local/pc-core/core_probe.build.json').read_text())
    walker=ROOT/'local/pc-core/core_walk.exe'
    if sha(walker.read_bytes())!=build['walker_sha256']:
        raise ValueError('Walker build identity mismatch')
    if any(sha(Path(p).read_bytes())!=h for p,h in build['sources'].items()):
        raise ValueError('Core sources changed since build')
    manager=struct.unpack_from('<I',ram,0x235e40)[0]
    payload=b'KX3W'+struct.pack('<III',1,manager,args.steps)+ram
    child=subprocess.run([str(walker)],input=payload,capture_output=True,timeout=120,
                         creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    rows=[json.loads(line) for line in child.stdout.decode('utf-8').splitlines()]
    result=dict(schema=1,kind='original-state-native-context-experiment',slot=args.slot,
                archive_sha256=state['archive_sha256'],elf_sha256=ELF_SHA,ram_sha256=sha(ram),
                walker_sha256=build['walker_sha256'],build=build,exit_code=child.returncode,
                trace=rows,stderr=child.stderr.decode('utf-8',errors='replace'),
                limitations=['Calls context step only; no main-tick input/graphics/audio processing.',
                             'Snapshot is a test fixture, not a dependency of the intended port or its save format.'])
    output=ROOT/'analysis/native-core'/f'walk-slot{args.slot}-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:6]}.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(output),exit_code=child.returncode,trace=rows,stderr=result['stderr']),ensure_ascii=False))
    return 0 if child.returncode in (0,3,5) else child.returncode

if __name__=='__main__': raise SystemExit(main())
