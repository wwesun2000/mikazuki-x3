"""Run the pinned upstream EE recompiler on the original boot ELF and build the selected native functions."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from datetime import datetime, timezone

from iso9660 import Iso9660

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT/'local/dependencies/ps2recomp'
EVAL = UPSTREAM/'_evaluation'
RESULTS = ROOT/'analysis/ps2recomp-pilot'
WORK = ROOT/'local/pc-core/ps2recomp-pilot'
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
ENTRIES = (0x184760, 0x179c68)
# Both .ctors entries tail-jump into earlier, contiguous blocks of their Ghidra bodies.
CONSTRUCTORS = (0x1b3d48,0x1b45e8)
# Upstream emits its registration unit even for an isolated function pilot.
BOOT_ENTRY = (0x1b4bb4,)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def record(path, data):
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')


def call(args, log, cwd, env=None):
    with log.open('wb') as output:
        result=subprocess.run(list(map(str,args)),cwd=cwd,env=env,stdout=output,
                              stderr=subprocess.STDOUT,timeout=300)
    if result.returncode:
        tail=log.read_text(encoding='utf-8',errors='replace').splitlines()[-8:]
        raise RuntimeError(f'{log.name}: exit {result.returncode}\n'+'\n'.join(tail))


def generate(iso_path,exe,*,entries=ENTRIES,work=WORK,callback_export=None,reviewed_switches=(),allow_padding=False,shared_returns=None,jump_tables=()):
    tool_receipt=json.loads((RESULTS/'build/receipt.json').read_bytes())
    if sha(exe)!=tool_receipt['exe_sha256']:
        raise ValueError('Generator differs from the recorded upstream build')
    run=work/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    run.mkdir(parents=True,exist_ok=False)
    image_proof=json.loads((ROOT/'analysis/iso_manifest.json').read_bytes())['source']
    with Iso9660(iso_path) as iso:
        if iso.size!=image_proof['size'] or iso.sha256()!=image_proof['sha256']:
            raise ValueError('Unexpected disc image')
        files={r['path']:r for r in iso.inventory() if r['kind']=='file'}
        cnf=files['SYSTEM.CNF']
        boot=re.search(rb'(?im)^BOOT2\s*=\s*cdrom0:\\([^;\s]+);1',iso.read(cnf['offset'],cnf['size']))
        if not boot or boot[1]!=b'SLPM_664.52':
            raise ValueError('Unexpected boot entry in SYSTEM.CNF')
        extract=iso.extract(boot[1].decode('ascii'),run)
    elf=Path(extract['path'])
    if extract['sha256']!=ELF_SHA or sha(elf)!=ELF_SHA:
        raise ValueError('Original EE executable digest mismatch')

    coverage=json.loads((ROOT/'analysis/decompiled-ee/coverage.json').read_bytes())
    if coverage['elf_sha256']!=ELF_SHA:
        raise ValueError('Ghidra function boundaries belong to a different ELF')
    selected={}
    disc_bytes=elf.read_bytes()
    for shard in sorted((ROOT/'analysis/decompiled-ee').glob('shard-*.jsonl')):
        for line in shard.read_text(encoding='utf-8').splitlines():
            row=json.loads(line)
            address=int(row['entry'],16)
            if address not in entries+CONSTRUCTORS+BOOT_ENTRY:
                continue
            ranges=row['ranges']
            if shared_returns and address in shared_returns:
                tail=shared_returns[address]
                if tail not in entries or len(ranges)!=2:raise ValueError("Missing shared return")
                first,last=sorted(ranges,key=lambda r:int(r['start'],16)!=address)
                if int(first['start'],16)!=address:raise ValueError("Missing shared-return function entry")
                size=int(first['end_exclusive'],16)-address
                jump=struct.unpack_from('<I',disc_bytes,first['file_offset']+size-8)[0]
                if (int(last['start'],16)!=tail or int(last['end_exclusive'],16)!=tail+8 or
                    jump!=(0x08000000|(tail>>2)) or struct.unpack_from('<I',disc_bytes,last['file_offset'])[0]!=0x03e00008 or
                    row['body_bytes']!=size+8 or row['instruction_bytes']!=size+8):
                    raise ValueError("Unverified shared JR return")
                selected[tail]=dict(name=f'FUN_{tail:08x}',ranges=[last],instruction_bytes=8,body_bytes=8)
                ranges=[first]
                row=dict(row,ranges=ranges,body_bytes=size,instruction_bytes=size)
            if address in reviewed_switches:
                if callback_export is None or len(ranges)<=1:
                    raise ValueError(f'Expected a new switch-body export for {address:x}')
                continue
            if len(ranges)>1 and allow_padding:
                first=ranges[0]
                start=int(first['start'],16)
                end=int(first['end_exclusive'],16)
                for part in ranges[1:]:
                    at=int(part['start'],16)
                    gap=at-end
                    off=first['file_offset']+end-start
                    if gap!=4 or part['file_offset']!=off+gap or disc_bytes[off:off+gap]!=bytes(4):
                        raise ValueError(f'Unverified gap in {address:x} before {at:x}')
                    end=int(part['end_exclusive'],16)
                decoded=end-start-4*(len(ranges)-1)
                if row['instruction_bytes']!=decoded or row['body_bytes']!=decoded:raise ValueError("Incomplete decoded ranges")
                ranges=[dict(first,end_exclusive=hex(end))]
                row=dict(row,ranges=ranges,body_bytes=end-start,instruction_bytes=end-start)
            if address in selected or len(ranges)!=1:
                raise ValueError(f'Ambiguous function range at {address:x}')
            selected[address]=row
    if callback_export is not None:
        for address in set(entries)-selected.keys():
            evidence=callback_export[address] if isinstance(callback_export,dict) else callback_export
            proof=json.loads((evidence/'functions'/f'{address:08x}.json').read_bytes())
            f,asm=proof['function'],proof['disassembly']
            if (f['entry']!=f'ram:{address:08x}' or not f['body_ranges'] or not asm['complete'] or
                not all(u['kind']=='instruction' and u['matches_original_elf'] for u in asm['units'])):
                raise ValueError(f'Incomplete callback export at {address:x}')
            bounds=f['body_ranges'][0]
            offset=bounds['canonical_elf_file_offset']
            raw=bytearray()
            disk=elf.read_bytes()
            for unit in asm['units']:
                pc=int(unit['address'].split(':')[1],16)
                gap=pc-address-len(raw)
                if gap:
                    if address not in reviewed_switches or gap!=4 or any(disk[offset+len(raw):offset+len(raw)+gap]):
                        raise ValueError(f'Unverified hole before {pc:x}')
                    raw.extend(bytes(gap))
                raw.extend(bytes.fromhex(unit['raw_hex']))
            end=int(f['body_ranges'][-1]['max_inclusive'].split(':')[1],16)+1
            if len(raw)!=end-address or disk[offset:offset+len(raw)]!=raw:
                raise ValueError(f'Callback differs from mounted ISO at {address:x}')
            selected[address]=dict(name=f['name'],instruction_bytes=len(raw),body_bytes=len(raw),
                ranges=[dict(start=hex(address),end_exclusive=hex(address+len(raw)),file_offset=offset)])
    if set(selected)!=set(entries+CONSTRUCTORS+BOOT_ENTRY):
        raise ValueError('Missing function(s) in verified Ghidra address map')
    data=elf.read_bytes()
    if struct.unpack_from('<I',data,24)[0]!=BOOT_ENTRY[0]:
        raise ValueError('Original ELF entry point differs from registration entry')
    ghidra_map=run/'functions.csv'
    mapped={}
    with ghidra_map.open('w',newline='',encoding='ascii') as stream:
        writer=csv.writer(stream)
        writer.writerow(('Name','Start','End','Size'))
        for address in entries+CONSTRUCTORS+BOOT_ENTRY:
            row=selected[address]
            r=row['ranges'][0]
            start,end=int(r['start'],16),int(r['end_exclusive'],16)
            if row['instruction_bytes']!=end-start or row['body_bytes']!=end-start or not start<=address<end:
                raise ValueError('Incomplete original instruction coverage')
            parts=[(address,end,row['name'])]
            if start!=address:
                tail=int.from_bytes(data[r['file_offset']+end-start-8:r['file_offset']+end-start-4],'little')
                if address not in CONSTRUCTORS or tail>>26!=2 or (tail&0x3ffffff)*4!=start:
                    raise ValueError('Unverified backward tail jump in constructor')
                parts.append((start,address,f'ctor_tail_{start:08x}'))
            for entry,limit,name in parts:
                writer.writerow((name,hex(entry),hex(limit),limit-entry))
                mapped[entry]=(limit,name,r['file_offset']+entry-start)

    config=run/'recompile.toml'
    config.write_text('[general]\ninput="SLPM_664.52"\noutput="generated"\nghidra_output="functions.csv"\n'
                      'single_file_output=false\noutput_worker_threads=1\npatch_syscalls=false\n'
                      'patch_cop0=false\npatch_cache=false\n',encoding='ascii')
    if jump_tables:
        from vm_handlers import Image
        image=Image(disc_bytes)
        with config.open('a',encoding='ascii') as stream:
            stream.write('\n[jump_tables]\n')
            for table,count in jump_tables:
                stream.write(f'[[jump_tables.table]]\naddress="0x{table:x}"\nentries=[\n')
                for index in range(count):
                    target=image.word(table+index*4)
                    stream.write(f'{{index={index},target="0x{target:x}"}},\n')
                stream.write(']\n')
    call([exe,config.name],run/'recompile.log',run)
    result={}
    for path in (run/'generated').rglob('*.cpp'):
        code=path.read_text(encoding='utf-8')
        match=re.search(r'// Address:\s*0x([0-9a-f]+)\s*-\s*0x([0-9a-f]+)',code,re.I)
        if not match:
            continue
        start,end=(int(v,16) for v in match.groups())
        if start not in mapped:
            continue
        limit,name,off=mapped[start]
        if hex(start) in result or end!=limit:
            raise ValueError(f'Unexpected generated range in {path}')
        result[hex(start)]=dict(name=name,end_exclusive=hex(end),elf_file_offset=off,
             original_bytes_sha256=hashlib.sha256(data[off:off+end-start]).hexdigest(),
             instructions=(end-start)//4,source=str(path.relative_to(run)),source_sha256=sha(path))
    if set(result)!=set(map(hex,mapped)):
        raise ValueError(f'Missing generated bodies {result.keys()}; inspect {run}')
    manifest=dict(run=str(run),iso=str(iso_path),iso_sha256=image_proof['sha256'],boot=extract,
                  generator=str(exe),generator_sha256=sha(exe),config_sha256=sha(config),
                  upstream_commit=tool_receipt['upstream_commit'],ghidra_map_sha256=sha(ghidra_map),functions=result)
    record(run/'generated.json',manifest)
    print(run,flush=True)
    return run


def build(run):
    proof=json.loads((run/'generated.json').read_bytes())
    elf=Path(proof['boot']['path'])
    if sha(elf)!=ELF_SHA or sha(Path(proof['generator']))!=proof['generator_sha256']:
        raise ValueError('Generation inputs changed')
    raw=elf.read_bytes()
    sources=[]
    for address in ENTRIES:
        item=proof['functions'][hex(address)]
        src=run/item['source']
        if sha(src)!=item['source_sha256']:
            raise ValueError(f'Generated source changed: {src}')
        code=src.read_text(encoding='utf-8')
        seen=set()
        for pc,word in re.findall(r'// 0x([0-9a-f]+): 0x([0-9a-f]+)\b',code,re.I):
            pc=int(pc,16)
            if not address<=pc<int(item['end_exclusive'],16):
                raise ValueError(f'Unexpected instruction annotation {pc:x}')
            actual=struct.unpack_from('<I',raw,item['elf_file_offset']+pc-address)[0]
            if actual!=int(word,16):
                raise ValueError(f'Original word differs at {pc:x}')
            seen.add(pc)
        if seen!=set(range(address,int(item['end_exclusive'],16),4)):
            raise ValueError(f'Generated instruction annotations incomplete in {src}')
        sources.append(src)
    toolchain=EVAL/'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    runtime=UPSTREAM/'ps2xRuntime/include'
    header=ROOT/'tools/ps2recomp_pilot_runtime.hpp'
    host=ROOT/'tools/ps2recomp_pilot_host.cpp'
    exe=run/'pilot_host.exe'
    args=[toolchain,'c++','-std=c++20','-target','x86_64-windows-gnu','-O2','-msse4.1',
          '-fno-fast-math','-ffp-contract=off','-include',header,'-I',runtime,
          '-I',UPSTREAM/'ps2xIOP/include','-I',UPSTREAM/'ps2xRuntime/src/lib/Kernel',
          '-I',run/'generated',host,*sources,'-o',exe]
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(EVAL/'zig-global-cache'),
             ZIG_LOCAL_CACHE_DIR=str(EVAL/'ee-pilot/zig-local-cache'))
    call(args,run/'compile.log',run,env)
    binary=exe.read_bytes()
    nt=struct.unpack_from('<I',binary,0x3c)[0]
    if binary[:2]!=b'MZ' or binary[nt:nt+6]!=b'PE\0\0\x64\x86' or struct.unpack_from('<H',binary,nt+24)[0]!=0x20b:
        raise ValueError('Compiler output is not a native Windows AMD64 PE32+ executable')
    call([exe,'expandband','3f800000','3f800000',2],run/'execution.jsonl',run)
    rows=[json.loads(line) for line in (run/'execution.jsonl').read_text().splitlines()]
    if len(rows)!=2:
        raise ValueError('Native executable did not run both frame calls')
    proof.update(compiler_sha256=sha(toolchain),compiler_argv=list(map(str,args)),
                 linked_game_functions=[hex(a) for a in ENTRIES],
                 host_sources_sha256={p.name:sha(p) for p in (host,header)},
                 runner=str(exe),runner_sha256=sha(exe),runner_format='Windows x64 PE32+',
                 recompile_log_sha256=sha(run/'recompile.log'),smoke_exit=0,
                 scope='Only the two linked update/setter entries are executed. Title startup and device backends are outside this pilot.')
    record(run/'build.json',proof)
    print(json.dumps(dict(runner=str(exe),sha256=proof['runner_sha256'],smoke_frames=len(rows))),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--iso',type=Path,default=ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso')
    p.add_argument('--generator',type=Path,default=EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe')
    p.add_argument('--build-run',type=Path,help='Build an existing verified generation run without repeating extraction')
    p.add_argument('--generate-only',action='store_true')
    args=p.parse_args()
    if args.build_run and args.generate_only:
        p.error('choose generation or building an existing run')
    run=args.build_run.resolve() if args.build_run else generate(args.iso.resolve(),args.generator.resolve())
    if not args.generate_only:
        build(run)
