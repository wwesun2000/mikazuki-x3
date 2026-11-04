"""Generate the first ID bank of the retail factory registry and compile-check each raw upstream C++ file."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from time import perf_counter

import run_ps2recomp_pilot as pilot

ROOT = pilot.ROOT
OUT = ROOT/'analysis/ps2recomp-factory-survey'
WORK = ROOT/'local/pc-core/ps2recomp-factory-survey'
TABLE, NEXT_DATA = 0x205640, 0x205c98
COMMENT = re.compile(r'^\s*// 0x([0-9a-f]+): 0x([0-9a-f]{1,8})\b', re.I|re.M)
UNRESOLVED = re.compile(r'unhandled|unimplemented|unsupported|not implemented|TODO:|unknown (?:op|instruction)|SignalException\(ctx, EXCEPTION_RESERVED_INSTRUCTION', re.I)


def original_offset(elf, address, size):
    phoff, = struct.unpack_from('<I',elf,28)
    stride, count = struct.unpack_from('<HH',elf,42)
    for i in range(count):
        typ, off, va, _, n, *_ = struct.unpack_from('<8I',elf,phoff+i*stride)
        if typ==1 and va<=address and address+size<=va+n:
            return off+address-va
    raise ValueError(f'Unmapped original address {address:#x}')


def source_paths(elf, rows):
    # List original compiler-emitted .c literals referenced by each function,
    # not file attribution inferred from address adjacency.
    references=ROOT/'analysis/ghidra/post-transition-frontiers-v1/references.csv'
    direct={}
    for ref in csv.DictReader(references.open(encoding='utf-8')):
        owner, dest = ref['from_function'],ref['to']
        if not owner.startswith('ram:') or not dest.startswith('ram:'):continue
        a=int(owner[4:],16); d=int(dest[4:],16)
        if not 0x200000<=d<0x238000:continue
        try:at=original_offset(elf,d,1)
        except ValueError:continue
        literal=elf[at:at+96].split(b'\0',1)[0]
        if re.fullmatch(rb'effect/[a-zA-Z0-9_./-]+\.c',literal):
            value={'original_literal':literal.decode(),'literal_va':hex(d),'referencing_pc':ref['from']}
            direct.setdefault(a,[]).append(value)
    def paths(a):
        found=[dict(x,function=hex(a)) for x in direct.get(a,[])]
        if found:return found
        row=rows.get(a)
        if not row:return []
        out=[]
        for r in row['ranges']:
            start,end=int(r['start'],16),int(r['end_exclusive'],16)
            for pc in range(start,end-3,4):
                word,=struct.unpack_from('<I',elf,r['file_offset']+pc-start)
                if word>>26 not in (2,3):continue
                target=((pc+4)&0xf0000000)|((word&0x3ffffff)<<2)
                out.extend(dict(x,via_original_j_or_jal=hex(pc),function=hex(target)) for x in direct.get(target,[]))
        return out
    return paths


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reuse-generation',type=Path,help='Compile existing hash-checked sources without rerunning PS2Recomp')
    prior=parser.parse_args().reuse_generation
    OUT.mkdir(parents=True,exist_ok=True)
    source=ROOT/'local/extracted/SLPM_664.52'
    elf=source.read_bytes()
    if hashlib.sha256(elf).hexdigest()!=pilot.ELF_SHA:raise ValueError('Unrecognized ELF')
    off=original_offset(elf,TABLE,NEXT_DATA-TABLE+5)
    if elf[off+NEXT_DATA-TABLE:off+NEXT_DATA-TABLE+5]!=bytes((3,5,9,10,15)):
        raise ValueError('Factory table successor differs')
    slots=[{'id':i,'factory':hex(p),'arguments':n}
           for i,(p,n) in enumerate(struct.iter_unpack('<II',elf[off:off+NEXT_DATA-TABLE]))]
    assert len(slots)==203
    selected={int(s['factory'],16):s['id'] for s in slots[:100] if int(s['factory'],16)}
    rows={}
    for shard in sorted((ROOT/'analysis/decompiled-ee').glob('shard-*.jsonl')):
        with shard.open(encoding='utf-8') as stream:
            for line in stream:
                row=json.loads(line);a=int(row['entry'],16)
                if a in selected:rows[a]=row
    paths=source_paths(elf,rows)
    entries=[];cases=[]
    for a,slot in sorted(selected.items(),key=lambda x:x[1]):
        row=rows.get(a);c={'table_id':slot,'entry':hex(a),'original_source_path_evidence':paths(a)}
        cases.append(c)
        if row is None:
            c['status']='not_generated_no_independent_ghidra_entry';continue
        c['body_ranges']=row['ranges'];c['instructions']=row['instruction_count']
        if len(row['ranges'])!=1:
            c['status']='not_generated_noncontiguous_body';continue
        r=row['ranges'][0];lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
        if lo!=a or lo%4 or hi%4 or row['instruction_bytes']!=hi-lo or row['body_bytes']!=hi-lo:
            c['status']='not_generated_inexact_instruction_range';continue
        entries.append(a)
    if prior:
        run=prior.resolve()
        if run.parent!=WORK.resolve():raise ValueError('Unexpected generator directory')
        first_report=json.loads((OUT/'report.json').read_bytes())
        gen_seconds=first_report['seconds_generate_including_iso_and_map']
    else:
        t=perf_counter()
        run=pilot.generate(next(ROOT.glob('*.iso')),pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',entries=tuple(entries),work=WORK)
        gen_seconds=perf_counter()-t
    gen=json.loads((run/'generated.json').read_bytes())
    if pilot.sha(run/'SLPM_664.52')!=pilot.ELF_SHA or pilot.sha(Path(gen['generator']))!=gen['generator_sha256']:
        raise ValueError('Generation input no longer matches its receipt')
    zig=pilot.EVAL/'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    args=[str(zig),'c++','-std=c++20','-target','x86_64-windows-gnu','-msse4.1',
          '-fno-fast-math','-ffp-contract=off','-c',
          '-I',str(pilot.UPSTREAM/'ps2xRuntime/include'),'-I',str(pilot.UPSTREAM/'ps2xIOP/include'),
          '-I',str(pilot.UPSTREAM/'ps2xRuntime/src/lib/Kernel'),'-I',str(run/'generated')]
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(pilot.EVAL/'zig-global-cache'),ZIG_LOCAL_CACHE_DIR=str(pilot.EVAL/'ee-pilot/zig-local-cache'))
    def check(c):
        a=int(c['entry'],16);f=gen['functions'][c['entry']];end=int(f['end_exclusive'],16)
        src=run/f['source'];code=src.read_text(encoding='utf-8');seen=set()
        if pilot.sha(src)!=f['source_sha256']:raise ValueError('Generated source hash changed')
        for vs,ws in COMMENT.findall(code):
            pc=int(vs,16);word=int(ws,16)
            if not a<=pc<end or pc%4 or struct.unpack_from('<I',elf,f['elf_file_offset']+pc-a)[0]!=word:
                raise ValueError(f'Generated instruction mismatch at {pc:#x}')
            seen.add(pc)
        missing=set(range(a,end,4))-seen
        missing_nonzero=[hex(pc) for pc in sorted(missing) if struct.unpack_from('<I',elf,f['elf_file_offset']+pc-a)[0]]
        text_issues=[{'line':n,'text':s.strip()} for n,s in enumerate(code.splitlines(),1) if UNRESOLVED.search(s)]
        started=perf_counter()
        obj=run/(c['entry']+'.obj')
        child=subprocess.run(args+[str(src),'-o',str(obj)],cwd=run,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
        log=run/(c['entry']+'.compile.log');log.write_bytes(child.stdout)
        if child.returncode==0:
            raw=obj.read_bytes()
            machine,sections=struct.unpack_from('<HH',raw)
            if machine!=0x8664 or sections<1:raise ValueError('Expected Windows AMD64 COFF object')
            c.update(object=obj.relative_to(ROOT).as_posix(),object_size=len(raw),object_sha256=hashlib.sha256(raw).hexdigest())
        c.update(status='object_failed' if child.returncode else 'object_compiled',
                 original_sha256=f['original_bytes_sha256'],source_sha256=f['source_sha256'],
                 source_path=src.relative_to(ROOT).as_posix(),compile_returncode=child.returncode,
                 compile_elapsed_seconds=round(perf_counter()-started,4),diagnostics_log=log.relative_to(ROOT).as_posix(),
                 diagnostics_sha256=pilot.sha(log),matched_unique_instruction_comments=len(seen),
                 omitted_nops=len(missing)-len(missing_nonzero),missing_nonzero_instruction_comments=missing_nonzero,
                 unresolved_source_markers=text_issues)
    start=perf_counter()
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(check,[c for c in cases if 'status' not in c]))
    syntax_seconds=perf_counter()-start
    report={'scope':'Original ID bank 0..99 inclusive, fixed before boundary or syntax filtering. Factory bodies only, not callbacks, boot, device or renderer verification.',
        'elf_sha256':pilot.ELF_SHA, 'iso_sha256':gen['iso_sha256'],'table_start':hex(TABLE),'next_data':hex(NEXT_DATA),
        'table_records':len(slots),'table_all_slots':slots,'selected_bank_nonnull_slots':sum(int(s['factory'],16)!=0 for s in slots[:100]),
        'selected_distinct':len(selected),'generated':len(entries),'objects_compiled':sum(c['status']=='object_compiled' for c in cases),
        'objects_failed':sum(c['status']=='object_failed' for c in cases),
        'selected_original_instruction_words_generated':sum(c['instructions'] for c in cases if 'compile_returncode' in c),
        'functions_with_unresolved_markers':sum(bool(c.get('unresolved_source_markers')) for c in cases),
        'functions_referencing_original_effect_source_path':sum(bool(c['original_source_path_evidence']) for c in cases),
        'seconds_generate_including_iso_and_map':round(gen_seconds,4),'seconds_compile_wall':round(syntax_seconds,4),
        'compile_arguments_excluding_source_and_output':args, 'three_parallel_compiler_processes':True,
        'compiler_sha256':pilot.sha(zig),'generator_sha256':gen['generator_sha256'],'upstream_commit':gen['upstream_commit'],
        'generator_log':(run/'recompile.log').relative_to(ROOT).as_posix(),'config_sha256':gen['config_sha256'],
        'raw_warnings':[l.strip() for l in (run/'recompile.log').read_text().splitlines() if '[warning]' in l],
        'unverified':['No host overrides or injected runtime preinclude; COFF object compilation does not check linkability, missing branch targets, FPU/VU hardware behavior, GS or normal game execution.',
            'A referenced compiler filename is evidence for the specific reference and its direct call path, not the complete original translation-unit boundary.',
            'The first ID bank was selected as a single family. Null slots and later ID banks remain visible in the source table inventory.'],
        'cases':cases}
    pilot.record(OUT/'report.json',report)
    print(json.dumps({k:report[k] for k in ('selected_distinct','generated','objects_compiled','objects_failed','functions_with_unresolved_markers','seconds_compile_wall')}),flush=True)


if __name__=='__main__':main()
