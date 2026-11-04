"""Verify native file relocation/indexing, including all original sn4g label IDs."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
import uuid
import zipfile
from scenario import parse_link,parse_scr

ROOT=Path(__file__).resolve().parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()
def u32(data,at): return struct.unpack_from('<I',data,at)[0]

def main():
    build_path=ROOT/'local/pc-core/core_probe.build.json'
    build=json.loads(build_path.read_text())
    executable=Path(build['index_output'])
    if sha(executable.read_bytes())!=build['index_sha256']:
        raise ValueError('Native index executable changed')
    if any(sha(Path(p).read_bytes())!=h for p,h in build['sources'].items()):
        raise ValueError('Native source changed after build')
    run=f'{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:6]}'
    directory=ROOT/'local/pc-core/script-index'/run
    directory.mkdir(parents=True,exist_ok=False)
    observation=json.loads((ROOT/'analysis/observations/OBS-001/state-analysis/report.json').read_text(encoding='utf-8'))
    state=next(s for s in observation['states'] if s['slot']==7)
    archive=ROOT/state['archive']
    if sha(archive.read_bytes())!=state['archive_sha256']: raise ValueError('Original snapshot changed')
    with zipfile.ZipFile(archive) as z:
        if z.getinfo('eeMemory.bin').file_size!=32*1024*1024: raise ValueError('Wrong RAM fixture size')
        ram=z.read('eeMemory.bin')
    rows=[]
    for name in ('sn2','sn4','sn4g'):
        source=ROOT/f'local/assets/SCENARIO/{name}.sn4'
        raw=source.read_bytes(); digest=sha(raw)
        blocks=parse_link(raw)
        parsed=[parse_scr(raw[b['offset']:b['offset']+b['size']]) for b in blocks]
        output=directory/f'{name}.index.bin'
        child=subprocess.run([str(executable),str(source),str(output)],capture_output=True,text=True,timeout=90,
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if child.returncode: raise RuntimeError(child.stdout+child.stderr)
        native=json.loads(child.stdout)
        index=output.read_bytes()
        if index[:4]!=b'KX3L' or u32(index,4)!=1: raise ValueError('Wrong index framing')
        count,labels=struct.unpack_from('<II',index,8)
        if count!=len(blocks) or len(index)!=16+count*8+labels*12: raise ValueError('Index count/length mismatch')
        for i,(block,tree) in enumerate(zip(blocks,parsed)):
            if struct.unpack_from('<II',index,16+i*8)!=(block['offset'],tree['code_offset']):
                raise ValueError('Native relocated code boundary differs from source')
        symbol_map={b['offset']+s['table_offset']:s for b,p in zip(blocks,parsed) for s in p['symbols'] if not s['name'].startswith('_')}
        if labels!=len(symbol_map): raise ValueError('Native symbol count differs from source records')
        seen=set(); originals=0
        if name=='sn4g':
            manager=u32(ram,0x235e40); script=u32(ram,manager+0x38)
            if u32(ram,script+0xc8)!=labels: raise ValueError('Original running label count differs')
            original_blocks=[u32(ram,script+8+i*4) for i in range(count)]
            label_table=u32(ram,script+0xcc)
        for label_id in range(labels):
            actual_id,offset,relative=struct.unpack_from('<III',index,16+count*8+label_id*12)
            if actual_id!=label_id or offset not in symbol_map or offset in seen or symbol_map[offset]['code_relative_offset']!=relative:
                raise ValueError('Native label table differs from original source symbol')
            seen.add(offset)
            if name=='sn4g':
                original=u32(ram,label_table+label_id*4)
                containing=[(b,a) for b,a in zip(blocks,original_blocks) if a<=original<a+b['size']]
                if len(containing)!=1: raise ValueError('Original runtime label outside script blocks')
                block,address=containing[0]
                normalized=block['offset']+original-address
                if normalized!=offset or u32(ram,original+4)!=relative or struct.unpack_from('<H',ram,original+2)[0]!=label_id:
                    raise ValueError('Native ID/order/target differs from actual original runtime')
                originals+=1
        if sha(source.read_bytes())!=digest: raise ValueError('Source changed while testing')
        rows.append(dict(script=name,source_sha256=digest,**native,source_symbols_verified=len(seen),
                         original_runtime_label_ids_verified=originals,index_sha256=sha(index),index=str(output)))
    if any(sha(Path(p).read_bytes())!=h for p,h in build['sources'].items()): raise ValueError('Source changed during verification')
    report=dict(schema=1,status='passed',build=build,original_observation_sha256=state['archive_sha256'],scripts=rows,
                limitations=['Native data-loader only; full ScriptData constructor and complete new-game boot remain separate.',
                             'Original runtime ID comparison exists for sn4g; sn2/sn4 use full source symbol/boundary validation.'])
    destination=ROOT/'analysis/native-core'/f'script-images-{run}.json'
    destination.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(destination),scripts=rows),ensure_ascii=False))

if __name__=='__main__':main()
