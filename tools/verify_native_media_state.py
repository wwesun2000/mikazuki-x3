"""Actual original context step + source-bound Windows decode/preparation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import time
import uuid
import zipfile
import zlib

ROOT=Path(__file__).resolve().parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()
def encode_layer(raw):
    width,height=640,448
    if len(raw)!=width*height*4:raise ValueError('Incomplete native RGBA layer')
    def chunk(kind,body):
        return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body))
    scanlines=b''.join(b'\0'+raw[y*width*4:(y+1)*width*4] for y in range(height))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(scanlines,9))+chunk(b'IEND',b'')

def main():
    parser=argparse.ArgumentParser()
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--layer',choices=['slot4-yield','slot7-snapshot'])
    mode.add_argument('--frames',choices=['timed','choice'])
    mode.add_argument('--font-slot',type=int,choices=range(1,8))
    args=parser.parse_args()
    build=json.loads((ROOT/'local/pc-core/media_state_probe.build.json').read_text())
    exe=Path(build['output'])
    if sha(exe.read_bytes())!=build['output_sha256']:raise ValueError('Media probe changed')
    def stable():return all(sha(Path(p).read_bytes())==h for p,h in build['sources'].items())
    if not stable():raise ValueError('Media/core source changed after build')
    report=json.loads((ROOT/'analysis/observations/OBS-001/state-analysis/report.json').read_text(encoding='utf-8'))
    slot=args.font_slot or (7 if args.layer=='slot7-snapshot' or args.frames=='choice' else 4)
    state=next(s for s in report['states'] if s['slot']==slot)
    path=ROOT/state['archive']
    if sha(path.read_bytes())!=state['archive_sha256']:raise ValueError('Original snapshot changed')
    with zipfile.ZipFile(path) as z:ram=z.read('eeMemory.bin')
    capture=None
    with tempfile.TemporaryDirectory(dir=ROOT/'local/pc-core') as temp:
        command=[str(exe),str(ROOT)]
        raw_path=Path(temp)/'text.rgba'
        if args.layer:command+=['--snapshot-layer' if slot==7 else '--yield-layer',str(raw_path)]
        if args.frames:command+=['--frames',args.frames,str(Path(temp)/'mid-wait.kx3save')]
        if args.font_slot:command+=['--font-resource','sn4g']
        child=subprocess.run(command,input=ram,capture_output=True,timeout=120,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        rows=[json.loads(line) for line in child.stdout.decode('utf-8').splitlines()]
        if args.layer and child.returncode==0:
            if not rows or rows[-1].get('visible_pixels',0)<=0:raise ValueError('No visible source glyphs')
            raw=raw_path.read_bytes()
            if slot==4:
                steps=[r for r in rows if 'step' in r]
                if [r.get('opcode') for r in steps[:4]]!=[0x72,0x40,0x65,0x02] or steps[-1].get('opcode')!=0x50 or steps[-1].get('return_value')!=1:
                    raise ValueError('Did not reach the original timed yield through the expected entry chain')
            target=ROOT/'captures/recompiled-core'/f'{args.layer}-{sha(raw)[:16]}.png'
            target.parent.mkdir(parents=True,exist_ok=True)
            png=encode_layer(raw)
            if target.exists():
                if target.read_bytes()!=png:raise ValueError('Conflicting previous capture')
            else:
                with target.open('xb') as f:f.write(png)
            capture=dict(path=str(target.relative_to(ROOT)),png_sha256=sha(png),rgba_sha256=sha(raw),
                source='Native logical text layer from original primary/ruby node pools and CLUT',
                dimensions=[640,448],presentation='isolated transparent layer; background and cursor not drawn')
    if not stable():raise ValueError('Media/core source changed during run')
    result=dict(schema=1,status='passed' if child.returncode==0 else 'failed',build=build,
        slot=slot,manager_frame_scenario=args.frames,font_resource_check=bool(args.font_slot),archive_sha256=state['archive_sha256'],ram_sha256=sha(ram),trace=rows,capture=capture,
        stderr=child.stderr.decode('utf-8',errors='replace'),exit_code=child.returncode,
        scope=('Native manager frame with host synchronization, source input/timing and transactional presentation' if args.frames
               else 'Original-state text-layer or context-step experiment with actual Windows decoded image preparation.'))
    output=ROOT/'analysis/native-core'/f'media-state-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:6]}.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(output),status=result['status'],steps=sum('step' in row for row in rows),
                          last=rows[-2:],capture=capture,stderr=result['stderr'])))
    return child.returncode
if __name__=='__main__':raise SystemExit(main())
