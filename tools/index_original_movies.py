"""Index the retail movie members and validate their frame counts without storing decoded frames."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from generate_movie_catalog import geometry
from generate_original_media_index import virtual_name
from scenario_resources import parse_mmv
from vm_handlers import Image

ROOT=Path(__file__).resolve().parents[1]
DECODER=ROOT/'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
CODEC_SHA='2ce797a0f88d7f067180338fb227f7b1928ea727bd9a4d7a1d022f7c52af71a3'


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify-all',action='store_true',help='Independently decode each unique member to EOF')
    options=parser.parse_args()
    if sha(DECODER.read_bytes())!=CODEC_SHA:raise ValueError('Unexpected FFmpeg executable')
    elf=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    disc=next(x for x in json.loads((ROOT/'analysis/fad_manifest.json').read_bytes())['archives'] if x['name']=='DISC.FAD')
    rows=sorted((x for x in disc['records'] if x['kind']=='file' and Path(x['path']).suffix in ('.mmv','.m2v','.pss')),
                key=lambda x:virtual_name(elf,x['path']))
    folder=ROOT/'local/port-assets/decode-temp'
    folder.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=folder) as scratch:
        encoded={}
        assets=[]
        for row in rows:
            path=ROOT/'local/assets'/row['path']
            data=path.read_bytes()
            if len(data)!=row['size'] or sha(data)!=row['sha256']:raise ValueError(path)
            spans=[(r['offset'],r['size']) for r in parse_mmv(data)] if path.suffix=='.mmv' else [(0,len(data))]
            if not 1<=len(spans)<=2:raise ValueError('Unexpected original clip count')
            clips=[]
            for start,size in spans:
                body=data[start:start+size]
                identity=sha(body)
                if identity not in encoded:
                    file=path
                    if len(body)!=len(data):
                        file=Path(scratch)/(identity+'.m2v')
                        file.write_bytes(body)
                    encoded[identity]=file
                clips.append(dict(sha256=identity,offset=start,size=size))
            assets.append(dict(name=virtual_name(elf,row['path']),sha256=row['sha256'],members=clips))

        def inspect(item):
            identity,path=item
            run=[DECODER,'-hide_banner','-nostdin','-loglevel','error','-xerror','-err_detect','explode',
                 '-threads','2','-i',path,'-map','0:v:0','-an','-sn','-dn']
            if path.suffix=='.pss':
                r=subprocess.run([*run,'-c:v','copy','-f','mpeg2video','pipe:1'],capture_output=True,timeout=100)
                if r.returncode or r.stderr:raise ValueError((path,r.stderr[:1024]))
                body=r.stdout
            else:body=path.read_bytes()
            width,height,fps=geometry(body)
            frames=body.count(b'\0\0\1\0')
            pictures=[body[m.end()+2]&3 for m in re.finditer(b'\0\0\1\xb5',body)
                      if m.end()+2<len(body) and body[m.end()]>>4==8]
            if not 0<frames<=36000 or len(pictures)!=frames or any(p!=3 for p in pictures):
                raise ValueError(f'Unsupported field/frame structure: {path} {frames}, {len(pictures)}')
            if options.verify_all:
                r=subprocess.run([*run,'-nostats','-progress','pipe:1','-fps_mode','passthrough','-f','null','-'],
                                 capture_output=True,timeout=180)
                counts=re.findall(rb'^frame=(\d+)\s*$',r.stdout,re.M)
                if r.returncode or r.stderr or not counts or int(counts[-1])!=frames:
                    raise ValueError((path,frames,counts[-1:],r.stderr[:1024]))
            return identity,dict(width=width,height=height,frames=frames,fps_num=fps.numerator,fps_den=fps.denominator)

        with ThreadPoolExecutor(max_workers=3) as pool:metadata=dict(pool.map(inspect,encoded.items()))
    header=['// Generated from original FAD payloads and MPEG frame-picture headers.',
            '#pragma once','#include <array>','#include <cstdint>','namespace kx3::platform {',
            'struct StreamMember {const char* sha;std::uint32_t offset,bytes,width,height,frames,num,den;};',
            'struct StreamMovie {const char* name;std::uint32_t start,count;};']
    members=[c for a in assets for c in a['members']]
    header.append(f'inline constexpr std::array<StreamMember,{len(members)}> stream_members = {{{{')
    for c in members:
        m=metadata[c['sha256']]
        args=[c['sha256'],c['offset'],c['size'],m['width'],m['height'],m['frames'],m['fps_num'],m['fps_den']]
        header.append('    {'+','.join(json.dumps(v) for v in args)+'},')
    header+=['}};',f'inline constexpr std::array<StreamMovie,{len(assets)}> stream_movies = {{{{']
    start=0
    for a in assets:
        n=len(a['members'])
        header.append(f'    {{"{a["name"]}",{start},{n}}},')
        start+=n
    header+=['}};','}','']
    (ROOT/'port/platform/movie_stream_index.hpp').write_text('\n'.join(header),encoding='utf-8')
    report=dict(ffmpeg_sha256=CODEC_SHA,full_decode_checked=options.verify_all,assets=assets,unique_members=metadata)
    proof=ROOT/'analysis/native-core'/('movie-stream-verified.json' if options.verify_all else 'movie-stream-index.json')
    proof.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(assets=len(assets),unique=len(metadata),frames=sum(m['frames'] for m in metadata.values()),
                          full_decode=options.verify_all,report=str(proof))))


if __name__=='__main__':main()
