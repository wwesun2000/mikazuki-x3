"""Decode source MPEG streams to fingerprinted, seekable PNG frame sequences."""
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from scenario_resources import parse_mmv
from vm_handlers import Image

ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/'local/port-assets/movies'
REPORT=ROOT/'analysis/scenario_decode.json'
RATES=[None,Fraction(24000,1001),Fraction(24),Fraction(25),Fraction(30000,1001),
       Fraction(30),Fraction(50),Fraction(60000,1001),Fraction(60)]


def digest(data):return hashlib.sha256(data).hexdigest()


def verified(path,expected):
    data=path.read_bytes()
    if digest(data)!=expected:raise ValueError(f'Changed source: {path}')
    return data


def geometry(es):
    at=es.find(b'\0\0\1\xb3')
    if at<0:raise ValueError('Missing MPEG sequence header')
    header=int.from_bytes(es[at+4:at+8],'big')
    width,height,code=header>>20,(header>>8)&4095,header&15
    if code not in range(1,9) or not (0<width<=1920 and 0<height<=1080):
        raise ValueError('Unsupported MPEG dimensions/frame rate')
    rate=RATES[code]
    # ISO/IEC 13818-2 sequence_extension has horizontal/vertical size
    # extensions and a rational frame-rate multiplier after low_delay.
    for ext in re.finditer(b'\x00\x00\x01\xb5',es):
        payload=es[ext.end():ext.end()+6]
        if len(payload)!=6 or payload[0]>>4!=1:continue
        bits=int.from_bytes(payload,'big')
        width|=((bits>>31)&3)<<12
        height|=((bits>>29)&3)<<12
        rate*=Fraction(((bits>>5)&3)+1,(bits&31)+1)
        break
    if width>1920 or height>1080:raise ValueError('Extended dimensions exceed native cache limits')
    return width,height,rate


def decode(ffmpeg,data,program_stream):
    path_id=digest(data)
    CACHE.mkdir(parents=True,exist_ok=True)
    target=CACHE/path_id
    # All new outputs are generated separately; source, ordered PNG identities
    # and decoded-frame count must still agree when reusing a prior generation.
    if target.exists():
        m=json.loads((target/'clip.json').read_bytes())
        hashes=(target/'frames.sha256').read_bytes()
        if (m['source']!=path_id or len(hashes)!=32*m['frames'] or digest(hashes)!=m['index_sha256'] or
                any(hashlib.sha256((target/f'{i:06}.png').read_bytes()).digest()!=hashes[32*i:32*i+32]
                    for i in range(m['frames']))):
            raise ValueError(f'Corrupted existing video cache: {target}')
        return m
    base=[str(ffmpeg),'-nostdin','-hide_banner','-v','error','-xerror','-err_detect','explode']
    with tempfile.TemporaryDirectory(dir=CACHE) as temp:
        work=Path(temp)
        encoded=work/('original.pss' if program_stream else 'original.m2v')
        encoded.write_bytes(data)
        if program_stream:
            es=subprocess.run([*base,'-i',str(encoded),'-map','0:v:0','-an','-c:v','copy','-f','mpeg2video','pipe:1'],
                              capture_output=True,check=True,timeout=120).stdout
        else:es=data
        width,height,rate=geometry(es)
        directory=work/'frames'
        directory.mkdir()
        log=subprocess.run([*base,'-i',str(encoded),'-map','0:v:0','-an','-fps_mode','passthrough',
                            '-pix_fmt','rgba','-c:v','png','-pred','mixed','-compression_level','4',
                            '-threads','2','-start_number','0',str(directory/'%06d.png')],
                           capture_output=True,check=True,timeout=180)
        if log.stderr:raise ValueError(log.stderr.decode(errors='replace'))
        files=sorted(directory.glob('*.png'))
        if not 1<=len(files)<=36000:raise ValueError('Invalid number of actual decoded frames')
        hashes=bytearray()
        for index,png in enumerate(files):
            body=png.read_bytes()
            if png.name!=f'{index:06}.png' or struct.unpack_from('>II',body,16)!=(width,height):
                raise ValueError('PNG geometry or ordinal mismatch')
            hashes.extend(hashlib.sha256(body).digest())
        (directory/'frames.sha256').write_bytes(hashes)
        m=dict(source=path_id,width=width,height=height,fps_num=rate.numerator,fps_den=rate.denominator,
               frames=len(files),index_sha256=digest(hashes),encoded_bytes=len(data))
        (directory/'clip.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
        directory.rename(target)
        return m


def main():
    cert=json.loads(REPORT.read_bytes())
    ffmpeg=Path(cert['tool'])
    verified(ffmpeg,cert['tool_sha256'])
    fad=json.loads((ROOT/'analysis/fad_manifest.json').read_bytes())
    entries={r['path']:r for r in fad['archives'][0]['records'] if r['kind']=='file'}
    members={}
    for row in cert['results']:
        if Path(row['source']).suffix not in {'.pss','.m2v','.mmv'}:continue
        if row['status']!='strict-decode-passed' or row['returncode'] or row['error_lines']:
            raise ValueError('Original strict MPEG certificate failed')
        members.setdefault(row['source'],{})[row['input_sha256']]=row['decoded_frame_count']
    # A standalone FAD file can have exactly the same bytes as an MMV slice.
    all_hashes={sha for group in members.values() for sha in group}
    for name,r in entries.items():
        if name.endswith('.m2v') and r['sha256'] in all_hashes:members.setdefault(name,{})
    elf=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    def virtual(name):
        kind={'.m2v':3,'.mmv':4,'.pss':5}[Path(name).suffix]
        offset=elf.offset(elf.word(0x22acc8+kind*68+12))
        return elf.data[offset:offset+64].split(b'\0')[0].decode()+Path(name).name
    assets=[]; clips=[]
    for name,counts in sorted(members.items()):
        item=entries[name];raw=verified(ROOT/'local/assets'/name,item['sha256'])
        if len(raw)!=item['size']:raise ValueError('Unexpected FAD payload size')
        streams=([(r['offset'],r['size']) for r in parse_mmv(raw)] if name.endswith('.mmv') else [(0,len(raw))])
        start=len(clips)
        for offset,size in streams:
            m=decode(ffmpeg,raw[offset:offset+size],name.endswith('.pss'))
            if counts and m['frames']!=counts.get(m['source']):raise ValueError('Certified frame count disagreement')
            clips.append({**m,'offset':offset})
        assets.append(dict(virtual=virtual(name),path='local/assets/'+name,sha=item['sha256'],
                           size=len(raw),start=start,clips=len(clips)-start))
    h=['// Generated from original FAD bytes, MMV member tables and MPEG sequence headers.',
       '#pragma once','#include <array>','#include <cstdint>','namespace kx3::platform {',
       'struct MovieClipBinding { const char *source_sha, *index_sha; std::uint32_t width,height,fps_num,fps_den,frames,offset,size; };',
       'struct MovieBinding { const char *name,*path,*sha; std::uint32_t size,start,clips; };',
       f'inline constexpr std::array<MovieClipBinding,{len(clips)}> movie_clips = {{{{']
    for c in clips:
        h.append('    {'+','.join(json.dumps(c[k]) for k in ('source','index_sha256','width','height',
                 'fps_num','fps_den','frames','offset','encoded_bytes'))+'},')
    h+=['}};',f'inline constexpr std::array<MovieBinding,{len(assets)}> movie_bindings = {{{{']
    for a in assets:h.append('    {'+','.join(json.dumps(a[k]) for k in ('virtual','path','sha','size','start','clips'))+'},')
    (ROOT/'port/platform/movie_catalog.hpp').write_text('\n'.join(h+['}};','}','']),encoding='utf-8')
    report=dict(ffmpeg_sha256=cert['tool_sha256'],verification_source=digest(REPORT.read_bytes()),
                source_elf_sha256=elf.sha256,assets=assets,clips=clips)
    (ROOT/'analysis/native-core/movie-catalog.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(assets=len(assets),unique_clips=len({c['source'] for c in clips}),
                          decoded_frames=sum(c['frames'] for c in {c['source']:c for c in clips}.values()))))


if __name__=='__main__':main()
