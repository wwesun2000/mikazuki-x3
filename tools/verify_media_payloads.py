"""Validate disc PSS PCM against FFmpeg's ADS decoder and field targets against original DMA packets."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
from collections import Counter

ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()


def timestamp(b):
    assert len(b)==5 and b[0]&b[2]&b[4]&1
    return ((b[0]&14)<<29)|(b[1]<<22)|((b[2]&254)<<14)|(b[3]<<7)|(b[4]>>1)


def private_stream(data):
    pieces=[]
    p=0
    pts=None
    while (p:=data.find(b'\0\0\1\xbd',p))>=0:
        end=p+6+int.from_bytes(data[p+4:p+6],'big');payload=p+9+data[p+8]
        assert end<=len(data) and data[payload:payload+4]==b'\xff\xa0\0\0'
        if pts is None and data[p+7]&128:pts=timestamp(data[p+9:p+14])
        pieces.append(data[payload+4:end]);p=end
    return b''.join(pieces),pts


def main():
    build=json.loads((ROOT/'local/pc-core/media_payload_probe.build.json').read_bytes())
    exe=Path(build['output']);assert sha(exe.read_bytes())==build['output_sha256']
    def stable():return all(sha(Path(p).read_bytes())==v for p,v in build['sources'].items())
    assert stable()
    oracle=ROOT/'analysis/ghidra/oracle-display-capture-v1'
    manifest=json.loads((oracle/'manifest.json').read_bytes());cases=(oracle/'cases.jsonl').read_bytes()
    assert manifest['status']=='oracle_completed' and sha(cases)==manifest['cases_sha256']
    records=[json.loads(r) for r in cases.splitlines()]
    fields=[];inputs=[]
    for r in records:
        _,*nums=r['id'].split('-');inputs.append(' '.join(nums))
        field=int(nums[3])
        obs={b['name']:bytes.fromhex(b['hex']) for b in r['output']['memory']}
        left,_,attempts,_,first,second=struct.unpack_from('<6I',obs['capture'])
        # Each original 13CEC0 emits exactly 0x190 bytes; 15D738 writes the
        # original readback destination into the DMA tag at +0x178.
        n,rem=divmod(int(r['output']['registers']['v0'],16)-0x360000,0x190);assert not rem and 0<=n<=2
        copies=[]
        for j in range(n):
            dest=struct.unpack_from('<I',obs['packet'],0x178+j*0x190)[0]
            copies.append(2*(first,second).index(dest)+field)
        fields.append([left,attempts,*copies])
    out=subprocess.run([exe,'--capture'],input=('\n'.join(inputs)+'\n').encode(),capture_output=True,check=True)
    assert [list(map(int,r.split())) for r in out.stdout.splitlines()]==fields
    fad_path=ROOT/'analysis/fad_manifest.json'
    fad=json.loads(fad_path.read_bytes())
    ff=ROOT/'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    ffhash=sha(ff.read_bytes());assert ffhash=='2ce797a0f88d7f067180338fb227f7b1928ea727bd9a4d7a1d022f7c52af71a3'
    files=[]
    for row in fad['archives'][0]['records']:
        if row['kind']!='file' or not row['path'].endswith('.pss'):continue
        path=ROOT/'local/assets'/row['path'];data=path.read_bytes()
        assert len(data)==row['size'] and sha(data)==row['sha256']
        ads,audio_pts=private_stream(data)
        native=subprocess.run([exe,'--pss',path],check=True,capture_output=True,timeout=30).stdout
        record={'source':row['path'],'size':len(data),'sha256':row['sha256'],'audio':bool(ads)}
        if not ads:assert native==b''
        else:
            header,pcm=native.split(b'\n',1);rate,channels,a,v,offset=map(int,header.split())
            first_video=data.index(b'\0\0\1\xe0');assert data[first_video+7]&128
            assert a==audio_pts and v==timestamp(data[first_video+9:first_video+14]) and offset==a-v
            decode=subprocess.run([ff,'-v','error','-xerror','-f','ads','-i','pipe:0','-map','0:a:0',
                '-c:a','pcm_s16le','-f','s16le','pipe:1'],input=ads,check=True,capture_output=True,timeout=60)
            assert rate==48000 and channels==2 and len(pcm)==len(ads)-40 and pcm==decode.stdout
            record.update(frames=len(pcm)//4,rate=rate,channels=channels,first_audio_pts=a,first_video_pts=v,
                          delta_pts=offset,pcm_sha256=sha(pcm))
        files.append(record)
    assert len(files)==268 and sum(r['audio'] for r in files)==53 and stable()
    report=dict(build=build,ffmpeg_sha256=ffhash,fad_sha256=sha(fad_path.read_bytes()),original_capture_sha256=sha(cases),
        capture_cases=len(fields),field_sources='Native 60 Hz display-field input; original GS buffer selected via 151550/151518.',
        pss=files,audio_files=53,without_audio=215,pts90k=dict(Counter(r['delta_pts'] for r in files if r['audio'])))
    out=ROOT/f'analysis/native-core/pss-audio-field-capture-{time.strftime("%Y%m%d-%H%M%S")}.json'
    out.write_text(json.dumps(report,indent=2)+'\n');print(out)


if __name__=='__main__':main()
