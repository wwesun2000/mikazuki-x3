"""Bounded source evidence for ScenePack effect9 and the admitted original BGM."""
import json
from pathlib import Path
import struct
import subprocess
import wave

from scenario_resources import ROOT, sha, require
from vm_handlers import Image
from vm_presentation_semantics import extended_decode


def build(root=ROOT):
    root=Path(root)
    image=Image((root/'local/extracted/SLPM_664.52').read_bytes())
    require(image.word(0x205688)==0x180eb0 and image.word(0x20568c)==4,'Effect9 dispatch changed')
    bank=(root/'local/assets/SOUND/SSDVDAT/bgm.dat').read_bytes()
    require(len(bank)==57344,'BGM header size mismatch')
    records=[]
    for offset in range(0,56000,56):
        raw=bank[offset:offset+56]
        if not raw[0]&0x80:break
        name=raw[40:54].split(b'\0',1)[0].decode('ascii')
        require(raw[3]&0x20 and name and len(name)<=12,'Invalid original Vorbis bank record')
        start,end=struct.unpack_from('<II',raw,4)
        volume,=struct.unpack_from('<H',raw,38)
        records.append(dict(name=name,record_offset=offset,record_sha256=sha(raw),raw_hex=raw.hex(),
                            loop_start_sample=start,loop_end_sample_exclusive=end,base_volume=volume))
    admitted=next(r for r in records if r['name']=='k1a006')
    source=root/'local/assets/SOUND/SSDVVOR/k1a006.ogg'
    target=root/'captures/derived/opening-audio/k1a006.bgm.wav'
    ffmpeg=root/'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    result=subprocess.run([str(ffmpeg),'-hide_banner','-v','error','-xerror','-i',str(source),'-c:a','pcm_s16le','-bitexact','-y',str(target)],capture_output=True,text=True)
    require(result.returncode==0 and not result.stderr.strip(),'Strict original OGG decode failed: '+result.stderr)
    with wave.open(str(target),'rb') as w:
        require(w.getnchannels()==2 and w.getframerate()==48000 and w.getsampwidth()==2,'Original BGM format mismatch')
        require(w.getnframes()==admitted['loop_end_sample_exclusive'],'BGM decoded frame count differs from original bank end')
        admitted.update(sample_rate=w.getframerate(),sample_count=w.getnframes(),channels=w.getnchannels())
    admitted.update(source_path=str(source.relative_to(root)).replace('\\','/'),source_sha256=sha(source.read_bytes()),
                    path=str(target.relative_to(root)).replace('\\','/'),sha256=sha(target.read_bytes()),
                    loop_enabled=True,original_master_factor=0.800000011920929)
    audio=dict(source_bank_sha256=sha(bank),record_count=len(records),admitted={'k1a006.ogg':admitted})
    (root/'analysis/bgm_bank.json').write_text(json.dumps(audio,indent=2)+'\n')
    regions=[]
    for start,end in [(0x13b240,0x13b49c),(0x10c528,0x10c628),(0x114348,0x114a50),
                      (0x180eb0,0x1812a8),(0x139abc,0x139c2c),(0x1396b0,0x1397ac),
                      (0x1b24c0,0x1b2590),(0x1b43a0,0x1b45dc),(0x1d10c0,0x1d124c),
                      (0x1d1548,0x1d17a4),(0x1d33c8,0x1d34d0)]:
        region=image.region(start,end)
        for ins in region['instructions']:
            address=int(ins['address'],16)
            ins['decoded']=extended_decode(image.word(address),address)
        regions.append(region)
    report=dict(evidence_id='CUE-MEDIA-EXTENSIONS-001',elf_sha256=image.sha256,
                effect9=dict(table_address=0x205688,constructor=0x180eb0,arguments=['duration_updates','R','G','B'],
                    initial_rgb=128,update=0x181020,draw=0x181110,source='current framebuffer via176970 texture8000',
                    operations={'08':'EFFECT_ON','09':'EFFECT_OFF','0B':'EFFECT_WAIT'},
                    encoding='2A:u8 byte count; BE32 effectID, u8 argcount, BE32 signed args; OFF is BE32 ID only',
                    wait='13B310 calls10C5F8; busy rewinds parser to original0B; END runs after completion'),
                bgm=audio,evidence_regions=regions,
                corrections=['Earlier END record_marker label denotes old effect task count, not video/audio recording.',
                             'Source library loops at PCM stereo frame end and seeks start; do not infer loop from OGG filename.'])
    (root/'analysis/cue_media_extensions.json').write_text(json.dumps(report,indent=2)+'\n')
    return dict(effect9='source-bound',bgm=admitted,records=len(records))


if __name__=='__main__':print(json.dumps(build()))
