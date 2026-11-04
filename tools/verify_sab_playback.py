"""Check all original SAB pictures and their two captured original EE GIF chains."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
from scenario_resources import ResourceIndex

ROOT=Path(__file__).resolve().parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
    records=json.loads((ROOT/'analysis/fad_manifest.json').read_bytes())['archives'][0]['records']
    disc={r['path']:r for r in records if r['kind']=='file'}
    memory=ROOT/'local/pc-core'
    binary=json.loads((memory/'media_payload_probe.build.json').read_bytes())
    exe=Path(binary['output']);assert sha(exe.read_bytes())==binary['output_sha256']
    for p,h in binary['sources'].items():assert sha(Path(p).read_bytes())==h
    # PCSX2 2.8.2 GSDrawScanline / GSVector4i::modulate16<shift>
    # multiplies signed halfwords and keeps their signed high 16 bits.
    channels=bytearray()
    for d in range(-255,256):
        base=255 if d<0 else 0
        for left,limit in ((2,128),(1,255)):
            for f in range(limit+1):
                hi=struct.unpack('<h',struct.pack('<i',(d<<left)*(f<<7))[2:])[0]
                channels.append(base+hi)
    assert subprocess.check_output([exe,'--blend'])==channels
    files={}
    for name,r in disc.items():
        if not name.endswith('.sab'):continue
        p=ROOT/'local/assets'/name;b=p.read_bytes()
        assert len(b)==r['size'] and sha(b)==r['sha256']
        lines=subprocess.check_output([exe,'--sab',p],timeout=30).splitlines()
        h=struct.unpack_from('<I',b)[0];n=struct.unpack_from('<I',b,h+12)[0]
        assert len(lines)==n and [int(line.split()[0]) for line in lines]==list(range(n))
        files[p.name]=dict(size=len(b),source_sha256=sha(b),frames=n,
                           rendered_frame_trace_sha256=sha(b'\n'.join(lines)),
                           distinct_pictures=len(set(line.split()[1] for line in lines)))
    assert len(files)==8 and sum(f['frames'] for f in files.values())==184
    gif=[]
    for raw in (ROOT/'analysis/ghidra/oracle-sab-gif-v1/cases.jsonl').read_bytes().splitlines():
        r=json.loads(raw);assert r['status']=='returned' and not r['faults']
        b=(ROOT/'local/assets/SANM'/(r['id']+'.sab')).read_bytes()
        u=lambda off:struct.unpack_from('<I',b,off)[0]
        h=u(0);index=1 if u(h+12)>1 else 0
        row=u(h+28+index*4);height=u(row+36);strips=(height+127)//128
        mem=r['output']['memory'];packet=bytes.fromhex(mem[1]['hex'])
        end=int(r['output']['registers']['v0'],0)-0x1100000;packet=packet[:end]
        def at(p):return struct.unpack_from('<I',packet,p)[0]
        # Source 146D20 constructs one 13-qword packet for each sprite.
        sprites=[p for p in range(0,end,16) if at(p)==0x1000000d]
        assert len(sprites)==4*strips
        for i,p in enumerate(sprites):
            assert at(p+0x30)==(0x316,0x356,0x316,0x156)[i%4]
            assert at(p+0x80)==(0x80808080,0x68808080,0x80808080,0x60808080)[i%4]
        refs=[(at(p+4)-0x1830100,(at(p)&65535)*16) for p in range(0,end,16)
              if at(p)>>28==3 and 0x1830100<=at(p+4)<0x1830100+len(b)]
        assert refs[:2]==[(u(h+16),1024),(u(h+20)+(u(row+20)//2+4)*64,64)]
        cw,ch=u(row+32)>>(u(h+24)+1),height>>(u(h+24)+1)
        assert refs.count((u(row+4),cw*ch))==strips
        masks=[(off,size) for off,size in refs[2:] if off!=u(row+4)]
        assert masks[0][0]==u(row+8) and all(a+n==b for (a,n),(b,_) in zip(masks,masks[1:]))
        assert sum(n for _,n in masks)==(u(row+40)>>u(row+48))*(u(row+44)>>u(row+52))//2
        gif.append(dict(name=r['id'],source_frame=index,original_steps=r['steps'],packet_sha256=sha(packet),
                        source_uploads=refs,sprites=len(sprites),strips=strips))
    report=json.loads((memory/'source-overlays/build.json').read_bytes())
    probe=Path(report['output']);assert sha(probe.read_bytes())==report['output_sha256'].lower()
    native_factory=subprocess.check_output([probe,ROOT,'--flash'],timeout=30).splitlines()
    factory=[]
    for line,raw in zip(native_factory,(ROOT/'analysis/ghidra/oracle-flash-factory-v1/cases.jsonl').read_bytes().splitlines(),strict=True):
        r=json.loads(raw);assert r['status']=='returned' and not r['faults'] and r['isolated_platform_calls']=={'0x0017a560':1}
        regions={v['name']:bytes.fromhex(v['hex']) for v in r['output']['memory']}
        expected=regions['flash-task']+regions['allocation']
        assert bytes.fromhex(line.decode())==expected and len(expected)==96
        factory.append(dict(id=r['id'],steps=r['steps'],task_and_allocation_sha256=sha(expected)))
    native_mesh=subprocess.check_output([probe,ROOT,'--mime-factory'],timeout=30).splitlines()
    meshes=[]
    for line,raw in zip(native_mesh,(ROOT/'analysis/ghidra/oracle-mime-factory-v1/cases.jsonl').read_bytes().splitlines(),strict=True):
        r=json.loads(raw);assert r['status']=='returned' and not r['faults']
        calls=r['isolated_platform_calls']
        assert calls=={'0x0017a560':2,'0x001b5154':200,'0x001b5164':100,'0x001b52a4':100,'0x001b5284':100}
        regions={v['name']:bytes.fromhex(v['hex']) for v in r['output']['memory']}
        expected=regions['mesh-task']+regions['working-mesh']+regions['MT-state']
        assert bytes.fromhex(line.decode())==expected and len(expected)==6272
        meshes.append(dict(id=r['id'],steps=r['steps'],original_platform_calls=calls,
                           task_mesh_and_rng_sha256=sha(expected)))
    rows=subprocess.check_output([probe,ROOT],timeout=90).decode().splitlines();groups={}
    index=ResourceIndex((ROOT/'local/assets/SCENARIO/sn4.spk').read_bytes())
    descriptors={s['name']:s for block in index.blocks for s in block['scenes']}
    largest=0
    for line in rows:
        name,cue,main,n,encoded,frame,changed=line.split()
        desc=descriptors[name];assets=[d['name'] for d in desc['dependencies']]
        overlays=[d for d in assets if d.endswith('.sab')]
        assert int(n)==len(overlays) and int(frame)==0 and bool(int(changed))==bool(overlays)
        assert any(c['name']==cue for c in desc['cues'])
        assert main.removeprefix('MOVIE/') in [d.replace('.m2s','.m2v') for d in assets]
        total=256
        for sab in overlays:total=(total+files[sab]['size']+63)&~63
        largest=max(largest,total)
        groups[name]=dict(dependencies=assets,cue=cue,primary=main,overlays=overlays,selected_bytes=int(encoded),
                          changed_pixels=int(changed),aligned_bytes=total)
    assert len(groups)==5 and largest==1486400 and largest<0x180000
    proof=ROOT/'analysis/native-core'/('sab-scene-groups-'+time.strftime('%Y%m%d-%H%M%S')+'.json')
    proof.write_text(json.dumps(dict(start='SN4 cold file construction followed by isolated original subsystem calls',
        files=files,source_gif=gif,scene_groups=groups,maximum_active_bytes=largest,
        native_picture_probe_sha256=sha(exe.read_bytes()),scene_group_probe_sha256=sha(probe.read_bytes()),
        isolated_flash_factory=factory,flash_update_diff='state-calls-20261031-035154-1d2e84.json',
        isolated_mesh_factory=meshes,mesh_update_diff='state-calls-20261031-040656-bcfd4f.json',
        gs_signed_high_channel_cases=len(channels),gs_signed_high_channel_sha256=sha(channels),
        source_queue_diff='state-calls-20261031-034143-86bde6.json',scope='Native bilinear composition checked against original submitted texture, blend and sprite fields. No emulator framebuffer pixel-equivalence claim.',
        gs_reference='https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/GS/Renderers/SW/GSDrawScanline.cpp#L1377-L1529'),indent=2)+'\n')
    print(proof)
if __name__=='__main__':main()
