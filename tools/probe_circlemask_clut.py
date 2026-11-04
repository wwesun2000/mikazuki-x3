"""Probe PSMT4 lane order in PCSX2 SW using two diagnostic rows and retail mask bytes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import zipfile
from compression import zstd

root=Path(__file__).resolve().parents[1]
work=root/'local/diagnostics/circlemask-clut'
proof=root/'analysis/native-core/circlemask-gates'
work.mkdir(parents=True,exist_ok=True)
mask=(root/'local/assets/EFFECT/smask.ctf').read_bytes()
assert len(mask)==8384 and mask[:8]==b'CTF V0.1'
assert hashlib.sha256(mask).hexdigest().startswith('de880fb6ef343ed2')
tex=struct.unpack_from('<Q',mask,112)[0]
tbp,cbp=tex&0x3fff,(tex>>37)&0x3fff
elf=(root/'local/extracted/SLPM_664.52').read_bytes()
assert hashlib.sha256(elf).hexdigest()=='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
tag=b''.join(bytes((7*i,255-7*i,42,128)) for i in range(32))
palettes=[tag]+[elf[p-0xff000:p-0xff000+128] for p in (0x20d9f0,0x20e170)]
pattern=bytearray(mask[192:])
pattern[:64]=bytes((i%8)*34+16 for i in range(64))
pattern[64:128]=bytes((i%16)*17 for i in range(64))
if sys.argv[1:]==['--compare']:
    sys.path.insert(0,str(root/'analysis/native-core/grade-pc-10'))
    from png_rgb import png_rgb
    for png in sorted((work/'draws-clut').glob('*_rt1_*')):
        w,h,rgb=png_rgb(png)
        if w>500 and h>160 and rgb[(w*160+500)*3:(w*160+500)*3+3]==bytes((19,41,73)):break
    else:raise SystemExit('No complete GS readback with terminal sentinel')
    def pixel(x,y):return rgb[3*(y*w+x):3*(y*w+x)+3]
    lanes=[pixel(i*2,1)[0]//7 for i in range(16)]
    ramp=[pixel(i,0)[0]//7 for i in range(16)]
    mismatches=[]
    for panel,palette in enumerate(palettes):
        source=pattern if panel==0 else mask[192:]
        count=0
        for y in range(128):
            for x in range(128):
                value=source[y*64+x//2]
                index=(value>>(4*(x%2)))&15
                expected=palette[4*lanes[index]:4*lanes[index]+3]
                count+=pixel(panel*128+x,y)!=expected
        mismatches.append(count)
    result=dict(scope='1:1 nearest RGB swatches, one field, actual retail PSMT4 and two ELF palettes; no full-screen composite.',
                render=str(png.relative_to(root)),render_sha256=hashlib.sha256(png.read_bytes()).hexdigest(),
                tex0=hex(tex),mask_sha256=hashlib.sha256(mask).hexdigest(),physical_clut_slots=lanes,
                ascending_nibble_row=ramp,compared_rgb_pixels_per_panel=128*128,mismatches=mismatches)
    (proof/'texture.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
    raise SystemExit(int(any(mismatches)))
spec=importlib.util.spec_from_file_location('gs_fixture',root/'analysis/native-core/expandband-gs-reference/make_reference.py')
gs=importlib.util.module_from_spec(spec);spec.loader.exec_module(gs);gs.WORK=work;gs.setup('clut')
with zipfile.ZipFile(sorted((root/'local/pcsx2/sstates').glob('*.p2s'))[0]) as state:
    ram=state.read('eeMemory.bin');frozen=bytearray(state.read('GS.bin'))
    privileged=state.read('PCSX2 Internal Structures.dat')[5834:5834+8192]
frozen[512:-128]=bytes(len(frozen)-640)
packet=bytearray(ram[0x23ed70+0x90:0x23ed70+0x120]);packet[1]&=0x7f
def upload(base,bw,psm,width,height,data):
    setup=gs.reglist([(0x50,(base<<32)|(bw<<48)|(psm<<56)),(0x51,0),(0x52,width|(height<<32)),(0x53,0)])
    return setup+gs.Q((2<<58)|0x8000|(len(data)//16),0)+data
packet+=gs.reglist([(0x47,0x30803),(0x14,0),(0x4a,0),(0x3b,0x8000000080)])
for i,palette in enumerate(palettes):
    packet+=upload(tbp,2,20,128,128,pattern if not i else mask[192:])
    packet+=upload(cbp,1,0,16,2,palette)
    packet+=gs.reglist([(0x3f,0),(6,tex)])
    packet+=gs.packed_prim(0x116,(128*i,0),(128*(i+1),128),(128,128,128,128),((0,0),(2048,2048)))
packet+=gs.packed_prim(6,(500,160),(504,164),(19,41,73,128),None)
dump=gs.transfer(packet,2)+b'\x03'+privileged+bytes((1,0))
(work/'clut.gs.zst').write_bytes(zstd.compress(struct.pack('<II',0x0d03c0a3,len(frozen))+frozen+privileged+dump,4))
runner=(root/'analysis/native-core/grade-pc-10/run-reference.ps1').read_text()
(work/'run-reference.ps1').write_text(runner.replace('$Fixture="grade"','$Fixture="clut"').replace('$need=8','$need=8'))
