"""Prepare a two-mode GS microtest with explicit source alpha and independent Z."""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile
from compression import zstd

root=Path(__file__).resolve().parents[1]
work=root/'local/diagnostics/circlemask-gates-z24'
evidence=root/'analysis/native-core/circlemask-gates'
work.mkdir(parents=True,exist_ok=True)
evidence.mkdir(parents=True,exist_ok=True)
if sys.argv[1:]==['--compare']:
    sys.path.insert(0,str(root/'analysis/native-core/grade-pc-10'))
    from png_rgb import png_rgb
    expected=json.loads((evidence/'expected.json').read_bytes())['expected']
    results=[]
    # GS flushes the last green draw at VSYNC, between rt0 and rt1 of
    # draw 7. Draw 5 is still an intermediate red destination in mode 9.
    for draw in ['00005_f00000','00007_f00001','00014_f00002']:
        path=next((work/'draws-gates').glob(f'{draw}_rt1_00000_C_32.png'))
        w,h,rgb=png_rgb(path)
        assert (w,h)==(640,224)
        samples=[]
        for case in expected:
            i=3*(w*case['y']+case['x'])
            samples.append(dict(**case,observed=list(rgb[i:i+3])))
        results.append(dict(draw=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            matches=sum(r['observed']==r['rgb'] for r in samples),samples=samples))
    (evidence/'result.json').write_text(json.dumps(dict(
        scope='Untextured replacement of palette alpha with explicit 0 or 128; relative depth and TEST only.',
        draw_order=['prior frame, before final pass','first VSYNC, final pass','second VSYNC, repeated final pass'],
        results=results),indent=2))
    if [r['matches'] for r in results]!=[6,8,8]:
        raise SystemExit('Unexpected GS gate readback')
    print('Two complete replays agree on all eight pixels')
    raise SystemExit
spec=importlib.util.spec_from_file_location('gs_fixture',root/'analysis/native-core/expandband-gs-reference/make_reference.py')
gs=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gs)
gs.WORK=work
gs.setup('gates')
ini=work/'pcsx2/inis/PCSX2.ini'
ini.write_text(ini.read_text().replace('SaveDrawCount = 17','SaveDrawCount = 100'))
with zipfile.ZipFile(sorted((root/'local/pcsx2/sstates').glob('*.p2s'))[0]) as state:
    ram=state.read('eeMemory.bin')
    frozen=bytearray(state.read('GS.bin'))
    privileged=state.read('PCSX2 Internal Structures.dat')[5834:5834+8192]
frozen[512:-128]=bytes(len(frozen)-640)
env=0x23ed70
packet=bytearray(ram[env+0x90:env+0x120])
packet[1]&=0x7f
packet+=gs.reglist([(0x4e,0x100),(0x42,0x44),(0x4a,0)])
def sprite(bounds,rgba,z,blend=True):
    x,y,right,bottom=bounds
    data=bytearray(gs.packed_prim(0x46 if blend else 6,(x,y),(right,bottom),rgba,None))
    for vertex in (0,1):
        # Packed register 4 is XYZF2. Four padding bits precede its 24-bit Z.
        struct.pack_into('<I',data,16+48*vertex+32+8,z<<4)
    return data
expected=[]
for mode,top in [(8,0),(9,112)]:
    # Two equal RGB backgrounds with opposite destination alpha MSBs. The
    # boundary across x tests source alpha. Y distinguishes the two Z modes.
    packet+=gs.reglist([(0x47,0x30803)])
    for y,alpha in [(top,0),(top+56,128)]:
        packet+=sprite((0,y,640,y+56),(192,0,0,alpha),1 if mode==8 else 100,False)
    packet+=gs.reglist([(0x47,0x70009 if mode==8 else 0x30009)])
    for x,alpha in [(0,0),(320,128)]:
        packet+=sprite((x,top,x+320,top+112),(0,0,0,alpha),100 if mode==8 else 1)
    packet+=gs.reglist([(0x47,0x7001b)])
    packet+=sprite((0,top,640,top+112),(0,192,0,128),10)
    for y in [top+10,top+70]:
        for x in [10,330]:
            old=(mode==8)==(x<320)
            expected.append(dict(mode=mode,x=x,y=y,rgb=[192,0,0] if old else [0,192,0]))
packets=gs.transfer(packet,2)+b'\x03'+privileged+bytes((1,0))
(work/'gates.gs.zst').write_bytes(zstd.compress(struct.pack('<II',0x0d03c0a3,len(frozen))+frozen+privileged+packets,4))
runner=(root/'analysis/native-core/grade-pc-10/run-reference.ps1').read_text()
(work/'run-reference.ps1').write_text(runner.replace('$Fixture="grade"','$Fixture="gates"').replace('$need=8','$need=10'))
(evidence/'expected.json').write_text(json.dumps(dict(
    scope='Synthetic untextured sprites substituting two palette alpha outputs. Z relative ordering only.',
    test_registers=['0x30803','0x70009','0x30009','0x7001b'],expected=expected),indent=2))
