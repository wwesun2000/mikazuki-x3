"""Source-bound renderer data and evidence for the recovered original text pump.

Use Python 3.14 for the Zstandard member in the original PCSX2 archive.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib
from scenario import parse_font

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA = '46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'
LOVE_SHA = 'b0b84740ca2a246b2c50d94851c850a4b568a068a0e7faadaf16063716e0c952'


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def require_digest(data: bytes, expected: str) -> None:
    if digest(data) != expected:
        raise ValueError('Original evidence SHA-256 mismatch')


def swizzle_clut(linear: bytes) -> bytes:
    result = bytearray(64)
    for index in range(16):
        x, y = index % 8, index // 8
        offset = ((x // 2) * 4 + 2*y + (x % 2)) * 4
        result[offset:offset+4] = linear[4*index:4*index+4]
    return bytes(result)


def atlas_png(asset: bytes) -> bytes:
    palette = []
    for index in range(16):
        r,g,b,a = asset[128+4*index:132+4*index]
        if a > 128:
            raise ValueError('Unexpected original CTF alpha')
        palette.append(bytes((r,g,b,a*255//128)))
    rows = bytearray()
    for y in range(128):
        rows.append(0)
        for x in range(128):
            byte = asset[192+y*64+x//2]
            rows.extend(palette[(byte >> (4*(x%2))) & 15])

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack('>I',len(data)) + kind + data + struct.pack('>I',zlib.crc32(kind+data))

    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',128,128,8,6,0,0,0))+
            chunk(b'IDAT',zlib.compress(rows,9))+chunk(b'IEND',b''))


def audit_font_runs() -> list[dict]:
    expected={'sn2':'396d03ea918799696e06495813c0369c8059b18c1ddf1e74b4d1595b4bb84738',
              'sn4':'a3dac7e146cc970e4c8ae2c191afa4ffd2592765c0f11e300a66b7ddf12d00c7',
              'sn4g':'c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3'}
    result=[]
    for name,identity in expected.items():
        source=ROOT/'local/assets/SCENARIO'/f'{name}.fnt'
        data=source.read_bytes();require_digest(data,identity)
        records=0;rows=0
        for group in parse_font(data)['groups']:
            for glyph in group['glyphs']:
                record=glyph['record_offset'];position=glyph['payload_offset'];width=data[record+4]
                records+=1
                for _ in range(data[record+6]):
                    filled=0;rows+=1
                    while filled<width:
                        if position>=len(data):raise ValueError('Original glyph data truncated')
                        run=data[position]>>4;position+=1
                        if run==0 or filled+run>width:raise ValueError('Original glyph uses an unsupported run')
                        filled+=run
        result.append(dict(source=source.relative_to(ROOT).as_posix(),sha256=identity,records=records,rows=rows,
                           all_rows_reach_declared_width=True,zero_runs=0,overlong_runs=0))
    return result


def build() -> dict:
    elf = (ROOT/'local/extracted/SLPM_664.52').read_bytes()
    require_digest(elf,ELF_SHA)
    state = ROOT/'analysis/observations/OBS-001/pcsx2/sstates/SLPM-66452 (0D03C0A3).07.p2s'
    require_digest(state.read_bytes(),STATE_SHA)
    with zipfile.ZipFile(state) as archive:
        ram = archive.read('eeMemory.bin')
        gs = archive.read('GS.bin')
    if len(ram)!=32*1024*1024 or ram[0x100000:0x204b38]!=elf[0x1000:0x105b38]:
        raise ValueError('Snapshot executable text differs from the original ELF')
    asset = (ROOT/'local/assets/EFFECT/love.ctf').read_bytes()
    require_digest(asset,LOVE_SHA)
    if len(asset)!=8384 or ram[0x23a500:0x23a580]!=asset[:128]:
        raise ValueError('Runtime texture descriptor differs from CTF header')
    table = struct.unpack_from('<3I',elf,0x228bb8+4*12-0xff000)
    if table[:2]!=(0x44,4) or elf[table[2]-0xff000:].split(b'\0',1)[0]!=b'EFFECT/love.ctf':
        raise ValueError('Original texture table entry 4 changed')
    cluts = []
    for name,bank,linear,source in [
        ('text',0x2e40,ram[0x1e44180:0x1e441c0],'eeMemory.bin@0x01e44180'),
        ('style9-icons',0x3000,asset[128:192],'EFFECT/love.ctf@0x80')]:
        # Observed GS.bin byte offset in PCSX2 v2.8.2 slot7. The complete
        # 64-byte match is checked for two separate original memory banks.
        file_offset=0x1a9+bank*256
        placed=swizzle_clut(linear)
        if gs[file_offset:file_offset+64]!=placed:
            raise ValueError(f'{name} CLUT differs in original GS state')
        cluts.append(dict(name=name,source=source,cbp=hex(bank),rgba=[list(linear[i:i+4]) for i in range(0,64,4)],
                          linear_hex=linear.hex(),linear_sha256=digest(linear),
                          gs_bin_offset=file_offset,gs_bin_hex=placed.hex(),gs_bin_matched_bytes=64))
    destination=ROOT/'analysis/text-render/atlas4-love.png'
    destination.parent.mkdir(parents=True,exist_ok=True)
    png=atlas_png(asset)
    if destination.exists() and destination.read_bytes()!=png:
        raise ValueError('Refuse to replace different atlas derivative')
    if not destination.exists():
        destination.write_bytes(png)
    selected = {}
    directories=['vm-execution-chain-v1','choice-runtime-v1','text-pump-direct-v1',
                 'text-pump-closure-v1','text-glyph-closure-v1','text-gs-clut-v1']
    entries={0x1126e0,0x119f80,0x16b200,0x16b498,0x16b608,0x16adc8,0x168d08,0x168dd0,
             0x16bfa8,0x1698a0,0x169218,0x16c280,0x169368,0x169600,0x10b290,0x17a6e8}
    for directory in directories:
        for path in (ROOT/'analysis/ghidra'/directory/'functions').glob('*.json'):
            if int(path.stem,16) not in entries:
                continue
            data=json.loads(path.read_text())
            for unit in data['disassembly']['units']:
                off=unit['canonical_elf_file_offset'];raw=bytes.fromhex(unit['raw_hex'])
                if elf[off:off+len(raw)]!=raw:
                    raise ValueError('Dossier original instruction mismatch')
            selected[path.stem]={'dossier':path.relative_to(ROOT).as_posix(),'sha256':digest(path.read_bytes())}
    if len(selected)!=len(entries):
        raise ValueError('Missing original function dossier')
    return dict(schema=1,source_elf_sha256=ELF_SHA,slot7_archive_sha256=STATE_SHA,gs_bin_sha256=digest(gs),
       source_function_dossiers=selected,cluts=cluts,font_run_audit=audit_font_runs(),
       glyph_layout=dict(stride=56,rgb='node+0..2',current='float32+4',step='float32+8',rect='4 signed32 at+C',
                         st='4 float32 at+1C',tex0='uint64+30',channel_data='channel+1C',
                         primary='font+8 -> channel',ruby='font+C -> channel',packing='low nibble first'),
       icon_atlas=dict(resource=4,source='EFFECT/love.ctf',sha256=LOVE_SHA,
                       descriptor='0x0023a500',tex0=hex(struct.unpack_from('<Q',asset,0x70)[0]),
                       image=destination.relative_to(ROOT).as_posix(),png_sha256=digest(png),
                       units={'817E':{'index':5,'xy':[32,0]},'81A2':{'index':6,'xy':[64,0]},'81A0':{'index':7,'xy':[96,0]}},
                       pixels='128x128 PSMT4; source CLUT starts at128, packed indices start at192',
                       preview_alpha='a*255//128; source palette in this report retains native alpha'),
       draw=dict(guard='font+28 zero',order='primary atlas upload and ascending pool draw, then ruby atlas upload and ascending pool draw',
                 source_calls=['16BAB8','169368','1697D0','169600'],tex1=0,alpha_1='0x44',test_1='0x31801',observed_prim='0xde',
                 source_vertices='Both use node RGB, CVT.W.S(node.current) alpha and STQ with Q=1',
                 texture_modulation='Cs.rgb=clamp8((CLUT.rgb * node.rgb)>>7); As=clamp8((CLUT.a * integer-current)>>7)',
                 blend='ALPHA fields 0,1,0,1: Cd + ((Cs-Cd)*As >>7)',
                 coordinates='GS x=(1728+x)*16, y=(1936+signed-trunc(y/2))*16; node rectangles preserve full-height logical coordinates'),
       limits=['The RGBA layer still needs stage-level frame/time/filter comparison.',
               '119F80 active RNG reaches GetThreadId/WaitSema/SignalSema; stock Ghidra oracle stops at syscall 1B5154.',
               'A presentation observer must stage output until its outer transaction commits.'])


if __name__=='__main__':
    report=build()
    path=ROOT/'analysis/text-render/font-render-evidence.json'
    path.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),cluts=len(report['cluts']),dossiers=len(report['source_function_dossiers']))))
