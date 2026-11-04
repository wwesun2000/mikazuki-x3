"""Decode the hash-bound original atlas0 CTF; no original program execution."""
import hashlib
import json
import struct
import zlib
from vm_handlers import Image,ROOT
from vm_presentation_semantics import extended_decode

SOURCE_SHA='1640696c4886e47890bd25651c6f1075ca9cf4c2a05a689e2fc373974ae296fb'


def decode(data):
    if hashlib.sha256(data).hexdigest()!=SOURCE_SHA:raise ValueError('Unexpected mark.ctf SHA')
    if len(data)!=8384 or not data.startswith(b'CTF V0.1:size= 128 x  128 :PSMT4'):raise ValueError('CTF header mismatch')
    tex0=struct.unpack_from('<Q',data,0x70)[0]
    fields=dict(tbp=tex0&0x3fff,tbw=(tex0>>14)&63,psm=(tex0>>20)&63,tw=(tex0>>26)&15,
        th=(tex0>>30)&15,cpsm=(tex0>>51)&15,csm=(tex0>>55)&1,csa=(tex0>>56)&31)
    if fields!=dict(tbp=12672,tbw=2,psm=20,tw=7,th=7,cpsm=0,csm=0,csa=0):raise ValueError('Unexpected TEX0')
    palette=[]
    for i in range(16):
        r,g,b,a=data[0x80+i*4:0x84+i*4]
        if a>128:raise ValueError('Unexpected palette alpha range')
        palette.append(bytes((r,g,b,min(255,a*255//128))))
    pixels=data[0xc0:];raw=bytearray();histogram=[0]*16
    for y in range(128):
        raw.append(0)
        for x in range(128):
            n=y*128+x;index=(pixels[n//2]>>(4*(n&1)))&15
            histogram[index]+=1;raw.extend(palette[index])
    def chunk(kind,body):
        return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body))
    png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',128,128,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(raw,9))+chunk(b'IEND',b'')
    return png,dict(tex0=hex(tex0),fields=fields,palette_offset=128,pixel_offset=192,pixel_size=8192,
        encoding='linear PSMT4 image-transfer input, low nibble first; GS upload handles local-memory layout',
        native_alpha='PS2alpha0..128 normalized toPNG0..255; sourcepalette values retained',
        source_palette_rgba=[list(data[0x80+i*4:0x84+i*4]) for i in range(16)],index_histogram=histogram)


def main():
    source=ROOT/'local/assets/EFFECT/mark.ctf';png,metadata=decode(source.read_bytes())
    target=ROOT/'captures/derived/atlas0-mark.png'
    if target.is_symlink():raise ValueError('Refuse linked output')
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        if target.read_bytes()!=png:raise ValueError('Refuse changed existing output')
    else:
        with target.open('xb') as f:f.write(png)
    image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    regions=[]
    for start,end in [(0x10B290,0x10B2A8),(0x10B0E8,0x10B1A8),(0x17A2E8,0x17A4FC)]:
        r=image.region(start,end)
        for ins in r['instructions']:ins['extended_decode']=extended_decode(int(ins['raw_word'],16),int(ins['address'],16))
        regions.append(r)
    table_offset=image.offset(0x228bb8,12)
    entry=struct.unpack_from('<3I',image.data,table_offset)
    if entry!=(ord('N'),0,0x228b40):raise ValueError('Unexpected atlas0 binding table entry')
    path_offset=image.offset(entry[2],len(b'EFFECT/mark.ctf\0'))
    raw_path=image.data[path_offset:path_offset+len(b'EFFECT/mark.ctf\0')]
    if raw_path!=b'EFFECT/mark.ctf\0':raise ValueError('Unexpected atlas0 source path')
    report=dict(evidence_id='ATLAS0-MARK-001',authority='source-bound static binding and offline decoder, visual atlas inspection',
        elf_sha256=image.sha256,source=str(source),source_sha256=SOURCE_SHA,output=str(target),
        output_sha256=hashlib.sha256(png).hexdigest(),atlas_token=SOURCE_SHA,metadata=metadata,
        binding={'table_address':'0x228BB8','table_file_offset':table_offset,'entry0_raw_hex':image.data[table_offset:table_offset+12].hex(),
            'path_address':hex(entry[2]),'path_file_offset':path_offset,'path_raw_hex':raw_path.hex(),
            'entry0':'typeN,resource index0,path228B40=EFFECT/mark.ctf',
            'runtime_slot':'10B290(0)=BSS23A300;loader copies128-byte CTF header,texture descriptor at+70',
            'upload':'17A2E8 uses data+128 CLUT; PSM20 branch uploads8x2 CLUT then advances by u32(header+0x60)*4=64bytes; common path uploads128x128PSMT4'},
        visual_check='128x128 output shows coherent original arrows/book/check icons;4D samplesu120..128,v48..56',
        limitations=['Offline decode is not original GS rendered pixel comparison','Modern alpha normalization is explicit; RGBbytes unmodified'],
        evidence_regions=regions)
    (ROOT/'analysis/atlas0_binding.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'output':str(target),'sha256':report['output_sha256']}))


if __name__=='__main__':main()
