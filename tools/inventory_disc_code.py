"""Inventory executable payloads without inferring code type from a file suffix alone."""
import hashlib
import json
import struct
from pathlib import Path

from iso9660 import Iso9660

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'analysis/decompiled-iop'
WORK = ROOT/'local/iop-analysis'
ELF = b'\x7fELF'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cstr(data, pos):
    return data[pos:data.index(0, pos)].decode('ascii', 'replace')


def describe_module(name, disk, offset, data):
    if not data.startswith(ELF+b'\x01\x01\x01'):
        raise ValueError(f'{name}: unexpected ELF identity')
    kind, machine, _, entry, phoff, shoff, flags, _, phsize, phnum, shsize, shnum, shstr = struct.unpack_from('<HHIIIIIHHHHHH',data,16)
    if machine!=8 or kind not in (0xff80,0xff81) or phsize!=32 or shsize!=40:
        raise ValueError(f'{name}: unexpected IOP ELF layout {kind:x}/{machine}')
    ph=[struct.unpack_from('<8I', data, phoff+i*phsize) for i in range(phnum)]
    sh=[struct.unpack_from('<10I', data, shoff+i*shsize) for i in range(shnum)]
    names=[cstr(data,sh[shstr][4]+row[0]) for row in sh]
    sect=dict(zip(names,sh))
    text=sect['.text']
    meta=sect['.iopmod']
    m=data[meta[4]:meta[4]+meta[5]]
    text_id=names.index('.text')
    encoded_name=cstr(m,26) if 0 in m[26:] else m[26:].decode('ascii','replace')
    funcs={}
    symbols={}
    sources=[]
    for sym in sh:
        if sym[1]!=2: continue
        strings=sh[sym[6]][4]
        for p in range(sym[4],sym[4]+sym[5],16):
            ix,va,size,info,_,section=struct.unpack_from('<IIIBBH',data,p)
            symbol=cstr(data,strings+ix)
            if info&15==4 and symbol: sources.append(symbol)
            if symbol and section<len(names) and section>0:
                symbols.setdefault(va,[]).append(dict(name=symbol,size=size,section=names[section],type=info&15))
            if section==text_id and info&15==2 and symbol:
                funcs.setdefault(va,[]).append(dict(name=symbol,size=size))
    code=data[text[4]:text[4]+text[5]]
    imports=[];exports=[]
    for pos in range(0,len(code)-20,4):
        magic=struct.unpack_from('<I',code,pos)[0]
        if magic not in (0x41e00000,0x41c00000): continue
        raw=code[pos+12:pos+20].split(b'\0')[0]
        if not raw or not all(0x21<=c<0x7f for c in raw):continue
        rec=dict(library=raw.decode(),address=pos+text[3],version=struct.unpack_from('<H',code,pos+8)[0],slots=[])
        q=pos+20
        if magic==0x41e00000:
            while q+8<=len(code):
                jr,li=struct.unpack_from('<II',code,q)
                if jr!=0x03e00008 or li>>16!=0x2400: break
                rec['slots'].append(dict(address=text[3]+q,ordinal=li&65535,
                                         symbol=next((s['name'] for s in symbols.get(text[3]+q,[]) if s['section']=='.text'),None)))
                q+=8
            imports.append(rec)
        else:
            while q+4<=len(code):
                ptr=struct.unpack_from('<I',code,q)[0]
                if (not ptr and rec['slots']) or ptr>=len(code) or ptr%4:break
                rec['slots'].append(dict(ordinal=len(rec['slots']),address=ptr))
                q+=4
            exports.append(rec)
    return dict(name=name,disc_path=disk,disc_offset=offset,bytes=len(data),sha256=sha(data),elf_type=hex(kind),
                elf_machine=machine,elf_flags=hex(flags),entry=entry,gp=struct.unpack_from('<I',m,8)[0],
                iopmod_name=encoded_name,iopmod_version=struct.unpack_from('<H',m,24)[0],
                text_address=text[3],text_file_offset=text[4],text_size=text[5],text_sha256=sha(code),
                symbols=[dict(address=a,names=v) for a,v in sorted(funcs.items())],imports=imports,exports=exports,
                elf_source_file_symbols=sources,sections=[dict(name=n,type=s[1],flags=s[2],address=s[3],file_offset=s[4],size=s[5]) for n,s in zip(names,sh)],
                load_segments=[dict(file_offset=s[1],va=s[2],bytes=s[4],mem_size=s[5]) for s in ph if s[0]==1])


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    modules=WORK/'inputs'
    modules.mkdir(parents=True,exist_ok=True)
    iso_manifest=json.loads((ROOT/'analysis/iso_manifest.json').read_bytes())
    iso=next(ROOT.glob('*.iso'))
    rows=[];containers=[];top=[]
    def add(name,disk,off,data):
        row=describe_module(name,disk,off,data)
        (modules/name).write_bytes(data)
        (modules/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8')
        rows.append(row)
    with iso.open('rb') as fp:
        for r in iso_manifest['entries']:
            if r['kind']!='file': continue
            fp.seek(r['offset']);magic=fp.read(16)
            top.append(dict(path=r['path'],size=r['size'],offset=r['offset'],magic=magic.hex()))
            if r['path'].startswith('IRX/'):
                fp.seek(r['offset']);data=fp.read(r['size'])
                if data.startswith(ELF):
                    add(Path(r['path']).name,r['path'],r['offset'],data)
                elif r['path']=='IRX/IOPRP.IMG':
                    if not data.startswith(b'RESET\0') or data[16:23]!=b'ROMDIR\0':raise ValueError('IOPRP ROMDIR not found')
                    limit=struct.unpack_from('<I',data,28)[0];cursor=0
                    for i in range(0,limit,16):
                        key,extra,n=struct.unpack_from('<10sHI',data,i)
                        key=key.split(b'\0')[0].decode('ascii')
                        if not key:break
                        if cursor+n>len(data): raise ValueError('IOPRP member outside image')
                        piece=data[cursor:cursor+n];containers.append(dict(name=key,image_offset=cursor,size=n,magic=piece[:8].hex()))
                        if piece.startswith(ELF):add('ROM_'+key+'.IRX',r['path']+'!'+key,r['offset']+cursor,piece)
                        cursor=(cursor+n+15)&~15
        fads=json.loads((ROOT/'analysis/fad_manifest.json').read_bytes())['archives']
        active=next(a for a in fads if a['name']=='DISC.FAD')
        matches=[];checked=0
        for r in active['records']:
            if r['kind']!='file':continue
            fp.seek(active['payload_base']+2048*r['sector']);head=fp.read(min(4,r['size']));checked+=1
            if head==ELF:matches.append(r['path'])
    scenarios=[]
    for name in ['sn2','sn4','sn4g']:
        data=json.loads((ROOT/'analysis'/('script_program'+('' if name=='sn4g' else '_'+name)+'.json')).read_bytes())
        scenarios.append(dict(name=name,**{k:data[k] for k in ['program_id','blocks','instructions','labels','text_records','undecoded_text_records','complete_execution']}))
    result=dict(iso_sha256_from_existing_integrity_manifest=iso_manifest['source'],iso_file_count=len(top),iso_files=top,
                modules=rows,ioprp_directory=containers,active_fad=dict(name='DISC.FAD',member_starts_checked=checked,elf_header_hits=matches),
                alternate_disc_indices=[dict(name=a['name'],index_entries=a['file_count'],payload_base=a.get('payload_base')) for a in fads if a is not active],
                scenario_programs=scenarios,
                scope='Inspects ISO file starts, IOPRP ROMDIR entries and active FAD payload starts. Overlays without ELF headers, executable data embedded in arbitrary assets and VU programs are not excluded. No whole-game completeness claim.')
    (OUT/'disc-inventory.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(modules=len(rows),functions={r['name']:len(r['symbols']) for r in rows},fad=checked,elf_hits=matches)))


if __name__=='__main__':main()
