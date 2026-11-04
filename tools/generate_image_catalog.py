"""Bind native image cache entries to original IPU and strict decode evidence."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from vm_handlers import Image

ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    report_path=ROOT/'analysis/scenario_decode.json'
    report=json.loads(report_path.read_text(encoding='utf-8'))
    elf=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    prefix_address=elf.word(0x22acc8+6*68+12)
    prefix_offset=elf.offset(prefix_address)
    prefix=elf.data[prefix_offset:prefix_offset+64].split(b'\0',1)[0].decode('ascii')
    entries=[]
    for row in report['results']:
        if not row['source'].lower().endswith('.ipu') or row.get('decoded_frame_count')!=1:continue
        if row['status']!='strict-decode-passed' or row['returncode']!=0 or row['error_lines']:
            raise ValueError('Image decode not certified')
        source=ROOT/'local/assets'/row['source']
        original=source.read_bytes()
        if sha(original)!=row['source_sha256']:raise ValueError('Original IPU changed')
        if original[:4]!=b'ipum' or len(original)<16:raise ValueError('Wrong original IPU')
        width,height,frames=struct.unpack_from('<HHI',original,8)
        if frames!=1:raise ValueError('Image cache is not a full single-frame source')
        decoded=Path(row['first_frame']).resolve()
        if not decoded.is_relative_to((ROOT/'captures/derived').resolve()):
            raise ValueError('Certified decode output is outside the derived-asset directory')
        pixels_file=decoded.read_bytes()
        digest=sha(pixels_file)
        if digest!=row['first_frame_sha256'] or sha(Path(row['log']).read_bytes())!=row['log_sha256']:
            raise ValueError('Derived PNG or strict decode log changed')
        if sha(Path(row['input']).read_bytes())!=row['input_sha256']:
            raise ValueError('Strictly decoded input changed')
        png=ROOT/'local/port-assets/scenes'/(digest+'.png')
        if png.exists():
            if sha(png.read_bytes())!=digest:raise ValueError('Native image cache entry changed')
        else:
            png.parent.mkdir(parents=True,exist_ok=True)
            tmp=tempfile.NamedTemporaryFile(dir=png.parent,delete=False)
            pending=Path(tmp.name)
            try:
                with tmp:
                    tmp.write(pixels_file)
                pending.replace(png)
            finally:
                pending.unlink(missing_ok=True)
        entries.append(dict(virtual_name=prefix+source.name,source_path=source.relative_to(ROOT).as_posix(),
            png_path=png.relative_to(ROOT).as_posix(),source_sha256=row['source_sha256'],png_sha256=row['first_frame_sha256'],
            source_size=len(original),width=width,height=height))
    entries.sort(key=lambda r:r['virtual_name'])
    if not entries or len({r['virtual_name'] for r in entries})!=len(entries):raise ValueError('Empty/ambiguous image catalog')
    text='// Generated only from original IPU + strict-decode-passed evidence.\n#pragma once\n#include <array>\n#include <cstdint>\nnamespace kx3::platform {\n'
    text+='struct ImageBinding { const char *virtual_name, *source_path, *png_path, *source_sha256, *png_sha256; std::uint32_t source_size,width,height; };\n'
    text+=f'inline constexpr std::array<ImageBinding,{len(entries)}> image_bindings = {{{{\n'
    for r in entries:
        values=[json.dumps(r[k],ensure_ascii=True) for k in ('virtual_name','source_path','png_path','source_sha256','png_sha256')]
        values += [str(r[k]) for k in ('source_size','width','height')]
        text+='    {'+','.join(values)+'},\n'
    text+='}};\n}\n'
    (ROOT/'port/platform/image_catalog.hpp').write_text(text,encoding='utf-8')
    result=dict(schema=1,elf_sha256=elf.sha256,decode_report_sha256=sha(report_path.read_bytes()),entries=entries)
    (ROOT/'analysis/native-core/image-catalog.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(images=len(entries),original_virtual_directory=prefix)))
if __name__=='__main__':main()
