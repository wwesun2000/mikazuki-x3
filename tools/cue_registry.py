"""Original 101710 ScenePack relocation IDs and 101928 cue lookup.

Works on immutable parsed originals. Disk trailer16 is overwritten in RAM;
the computed signed16 ID is the value used by ScriptData+E0.
"""
import json
from pathlib import Path
from scenario_resources import ROOT, ResourceIndex, SPK_SHA, require
from vm_handlers import Image
from vm_presentation_semantics import extended_decode


def cue_hash(name):
    data = name.encode('ascii')
    require(b'\0' not in data, 'Embedded NUL')
    total = sum(b << (b & 7) for b in data) & 0xffffffff
    return ((total & 255) + (total >> 8)) & 255


def registry(index):
    """Exact nested iteration, including repeated pointers if ever present."""
    require(index.spk_sha256 == SPK_SHA, 'Unexpected original ScenePack')
    assigned, serial = {}, 0
    for block in index.blocks:
        for scene in sorted(block['scenes'], key=lambda s:(s['bucket'],s['symbol_offset'])):
            require(cue_hash(scene['name']) == scene['bucket'], 'Scene bucket/hash mismatch')
            for cue in scene['cues']:
                require(cue_hash(cue['name']) == cue['unknown16'], 'Cue hash mismatch')
                key = (block['index'],cue['record_offset'])
                unsigned = serial & 65535
                assigned[key] = dict(name=cue['name'],scene=scene['name'],block=block['index'],
                    record_offset=cue['record_offset'],id=unsigned-65536 if unsigned>=32768 else unsigned,
                    assignment_ordinal=serial,original_trailer=cue['unknown_trailer16'])
                serial += 1
    return dict(count=serial,records=list(assigned.values()))


def lookup(index, name):
    """101DC0 first-underscore prefix, first matching block/bucket scene.

Missing scenes/cues return -1 as the original lookup. Bounds failures remain
errors in the parser. No on-disk pointer is ever patched.
"""
    scene_name = name.split('_',1)[0]
    group = None
    for block in index.blocks:
        group = next((s for s in block['scenes'] if s['bucket']==cue_hash(scene_name) and s['name']==scene_name),None)
        if group is not None:
            break
    if group is None:
        return -1
    cue = next((c for c in group['cues'] if c['unknown16']==cue_hash(name) and c['name']==name),None)
    if cue is None:
        return -1
    row = next(r for r in registry(index)['records'] if r['block']==block['index'] and r['record_offset']==cue['record_offset'])
    return row['id']


def report():
    index = ResourceIndex.from_project()
    image = Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    regions = []
    for start,end in [(0x1016c0,0x101710),(0x101710,0x101928),(0x101928,0x101a58),
                      (0x101aa8,0x101ac8),(0x101af8,0x101b58),(0x101b58,0x101ca8),(0x101dc0,0x101f50)]:
        region = image.region(start,end)
        for row in region['instructions']:
            row['extended_decode'] = extended_decode(int(row['raw_word'],16),int(row['address'],16))
        regions.append(region)
    require(image.word(0x101898)==0x32a5ffff and image.word(0x1018a4)==0x26b50001,'Relocation serial writes differ')
    return dict(schema=1,evidence='source-static-not-runtime',elf_sha256=image.sha256,spk_sha256=index.spk_sha256,
        runtime=registry(index),samples={name:lookup(index,name) for name in ['top0000_00','pr0000_00','pr5011m_00','pr1034_00']},
        regions=regions)


if __name__=='__main__':
    result=report()
    (ROOT/'analysis/cue_registry.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(count=result['runtime']['count'],samples=result['samples'])))
