"""Source-derived scene-primary-media selection and verified decoded asset binding.

This exposes a backend contract, not the PS2's full asynchronous decoder state.
No preload operation is modelled as an onscreen image change.
"""
import argparse
import json
from pathlib import Path
import struct

from scenario_resources import ROOT, ResourceIndex, sha, require
from vm_handlers import Image
from vm_presentation_semantics import extended_decode

TYPE_TABLE = 0x22acc8
REGIONS = [(0x137578,0x137698),(0x137ca8,0x137d78),
           (0x1384b0,0x138638),(0x1387a4,0x138930),
           (0x138930,0x138b30),(0x1383f0,0x138478),
           (0x135618,0x135708),(0x13efb8,0x13f010),
           (0x13f208,0x13f4e0),(0x1946e0,0x1947e8),
           (0x13bc64,0x13bde0),(0x140b30,0x140bc8)]


def read_types(image):
    rows=[]
    for i in range(16):
        address=TYPE_TABLE+i*68
        off=image.offset(address,68)
        raw=image.data[off:off+68]
        words=struct.unpack('<17I',raw)
        require(words[0]==i, 'Media type index mismatch')
        def cstr(ptr):
            at=image.offset(ptr)
            stop=image.data.find(b'\0',at,at+128)
            require(stop>=at, 'Unterminated media type string')
            return image.data[at:stop].decode('ascii')
        rows.append(dict(index=i,address=address,file_offset=off,raw_hex=raw.hex(),raw_sha256=sha(raw),
                         words=words,virtual_directory=cstr(words[3]),extension=cstr(words[4]),
                         replacement_extension=cstr(words[5]),primary_media_flag=words[8]))
    require([(r['extension'],r['primary_media_flag']) for r in rows[2:7]] ==
            [('m2s',1),('m2v',1),('mmv',1),('pss',1),('ipu',1)], 'Primary media table changed')
    return rows


def prepared_media(index, scene_name, root=ROOT, cue_name=None):
    """Bind one original primary media dependency to certified local derivatives.

    Supports only normal existing-file selection (no fallback replacement,
    preview-only load mode, multiple media candidates or implicit .m2s alias).
    """
    root=Path(root)
    types=read_types(Image((root/'local/extracted/SLPM_664.52').read_bytes()))
    lookup={r['extension']:r for r in types if r['extension']}
    scene=index.resolve(0x73,scene_name)
    candidates=[]
    for asset in scene['assets']:
        if asset['kind']!='file':continue
        row=lookup.get(asset['name'].rsplit('.',1)[-1])
        require(row is not None, 'Unresolved dependency media type')
        if row['primary_media_flag']:
            candidates.append((row,asset))
    require(len(candidates)==1, 'Only a unique primary media dependency is admitted')
    row,asset=candidates[0]
    require(not row['replacement_extension'], 'Extension substitution is unresolved')
    report=json.loads((root/'analysis/scenario_decode.json').read_text(encoding='utf-8'))
    derived=[x for x in report['results'] if x['source']==asset['fad_path'] and x['source_sha256']==asset['sha256']]
    require(derived and all(x['status']=='strict-decode-passed' for x in derived), 'Media lacks strict decode evidence')
    for d in derived:
        require(sha(Path(d['input']).read_bytes())==d['input_sha256'], 'Decoded input changed')
        require(d.get('first_frame') and sha(Path(d['first_frame']).read_bytes())==d['first_frame_sha256'], 'Decoded first frame changed')
    if cue_name:
        from scenario_cues import plan_cue
        cue=plan_cue(index,cue_name)
        require(index.resolve(0x74,cue_name)['scene']['name']==scene_name, 'Cue belongs to another scene')
        filenames=[e['filename'] for e in cue['events'] if 'filename' in e]
        require(filenames==[asset['name']], 'Cue movie operand differs from prepared media')
    return dict(scene=scene_name,spk_block=scene['spk_block'],primary_asset=asset,
                original_type=row,decoded=derived,preload_changes_display=False,
                cue=cue_name,
                native_binding_status='verified-static-pixels-backend-callback-required' if asset['extension']=='.ipu'
                    else 'decoded-video-members-sequencing-and-playback-backend-required',
                stage_contract=['preload 72 prepares/cache-only; retain current displayed media',
                                '73 finalized scene request identifies the prepared primary media',
                                '74 executes cue callbacks against prepared media; 07 is not a filename loader'],
                unresolved=['Exact presentation commit timing and asynchronous buffer ownership are not fully translated.',
                            'MMV member selection/repetition and full-frame timing must not be inferred from index order.'])


def build_report(root=ROOT):
    root=Path(root)
    image=Image((root/'local/extracted/SLPM_664.52').read_bytes())
    index=ResourceIndex.from_project(root)
    regions=[]
    for start,end in REGIONS:
        region=image.region(start,end)
        for inst in region['instructions']:
            address=int(inst['address'],16)
            inst['decoded']=extended_decode(image.word(address),address)
        regions.append(region)
    return dict(evidence_id='SCENARIO-MEDIA-BINDING-001',elf_sha256=image.sha256,spk_sha256=index.spk_sha256,
                media_types=read_types(image),evidence_regions=regions,
                priority_bindings=[prepared_media(index,n,root,c) for n,c in
                                   [('pr0000','pr0000_00'),('pr5011m','pr5011m_00'),('pr1034','pr1034_00')]],
                pointer_chain=[dict(function=0x1384b0,operation='dependency parse/type sort; first type+32 flagged media to global206250+3652'),
                               dict(function=0x138930,operation='copy primary filename global+3652 to +3698'),
                               dict(function=0x138420,operation='state5 calls13EFB8(global+3698) when media needs reprepare'),
                               dict(function=0x13efb8,operation='copy requested name to23D2A0 and set movie-worker pending flag'),
                               dict(function=0x13f208,operation='dispatch format and call1946E0 to prepare decoder input'),
                               dict(function=0x135660,operation='finalize pending scene identity and flags; renderer ownership remains external')])


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=ROOT/'analysis/scenario_media_binding.json')
    args=ap.parse_args()
    report=build_report()
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(bindings=len(report['priority_bindings']),types=len(report['media_types']))))
