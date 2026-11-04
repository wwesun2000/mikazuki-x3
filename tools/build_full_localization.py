"""Rebuildable source-bound localization shards. Never invents translations.

All framed primary/ruby records are catalogued; this is still partial game-wide
coverage. Existing translations/reviews/notes survive identical-source rebuilds.
Changed source metadata or removed IDs abort before any output file is replaced.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile

import localization as loc
from build_script_program import SOURCES, FORMAT, SourceScript
from vm_control_semantics import runtime_label_ids
from opening_instructions import frame_text
from vm_handlers import ROOT

ISO_SHA='2a193cdbe97ba96faf0ad4d376a1d45b765aa99625895ff161f5102a5e85c95d'
NAMES=('sn2','sn4','sn4g')
OUTPUT=ROOT/'localization/full-source'
PROGRAM_DIR=ROOT/'analysis/script-programs'
EXPECTED_COUNTS={'sn2':10308,'sn4':18634,'sn4g':32255}
SOURCE_KEYS=(*loc.SOURCE_FIELDS,'record_kind','program','selector','public_label_context','decode_status')


def sha(data):return hashlib.sha256(data).hexdigest()


def require(condition,message):
    if not condition:raise ValueError(message)


def read_program(path,source_path):
    envelope=loc.load_json(path)
    require(envelope.get('format')==FORMAT and isinstance(envelope.get('payload'),str),'Program envelope format')
    require(sha(envelope['payload'].encode('utf-8'))==envelope.get('sha256'),'Program envelope SHA mismatch')
    payload=json.loads(envelope['payload'])
    source=source_path.read_bytes();digest=sha(source)
    require(digest in SOURCES,'Unrecognized original script SHA')
    name,size=SOURCES[digest]
    require(len(source)==size and payload.get('schema')==1,'Script size/program schema mismatch')
    require(payload.get('source')==dict(path=f'SCENARIO/{name}.sn4',sha256=digest,size=size),'Program source identity mismatch')
    parsed_source=SourceScript(source);label_rows=runtime_label_ids(parsed_source)
    expected_selectors={b['index'] for b in parsed_source.blocks if b['kind']=='SCR-file'}
    require({b['selector'] for b in payload['blocks']}==expected_selectors,'Stored block coverage differs from source')
    for block in payload['blocks']:
        selector=block['selector'];original,parsed=parsed_source.block(selector)
        labels={s['name']:original['offset']+s['destination_offset'] for s in parsed['symbols']}
        metadata={r['label']:dict(id=r['runtime_label_id'],internal=r['internal'])
            for r in label_rows if r['block_selector']==selector}
        require(block['labels']==labels and block['label_metadata']==metadata,'Public/internal label context differs from original symbol tables')
        require(block['code_start']==original['offset']+parsed['code_offset'] and
            block['code_end']==original['offset']+original['size'],'Code region differs from original SCR header')
    return payload,envelope['sha256'],source


def extract_block(program,program_id,source,block):
    name=Path(program['source']['path']).stem;selector=block['selector']
    require(type(selector) is int and 0<=selector<32,'Invalid source selector')
    cursor=block['code_start'];end=block['code_end'];joined=[];boundaries=set()
    for row in block['instructions']:
        require(row['offset']==cursor and row['next']>cursor and row['next']<=end,'Instruction coverage mismatch')
        raw=bytes.fromhex(row['raw_hex'])
        require(raw==source[cursor:row['next']] and raw[0]==row['op'],'Program raw instruction differs from source')
        joined.append(raw);boundaries.add(cursor);cursor=row['next']
    require(cursor==end and sha(b''.join(joined))==block['code_sha256'],'Code hash/bounds mismatch')
    public=defaultdict(list)
    for label,offset in block['labels'].items():
        require(offset in boundaries,'Label not at instruction boundary')
        metadata=block['label_metadata'][label]
        require(metadata['internal']==label.startswith('_'),'Label kind mismatch')
        if not metadata['internal']:public[offset].append(label)
    positions=sorted(public);entries=[]
    for row in block['instructions']:
        records=[]
        if row['op']==2:
            require(isinstance(row.get('text'),dict),'Missing primary text record')
            records.append(('primary_text',row['text']))
        if row['op']==6:
            require(isinstance(row.get('ruby'),list),'Missing ruby records')
            records.extend(('ruby',r) for r in row['ruby'])
        for kind,record in records:
            start=record['offset'];group=frame_text(source,start,row['next'])
            require(row['offset']<=start<group['end_exclusive']<=row['next'],'Record outside owner instruction')
            if kind=='primary_text':require(start==row['offset'] and group['end_exclusive']==row['next'],'Primary record coverage')
            text_bytes=b''.join(bytes.fromhex(u['raw_hex']) for u in group['units'])
            original=text_bytes.decode('cp932',errors='strict')
            expected_id=f'{name}:{selector:02x}:{start:08x}'
            require(record.get('id')==expected_id and record.get('raw_hex')==text_bytes.hex(),'Record identity/bytes mismatch')
            require(record.get('text')==original and record.get('skip_21_offsets')==group['skip_21_offsets'],'Record decode/markers mismatch')
            at=bisect_right(positions,start)-1
            labels=sorted(public[positions[at]]) if at>=0 else []
            raw=source[start:group['end_exclusive']]
            context=f'{kind}; program={name}; selector={selector}; nearest static public labels={json.dumps(labels,ensure_ascii=False)}; static locality is not execution order'
            entries.append(dict(entry_id=expected_id,original=original,source_hash=loc.text_hash(original),
                context=context,tokens=[],record_kind=kind,program=name,selector=selector,
                public_label_context=dict(labels=labels,offset=positions[at] if at>=0 else None,
                    relationship='nearest preceding public-label destination in same stored block; not runtime caller'),
                decode_status='strict-cp932; original-font-mapping-not-fully-verified',
                location=dict(path=program['source']['path'],offset=start,length=len(raw),
                    script_sha256=program['source']['sha256'],program_sha256=program_id,
                    raw_hex=raw.hex(),raw_sha256=sha(raw),text_bytes_hex=text_bytes.hex(),text_bytes_sha256=sha(text_bytes),
                    skip_21_offsets=group['skip_21_offsets'],container_offset=row['offset'],
                    container_length=row['next']-row['offset'],container_opcode=row['op'])))
    require(len({e['entry_id'] for e in entries})==len(entries),'Duplicate text ID')
    return entries


def coverage(scope):
    return dict(status='partial',scope=scope,evidence=[
        'All primary02 and nested06/02 ruby records in the three SHA-bound compiled programs are indexed.',
        'Exact original script bytes, instruction coverage and strict CP932 decoding rechecked by build_full_localization.py.',
        'Not complete game-wide coverage: other string operands, binary/system UI, image lettering, movies, dynamic text and font mapping remain unaudited.',
        'Labels describe static source locality; no claim of sequential play order or branch coverage.'])


def make_pair(entries,scope):
    baseline=dict(schema_version=1,kind='source-baseline',artifact_sha256=ISO_SHA,
        entry_count=len(entries),coverage=coverage(scope),entries=deepcopy(entries))
    baseline['source_digest']=loc.source_digest(baseline)
    catalog=deepcopy(baseline);catalog.pop('source_digest')
    catalog.update(kind='localization-catalog',baseline_digest=baseline['source_digest'],holistic_reviews={})
    for e in catalog['entries']:
        e['targets']={language:dict(text='',status='untranslated') for language in loc.LOCALES}
    return baseline,catalog


def merge_existing(baseline,catalog,old_baseline=None,old_catalog=None):
    if old_baseline is None and old_catalog is None:return catalog
    require(old_baseline is not None and old_catalog is not None,'Incomplete existing baseline/catalog pair; refusing overwrite')
    checked=loc.validate(old_catalog,old_baseline)
    require(checked['ok'],'Existing localization invalid; untouched: '+ '; '.join(checked['errors'][:5]))
    require(old_baseline==baseline,'Source baseline changed; create a separate version instead of replacing existing targets')
    old={e['entry_id']:e for e in old_catalog['entries']}
    fresh_index={e['entry_id']:e for e in baseline['entries']}
    require(set(old)=={e['entry_id'] for e in baseline['entries']},'Existing source ID set differs; refusing to drop entries')
    out=deepcopy(old_catalog)
    for entry in out['entries']:
        source=old[entry['entry_id']]
        #Check extra provenance too; the generic gate binds its source fields.
        fresh=fresh_index[entry['entry_id']]
        for key in SOURCE_KEYS:
            require(source.get(key)==fresh.get(key),f'{entry["entry_id"]}: source provenance changed')
    return out


def gate(baselines,catalogs,holistic,release=False,locales=loc.LOCALES):
    entries=[e for b in baselines for e in b['entries']]
    baseline,catalog=make_pair(entries,'all three original programs; all framed primary/ruby text records')
    catalog['entries']=[deepcopy(e) for c in catalogs for e in c['entries']]
    catalog['holistic_reviews']=deepcopy(holistic)
    result=loc.validate(catalog,baseline,release=release,locales=locales)
    return result,baseline['source_digest']


def _encoded(document):return (json.dumps(document,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')


def write_batch(documents,observed):
    """All validation precedes writes; detect changes since initial catalog reads."""
    for path,old in observed.items():
        require((sha(path.read_bytes()) if path.exists() else None)==old,f'Concurrent edit at {path}; no writes performed')
    changed=[]
    for path,document in documents.items():
        payload=_encoded(document)
        if path.exists() and path.read_bytes()==payload:continue
        #Formatting/extra translator fields in existing catalogs are preserved.
        if path.exists() and loc.load_json(path)==document:continue
        path.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.building-',suffix='.tmp',delete=False) as f:
            temp=Path(f.name);f.write(payload);f.flush();os.fsync(f.fileno())
        try:
            require((sha(path.read_bytes()) if path.exists() else None)==observed.get(path),f'Concurrent edit at {path}; replacement refused')
            os.replace(temp,path)
        finally:
            if temp.exists():temp.unlink()
        changed.append(str(path))
    return changed


def build(output=OUTPUT,*,check_only=False,release=False,locales=loc.LOCALES,program_dir=None,source_dir=None):
    output=Path(output)
    program_dir=Path(program_dir or PROGRAM_DIR)
    source_dir=Path(source_dir or ROOT/'local/assets/SCENARIO')
    documents={};observed={};groups=[];program_summaries=[];all_entries=[]
    for name in NAMES:
        program,program_id,source=read_program(program_dir/f'{name}.program.json',source_dir/f'{name}.sn4')
        require(Path(program['source']['path']).stem==name,'Filename/source program mismatch')
        program_count=0;kinds=Counter()
        for block in program['blocks']:
            entries=extract_block(program,program_id,source,block);program_count+=len(entries)
            kinds.update(e['record_kind'] for e in entries);all_entries.extend(entries)
            stem=f'{name}/block-{block["selector"]:02d}'
            bp=output/f'{stem}.baseline.json';cp=output/f'{stem}.catalog.json'
            baseline,catalog=make_pair(entries,f'{name} stored block {block["selector"]}')
            for path in (bp,cp):observed[path]=sha(path.read_bytes()) if path.exists() else None
            if check_only:require(bp.exists() and cp.exists(),f'Missing shard {stem}')
            oldb=loc.load_json(bp) if bp.exists() else None;oldc=loc.load_json(cp) if cp.exists() else None
            catalog=merge_existing(baseline,catalog,oldb,oldc)
            groups.append(dict(program=name,selector=block['selector'],baseline_path=bp,catalog_path=cp,
                baseline=baseline,catalog=catalog,program_sha256=program_id))
        require(program_count==EXPECTED_COUNTS[name],f'{name}: unexpected framed text count')
        program_summaries.append(dict(program=name,source=program['source'],program_sha256=program_id,
            entry_count=program_count,record_kinds=dict(kinds),shards=len(program['blocks'])))
    #Untracked old catalog shards must not become silently orphaned.
    known={g['catalog_path'].resolve() for g in groups}
    if output.exists():
        extras=[p for p in output.glob('*/block-*.catalog.json') if p.resolve() not in known]
        require(not extras,'Existing orphan catalog shards; refusing to omit them')
    for g in groups:
        catalog=g['catalog']
        checked=loc.validate(catalog,g['baseline'])
        require(checked['ok'],'Shard validation failed: '+ '; '.join(checked['errors'][:5]))
        documents[g['baseline_path']]=g['baseline'];documents[g['catalog_path']]=catalog
    hp=output/'holistic-reviews.json';observed[hp]=sha(hp.read_bytes()) if hp.exists() else None
    holistic=loc.load_json(hp) if hp.exists() else {}
    require(isinstance(holistic,dict),'Holistic review file must be an object')
    documents[hp]=holistic
    checked,digest=gate([g['baseline'] for g in groups],[g['catalog'] for g in groups],holistic,release=release,locales=locales)
    if not release:require(checked['ok'],'Full-source gate failed: '+ '; '.join(checked['errors'][:5]))
    overview=dict(schema_version=1,artifact_sha256=ISO_SHA,coverage=coverage('all three scripts'),
        entry_count=len(all_entries),record_kinds=dict(Counter(e['record_kind'] for e in all_entries)),
        programs=program_summaries,shard_count=len(groups),full_source_digest=digest,
        translation_counts=checked['counts'],full_project_locale_digests=checked.get('locale_digests',{}),release_allowed=False,
        release_blockers=['Coverage is partial for the full game.','All line reviews and subsequent full-project holistic review are mandatory before release.'],
        shards=[dict(program=g['program'],selector=g['selector'],entry_count=g['baseline']['entry_count'],
            baseline=str(g['baseline_path'].relative_to(output)).replace('\\','/'),
            catalog=str(g['catalog_path'].relative_to(output)).replace('\\','/'),
            source_digest=g['baseline']['source_digest']) for g in groups])
    path=output/'overview.json'
    observed[path]=sha(path.read_bytes()) if path.exists() else None
    documents[path]=overview
    changed=[] if check_only or release else write_batch(documents,observed)
    return dict(ok=checked['ok'],mode='release-check' if release else 'check' if check_only else 'build',
        entry_count=len(all_entries),shard_count=len(groups),record_kinds=overview['record_kinds'],checked_locales=list(locales),
        translation_counts=checked['counts'],
        full_source_digest=digest,changed_files=len(changed),error_count=len(checked['errors']),errors=checked['errors'][:12],coverage='partial')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=OUTPUT)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--release-check',action='store_true')
    parser.add_argument('--locale',choices=loc.LOCALES,action='append',
                        help='Check release readiness for this locale. Source validation still covers all three programs.')
    args=parser.parse_args()
    if args.locale and not args.release_check:parser.error('--locale requires --release-check')
    try:result=build(args.output,check_only=args.check or args.release_check,release=args.release_check,
                     locales=tuple(dict.fromkeys(args.locale or loc.LOCALES)))
    except (ValueError,KeyError,OSError,TypeError) as error:
        print(json.dumps(dict(ok=False,error=str(error)),ensure_ascii=False));return 2
    print(json.dumps(result,ensure_ascii=False));return 0 if result['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
