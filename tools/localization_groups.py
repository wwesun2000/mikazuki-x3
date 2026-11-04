"""Bind contextual translation drafts to exact source records without VM edits.

A group cannot cross a known input wait or control transfer. Timed pauses are
retained and must execute before the complete group can be revealed. Unknown
intervening handlers remain explicit dependencies. Source record targets are never filled
with repeated copies of a whole-sentence translation.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

import localization as loc
import build_full_localization as full
from vm_handlers import ROOT

BASE=ROOT/'localization/full-source'
PACKS=ROOT/'localization/packs'
SPEC=BASE/'groups/sn4g-prologue-first-batch.spec.json'
OUTPUT=BASE/'groups/sn4g-prologue-first-batch.json'
WAIT_OR_FLOW={0x09,0x0B,0x0C,0x15,0x16,0x17,0x1A,0x1E,0x22,0x68,0x69,0x6A,0x6B,0x6C,0x70,0x71,0x7F,0x85}
KNOWN_LAYOUT={0x02,0x04,0x06,0x40,0x43,0x45,0x46,0x4C,0x4D,0x50,0x54,0x56,0x57,0x65,0x66}


def require(value,message):full.require(value,message)


def binding_digest(members):
    return loc.json_hash([{key:m[key] for key in ('entry_id','source_hash','raw_sha256','offset','length','record_kind')} for m in members])


def bind_group(spec,index,block,program_name,selector):
    offsets=spec['primary_offsets']+spec['ruby_offsets']
    require(offsets and len(set(offsets))==len(offsets),'Empty/duplicate group source offsets')
    members=[]
    for offset in sorted(offsets):
        entry_id=f'{program_name}:{selector:02x}:{offset:08x}'
        require(entry_id in index,f'Missing exact source ID {entry_id}')
        e=index[entry_id];location=e['location']
        require(spec['label'] in e['public_label_context']['labels'],'Group crosses static public-label context')
        expected='primary_text' if offset in spec['primary_offsets'] else 'ruby'
        require(e['record_kind']==expected,'Primary/ruby identity mismatch')
        members.append(dict(entry_id=entry_id,source_hash=e['source_hash'],raw_sha256=location['raw_sha256'],
            offset=offset,length=location['length'],record_kind=e['record_kind'],original=e['original']))
    primary=[m for m in members if m['record_kind']=='primary_text']
    require([m['offset'] for m in primary]==spec['primary_offsets'],'Primary record order must follow original source offsets')
    original=''.join(m['original'] for m in primary)
    require(original==spec['source_text'],'Joined source text differs from authored draft context')
    start=min(index[m['entry_id']]['location']['container_offset'] for m in members)
    end=max(m['offset']+m['length'] for m in members)
    within={e['entry_id'] for e in index.values() if e['program']==program_name and e['selector']==selector and
        start<=e['location']['offset']<end}
    require(within=={m['entry_id'] for m in members},'Group omits source text/ruby within its span')
    instructions=[r for r in block['instructions'] if start<=r['offset']<end]
    require(instructions and instructions[0]['offset']==start and instructions[-1]['next']==end,'Group span is not exactly bounded by owner instructions')
    require(not any(r['op'] in WAIT_OR_FLOW for r in instructions),'Group crosses input-wait/control-flow boundary')
    controls=[dict(offset=r['offset'],opcode=r['op'],raw_hex=r['raw_hex'],raw_sha256=full.sha(bytes.fromhex(r['raw_hex'])))
        for r in instructions if r['op'] not in (2,6)]
    pending=[c for c in controls if c['opcode'] not in KNOWN_LAYOUT]
    targets={language:dict(text=spec[language],status='draft',authored_by='Codex contextual first draft',
        source_binding_hash=binding_digest(members)) for language in loc.LOCALES}
    require(all(isinstance(t['text'],str) and t['text'].strip() for t in targets.values()),'Empty group draft')
    return dict(group_id=spec['id'],program=program_name,selector=selector,public_label=spec['label'],
        source_text=original,source_hash=loc.text_hash(original),source_binding_hash=binding_digest(members),
        ordered_source_ids=[m['entry_id'] for m in members],ordered_primary_ids=[m['entry_id'] for m in primary],
        members=members,source_span=dict(offset=start,length=end-start),original_controls=controls,
        pending_vm_dependencies=pending,retained_timed_pauses=[c for c in controls if c['opcode']==0x50],render_contract=dict(
            completion='emit target only after every source member has actually completed; primary completion order must match ordered_primary_ids',
            controls='Original VM executes every source opcode/resource/audio event. Grouping never changes PC, input waits, cues or images.',
            reveal='No per-character alignment is claimed. Do not reveal the full group at its first source record.',
            timed_pauses='Original50 countdowns remain in place. Group overlay is emitted only afterwards, not at the earlier fragment.',
            ruby='Original ruby records remain bound and available; translated ruby placement is not implemented.',
            integration='Draft group resolver available; production main/session renderer not modified'),
        voice=spec.get('voice',''),notes=spec.get('notes',[]),draft_origin=spec.get('draft_origin','Direct contextual translation in this task'),
        quote_continues_from=spec.get('quote_continues_from'),quote_continues_to=spec.get('quote_continues_to'),targets=targets)


def render_group(group,completed_source_ids,locale,resolved_vm_opcodes=()):
    """Bounded non-speculative overlay resolver; never advances the original VM."""
    require(locale in loc.LOCALES,'Unsupported target locale')
    completed=list(completed_source_ids)
    require(len(completed)==len(set(completed)),'Duplicate completion event')
    require(set(completed)<=set(group['ordered_source_ids']),'Completion event from a different group')
    observed=[i for i in completed if i in group['ordered_primary_ids']]
    require(observed==group['ordered_primary_ids'][:len(observed)],'Primary completion order differs from bound source')
    if set(completed)!=set(group['ordered_source_ids']):return dict(ready=False,reason='source_members_pending')
    pending={d['opcode'] for d in group['pending_vm_dependencies']}-set(resolved_vm_opcodes)
    if pending:return dict(ready=False,reason='pending_vm_dependency',opcodes=sorted(pending))
    return dict(ready=True,group_id=group['group_id'],text=group['targets'][locale]['text'],status='draft',
        source_binding_hash=group['source_binding_hash'],release_allowed=False)


def bind_catalog(catalog,groups,relative_path):
    out=deepcopy(catalog);index={e['entry_id']:e for e in out['entries']}
    for group in groups:
        singles=len(group['ordered_primary_ids'])==1
        for member in group['members']:
            e=index[member['entry_id']]
            link=dict(group_id=group['group_id'],path=relative_path,source_binding_hash=group['source_binding_hash'],
                role=member['record_kind'],status='direct_single_record_draft' if singles and member['record_kind']=='primary_text' else 'pending_grouping')
            require('grouping' not in e or e['grouping']==link,'Existing grouping differs; refusing replacement')
            e['grouping']=link
            for language in loc.LOCALES:
                target=e['targets'][language]
                if singles and member['record_kind']=='primary_text':
                    proposed=dict(text=group['targets'][language]['text'],status='draft',
                        authored_by='Codex contextual first draft',group_id=group['group_id'])
                    if target==dict(text='',status='untranslated'):e['targets'][language]=proposed
                    else:require(target.get('text')==proposed['text'],'Existing translator target conflicts; refusing overwrite')
                else:
                    require(target.get('text')=='' and target.get('status')=='untranslated',
                        'Grouped fragment already has a target; manual reconciliation required, no overwrite')
    return out


def member_units(member,raw):
    require(len(raw)>=2 and raw[0]==2 and raw[-1]==3,'Invalid source text record framing')
    units=[];pos=1
    while pos<len(raw)-1:
        if raw[pos]==0x21:pos+=1;continue
        require(pos+2<=len(raw)-1,'Truncated source group unit')
        units.append(dict(offset=member['offset']+pos,unit=int.from_bytes(raw[pos:pos+2],'big'),
            channel=0 if member['record_kind']=='primary_text' else 1,entry_id=member['entry_id']))
        pos+=2
    return units


def group_envelope(artifact,*,compact=False):
    """Include the original byte offsets and glyph units for each translation group."""
    index={}
    for program,selector in {(g['program'],g['selector']) for g in artifact['groups']}:
        require(program in full.NAMES,'Invalid grouping program')
        baseline=loc.load_json(BASE/program/f'block-{selector:02d}.baseline.json')
        index.update({e['entry_id']:e for e in baseline['entries']})
    payload=deepcopy(artifact)
    payload['recovered_vm_dependencies']={'85':dict(opcode=0x55,entry='0x001284f8',helper='0x0016a680',
        leaf='0x00168380',effect='primary.line_spacing=signedBE32; no branch/wait; original VM must still execute it')}
    for group in payload['groups']:
        units=[]
        for member in group['members']:
            entry=index[member['entry_id']];raw=bytes.fromhex(entry['location']['raw_hex'])
            member['raw_hex']=raw.hex()
            units.extend(member_units(member,raw))
        group['source_units']=units
        group['has_unobservable_space']=any(u['unit']==0x8140 for u in units)
    raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')) if compact else full._encoded(payload).decode('utf-8')
    return dict(format='kamaitachi-localization-groups',payload=raw,sha256=loc.text_hash(raw))


def export_pack(artifact,path,*,compact=False,previous=None):
    envelope=group_envelope(artifact,compact=compact)
    path=Path(path)
    if path.exists():
        existing=loc.load_json(path)
        if existing!=envelope:
            require(previous is not None and existing==group_envelope(previous,compact=compact), 'Existing localization pack differs; refusing overwrite')
            prior_ids={group['group_id'] for group in previous['groups']}
            preserved=[group for group in artifact['groups'] if group['group_id'] in prior_ids]
            require(preserved==previous['groups'], 'Existing groups changed or were reordered during pack expansion')
    full.write_batch({path:envelope},{path:full.sha(path.read_bytes()) if path.exists() else None})
    return envelope['sha256']


def build(spec_path=SPEC,output=OUTPUT,apply=False):
    spec_path=Path(spec_path);output=Path(output).resolve();spec=loc.load_json(spec_path)
    selector=spec.get('selector')
    name=spec.get('program')
    require(spec.get('schema_version')==1 and name in full.NAMES and type(selector) is int and 0<=selector<32,'Unsupported grouping source scope')
    bp=BASE/name/f'block-{selector:02d}.baseline.json';cp=BASE/name/f'block-{selector:02d}.catalog.json'
    baseline=loc.load_json(bp);catalog=loc.load_json(cp)
    checked=loc.validate(catalog,baseline);require(checked['ok'],'Original source catalog does not validate')
    index={e['entry_id']:e for e in baseline['entries']}
    program,program_id,source=full.read_program(full.PROGRAM_DIR/f'{name}.program.json',ROOT/f'local/assets/SCENARIO/{name}.sn4')
    block=next(b for b in program['blocks'] if b['selector']==selector)
    require(full.extract_block(program,program_id,source,block)==baseline['entries'],'Group baseline differs from rebuilt original source')
    groups=[bind_group(s,index,block,name,selector) for s in spec['groups']]
    for authored,group in zip(spec['groups'],groups):
        if 'choice_preview' in authored:
            group['choice_preview']=bind_choice_preview(program,block,authored['choice_preview'],group)
    require(len({g['group_id'] for g in groups})==len(groups),'Duplicate group identity')
    member_ids=[i for g in groups for i in g['ordered_source_ids']]
    require(len(set(member_ids))==len(member_ids),'A source record belongs to more than one draft group')
    ids={g['group_id'] for g in groups}
    for group in groups:
        for key in ('quote_continues_from','quote_continues_to'):
            require(group[key] is None or group[key] in ids,'Missing dialogue continuation group')
    artifact=dict(schema_version=1,kind='source-bound-localization-groups',artifact_sha256=full.ISO_SHA,
        script_sha256=program['source']['sha256'],program_sha256=program_id,spec_sha256=full.sha(spec_path.read_bytes()),
        baseline_digest=baseline['source_digest'],scope=spec['scope'],status='draft',reviewed=False,release_allowed=False,
        group_count=len(groups),source_record_count=len(member_ids),primary_record_count=sum(len(g['ordered_primary_ids']) for g in groups),
        groups=groups,limitations=spec.get('limitations',['Only six public labels; no coverage claim for the rest of the prologue/game.',
            'Input waits/control flow are never merged. Original50 timed pauses are retained and run before a group can finish.',
            'Opcode55 in one group is pending semantics; target glyph layout/ruby mapping and timing need native integration.',
            'Whole-project Chinese first translation and later complete proofreading gates remain unsatisfied.']))
    relative=str(output.relative_to(BASE)).replace('\\','/')
    updated=bind_catalog(catalog,groups,relative)
    checked=loc.validate(updated,baseline);require(checked['ok'],'Grouped catalog violates line gate')
    if output.exists():require(loc.load_json(output)==artifact,'Existing bound group drafts changed; refusing overwrite')
    if apply:
        full.write_batch({output:artifact,cp:updated},{output:full.sha(output.read_bytes()) if output.exists() else None,cp:full.sha(cp.read_bytes())})
    return artifact,updated


def bind_choice_preview(program,block,reference,group):
    """Bind an ordinary three-option display to its 6C operand and exact preview prefix."""
    owner=next((b for b in program['blocks'] if b['selector']==reference['source_selector']),None)
    require(owner is not None,'Missing choice source selector')
    row=next((r for r in owner['instructions'] if r['offset']==reference['source_offset']),None)
    require(row is not None and row['op']==0x6C,'Choice reference does not point to source 6C')
    operands=row['operands'];options=operands['options'];i=reference['option_index']
    require(operands['mode']==1 and isinstance(i,int) and 0<=i<len(options),'Unsupported choice mode/index')
    option=options[i]
    require(option['index']==i and option['block_selector']==block['selector'] and option['label']==group['public_label'], 'Choice source points to a different target')
    target=block['labels'][option['label']]
    start=next(i for i,r in enumerate(block['instructions']) if r['offset']==target)
    prefix=block['instructions'][start:start+5]
    require([r['op'] for r in prefix]==[0x22,0x6A,2,4,0x16],'Unsupported original preview prefix')
    require([prefix[2]['text']['id']]==group['ordered_primary_ids'],'Selected group is not the source preview occurrence')
    return dict(source_selector=owner['selector'],source_offset=row['offset'],source_raw_hex=row['raw_hex'],source_raw_sha256=full.sha(bytes.fromhex(row['raw_hex'])),
                mode=operands['mode'],option_count=len(options),option_index=i,raw_flag=option['raw_flag'],target_selector=block['selector'],target_label=option['label'],
                target_offset=target,preview_entry_id=prefix[2]['text']['id'],preview_end=prefix[-1]['offset'])


def prologue_supplement():
    """Recheck each authored batch against the retail script before combining."""
    original,_=build()
    seen_groups={g['group_id'] for g in original['groups']}
    seen_members={member for g in original['groups'] for member in g['ordered_source_ids']}
    keys=('schema_version','kind','artifact_sha256','script_sha256','program_sha256','baseline_digest','status','reviewed','release_allowed')
    combined={key:original[key] for key in keys}
    blocks=[];groups=[]
    for part in ('cafe','apartment','inn','invitation'):
        stem=f'sn4g-prologue-{part}';spec=BASE/'groups'/f'{stem}.spec.json';bound=BASE/'groups'/f'{stem}.json'
        artifact,_=build(spec,bound)
        require(all(artifact[key]==combined[key] for key in keys),'Source or review status differs between batches')
        blocks.append(dict(spec=spec.name,spec_sha256=artifact['spec_sha256'],bound=bound.name,bound_sha256=full.sha(bound.read_bytes())))
        for group in artifact['groups']:
            members=set(group['ordered_source_ids'])
            require(group['group_id'] not in seen_groups and not members&seen_members,'Overlapping source membership across batches')
            seen_groups.add(group['group_id']);seen_members.update(members);groups.append(group)
    groups.sort(key=lambda g:g['source_span']['offset'])
    return dict(**combined,scope='Additional sn4g selector 15 groups from the opening notice through pr01_1390',
        batch_sources=blocks,groups=groups,group_count=len(groups),
        source_record_count=sum(len(g['ordered_source_ids']) for g in groups),
        primary_record_count=sum(len(g['ordered_primary_ids']) for g in groups),
        limitations=['Draft overlay. Per-group original waits, ruby, branch identities and unresolved VM dependencies remain bound.'])


def export_route_packs():
    """Export the complete selector18 source coverage and adjacent selector19 branches."""
    def part(selector,section):
        stem=f'sn4g-selector-{selector}-{section}'
        return build(BASE/'groups'/f'{stem}.spec.json',BASE/'groups'/f'{stem}.json')[0]
    arrival=part(18,'arrival');first=part(18,'dinner');second=part(18,'memorial');cellar=part(18,'cellar');branches=part(19,'dinner')
    keys=('schema_version','kind','artifact_sha256','script_sha256','program_sha256','baseline_digest','status','reviewed','release_allowed')
    def join(parts,scope):
        require(all(p[k]==first[k] for p in parts for k in keys),'Continuation source or review state differs')
        groups=[group for p in parts for group in p['groups']];ids=[m for group in groups for m in group['ordered_source_ids']]
        require(len(set(ids))==len(ids) and len({g['group_id'] for g in groups})==len(groups),'Overlapping route batches')
        return dict(**{k:first[k] for k in keys},scope=scope,batch_spec_sha256=[p['spec_sha256'] for p in parts],
                    groups=groups,group_count=len(groups),source_record_count=len(ids),
                    primary_record_count=sum(len(g['ordered_primary_ids']) for g in groups),limitations=first['limitations'])
    previous=join((first,second),'rx01_0390 through rx01_1200')
    combined=join((arrival,first,second,cellar),'All framed primary and ruby source records in sn4g selector 18')
    baseline=loc.load_json(BASE/'sn4g/block-18.baseline.json')
    require({e['entry_id'] for e in baseline['entries']}=={m for group in combined['groups'] for m in group['ordered_source_ids']},'Incomplete selector18 group coverage')
    result={}
    for selector,artifact,old in ((18,combined,previous),(19,branches,None)):
        path=PACKS/f'sn4g-selector-{selector}-groups.json'
        digest=export_pack(artifact,path,compact=True,previous=old)
        result[str(selector)]=dict(path=str(path),group_count=artifact['group_count'],source_record_count=artifact['source_record_count'],sha256=digest)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    parser.add_argument('--spec',type=Path,default=SPEC);parser.add_argument('--output',type=Path,default=OUTPUT)
    parser.add_argument('--export-pack',action='store_true')
    parser.add_argument('--export-prologue-supplement',action='store_true',help='Validate four continuation batches and export their combined localization pack')
    parser.add_argument('--export-route-packs',action='store_true',help='Validate and build the selector18/19 main-route and option-branch packages')
    parser.add_argument('--pack-name',help='Unique basename for an additional source-bound draft pack')
    args=parser.parse_args()
    try:
        if args.export_route_packs:
            require(not (args.apply or args.export_pack or args.export_prologue_supplement) and args.spec==SPEC and args.output==OUTPUT,'Route pack export is a standalone operation')
            print(json.dumps(dict(ok=True,packs=export_route_packs(),release_allowed=False)));return 0
        if args.export_prologue_supplement:
            require(not args.apply and not args.export_pack and args.spec==SPEC and args.output==OUTPUT,'Supplement export is a standalone operation')
            artifact=prologue_supplement(); path=PACKS/'prologue-groups.json'
            digest=export_pack(artifact,path,compact=True)
            print(json.dumps(dict(ok=True,path=str(path),sha256=digest,group_count=artifact['group_count'],source_record_count=artifact['source_record_count'],release_allowed=False)));return 0
        artifact,catalog=build(args.spec,args.output,args.apply)
        if args.export_pack:
            selector=artifact['groups'][0]['selector']
            name='opening-groups.json' if selector==15 else f'sn4g-selector-{selector:02d}-groups.json'
            program=artifact['groups'][0]['program']
            if args.pack_name:
                name=args.pack_name
                require(name==Path(name).name and name.endswith('-groups.json'),'Expected a single draft pack basename')
            destination=PACKS if program=='sn4g' else PACKS/program
            if program!='sn4g' and not args.pack_name:name=f'{program}-selector-{selector:02d}-groups.json'
            export_pack(artifact,destination/name,compact=selector!=15)
    except (ValueError,KeyError,OSError,TypeError) as error:
        print(json.dumps(dict(ok=False,error=str(error)),ensure_ascii=False));return 1
    print(json.dumps(dict(ok=True,group_count=artifact['group_count'],source_record_count=artifact['source_record_count'],
        primary_record_count=artifact['primary_record_count'],ruby_record_count=artifact['source_record_count']-artifact['primary_record_count'],
        group_drafts_per_locale=artifact['group_count'],groups_with_vm_dependencies=sum(bool(g['pending_vm_dependencies']) for g in artifact['groups']),
        applied=args.apply,release_allowed=False),ensure_ascii=False));return 0


if __name__=='__main__':raise SystemExit(main())
