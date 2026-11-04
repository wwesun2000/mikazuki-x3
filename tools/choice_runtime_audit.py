"""Bounded, hash-bound 6C entry/preview/confirmation evidence; never executes ELF."""
import hashlib
import json

from vm_handlers import Image, ROOT
from vm_presentation_semantics import extended_decode
from choice_branch import Script, CHOICE_OFFSET, PREVIEW_ALLOWLIST, decode_operands, target_prefix

REGIONS = [
    (0x10EDC0,0x10EDF0), (0x113448,0x113460), (0x117560,0x117568),
    (0x1186E8,0x1189F8), (0x11E508,0x11E608), (0x118338,0x118568),
    (0x118628,0x1186E8), (0x118088,0x118150), (0x118288,0x118308),
    (0x11E748,0x11E828), (0x11E608,0x11E660), (0x118D68,0x118E20),
    (0x17D380,0x17D3B8), (0x117E30,0x117EE8),
]


def build():
    script_data=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
    script=Script(script_data)
    image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    allow=[image.word(PREVIEW_ALLOWLIST+i*4) for i in range(19)]
    row=script.instruction(15,CHOICE_OFFSET)
    operands=decode_operands(row)
    regions=[]
    for start,end in REGIONS:
        region=image.region(start,end)
        for instruction in region['instructions']:
            instruction['extended_decode']=extended_decode(int(instruction['raw_word'],16),int(instruction['address'],16))
        regions.append(region)
    return dict(schema=1,evidence_id='CHOICE-RUNTIME-002',
        authority='bounded static ELF and script inspection',
        elf_sha256=image.sha256,script_sha256=hashlib.sha256(script_data).hexdigest(),
        source_instruction=row,operands=operands,
        preview_allowlist=allow,preview_allowlist_raw=[image.record(PREVIEW_ALLOWLIST+i*4,False) for i in range(19)],
        source_options=[target_prefix(script,o,allow) for o in operands['options']],
        corrections=[dict(address='0x10EDC0',confidence='high: direct instruction sequence',
            old_description='clear ScriptData pending states',
            actual='10E630(current D4); record.word0 |= 0x80000000. No writes to ScriptData014C or0150.',
            callsite='0x1187EC on manager-modefalse branch')],
        confirmed=[
            '117560 returns manager04 object+4.',
            '113448 delegates manager58 to17D380: copies task+14 float to+18, conditionally clamps+14, and changes update callback via179C40. Not a NOP.',
            '118338 stores primary and ruby glyph counts minus1 into per-option end arrays; normal completion restores saved D0,D4,cursor by direct setters118444/454/460.',
            'Preview6A is skipped by the original111738 path because6A is absent from the19-entry allowlist. No ordinary transfer/history write happens merely by scanning it.',
            '118010 calls118138/118088 read-state predicate before recoloring selected glyph ranges. This is not evidence that an option is unavailable.',
            '11E748 confirmation mask2100 calls118288 and switches to11EB28 transition context; it does not immediately branch.',
            '118288 performs118150,16CC38,113430,conditional117E30,19CAA8,119E70 before confirmation is ready.',
            '118D68 normal path restores font position, clears selected glyph range animation via117EE8, sets default context, and calls10D868(target,flag0). It follows restored ordinary selector, so normal history remains required.',
        ],
        outside_this_inspection=[
            'manager04+4 original cold initialization and all mutation sites',
            'manager58 task ownership and17D380/17D418 update state',
            'context-slot1 font/template preview implementation, including22/04/16 and generated32+i buffers',
            '118338 highlight/prompt/range lifecycle and font stack storage',
            'full navigation/readback and118288 confirmation-start transition, including observers19CAA8/19CAD8',
            '16BA10 animation readiness and post-choice manager28+14 snapshot state',
        ],
        evidence_regions=regions)


if __name__=='__main__':
    report=build()
    target=ROOT/'analysis/choice_runtime_audit.json'
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'report':str(target),'evidence_regions':len(report['evidence_regions']),
                      'options':len(report['source_options']),'full6c_executable':False}))
