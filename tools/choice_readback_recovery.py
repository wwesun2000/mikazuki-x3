"""Bounded source/actual-state evidence for native ordinary readback entry."""
import csv
import hashlib
import json
from pathlib import Path
import struct
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ELF_SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA='46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if sha(elf)!=ELF_SHA:raise ValueError('ELF identity mismatch')
    functions_file=ROOT/'analysis/ghidra/choice-readback-v1/functions.csv'
    with functions_file.open(newline='') as f:boundaries={r['entry']:r for r in csv.DictReader(f)}
    anchors=[0x134af0,0x134bd0,0x114b28,0x1195a8,0x1165b0,0x1165d8,0x10ead0,0x10eaa8,
             0x101190,0x1133f0,0x1163e8,0x186050,0x111550,0x16c978,0x16c790,0x16a9f0,
             0x1683a0,0x1683c8,0x19cca8,0x116a98,0x10dbd8,0x116908,0x116e78,0x1136f8,
             0x113778,0x117a90,0x17a0e0,0x17a1b0,0x19ce18]
    sources=[]
    for entry in anchors:
        row=boundaries[f'ram:{entry:08x}'];ranges=[]
        for r in json.loads(row['body_ranges_json']):
            address=int(r['min'].split(':')[1],16);off=r['canonical_elf_file_offset'];size=r['length']
            raw=elf[off:off+size]
            if len(raw)!=size or address-off!=0xff000:raise ValueError('Unsupported source address mapping')
            ranges.append(dict(address=f'0x{address:08x}',file_offset=off,size=size,hex=raw.hex(),sha256=sha(raw)))
        sources.append(dict(entry=f'0x{entry:08x}',boundary='existing Ghidra function; no boundary creation',ranges=ranges))
    archive=ROOT/'analysis/observations/OBS-001/pcsx2/sstates/SLPM-66452 (0D03C0A3).07.p2s'
    if sha(archive.read_bytes())!=STATE_SHA:raise ValueError('Actual-state archive identity mismatch')
    with zipfile.ZipFile(archive) as z:ram=z.read('eeMemory.bin')
    u=lambda a:struct.unpack_from('<I',ram,a)[0]
    manager=u(0x235e40);script=u(manager+0x38);helper=u(manager+4);history=u(script+0x138)
    current=u(script+0xd4);record=history+current*8;previous=u(record)&0x3fff
    observed=[]
    font=u(manager+0x3c)
    for name,address,size in [('helper',helper,0x40),('current_record',record,8),('previous_record',history+previous*8,8),
                              ('font_primary',u(font),0x40),('font_ruby',u(font+4),0x40),('task_table',u(0x2388bc),37*48),
                              ('pointer_records',0x1e44200,3*0xbc),('working_variables',0x238af0,1024)]:
        raw=ram[address:address+size];observed.append(dict(name=name,address=f'0x{address:08x}',size=size,hex=raw.hex(),sha256=sha(raw)))
    fixture=dict(schema=1,archive_sha256=STATE_SHA,elf_sha256=ELF_SHA,incomplete_memory=True,memory=observed)
    fixture_path=ROOT/'analysis/choice_readback_slot7.json';fixture_path.write_text(json.dumps(fixture,indent=2)+'\n')
    report=dict(schema=1,status='ordinary_backward_entry_and_eligibility_recovered; viewer_and_forward_scan_incomplete',
        elf_sha256=ELF_SHA,archive_sha256=STATE_SHA,boundary_manifest_sha256=sha(functions_file.read_bytes()),source_functions=sources,
        fixture=dict(path=str(fixture_path.relative_to(ROOT)),sha256=sha(fixture_path.read_bytes()),guest_bytes=sum(r['size'] for r in observed)),
        actual_slot7=dict(manager=f'0x{manager:08x}',helper=f'0x{helper:08x}',script=f'0x{script:08x}',
                          current_selector=u(script+0xd0),current_label_id=current,previous_label_id=previous,
                          previous_marker_bit31=bool(u(history+previous*8)&0x80000000),
                          callbacks={f'0x{a:08x}':f'0x{u(a):08x}' for a in [0x1e4ab68,0x1e4ab8c,0x1e4ab9c]},
                          original_history_depth=u(script+0x148),original_variable_depth=u(0x238684),
                          backward_context_pointer=f'0x{u(0x235f24):08x}',backward_context_vtable=f'0x{u(u(0x235f24)):08x}'),
        eligibility='134AF0 reads manager32C,object14.word0,helper04.word0,hint20.word4,manager740/744/808 and current history word1 bit24.134BD0 tail-delegates. No presentation guesses.',
        entry_core=['Save original context,selector,label,relative cursor,pending-text word','10EAD0 no-notify eligibility walk',
                    '10F070 full history snapshot and101190 full1024-byte variable push','1133F0 manager format snapshot',
                    '186050 original task callbacks;111550 manager29C/294 reset','Pointer active fields and font palette update',
                    '19CCA8 chapter/suspension/name state and actual optional callback','10DBD8 notified backward walk and10DAF0 exact target',
                    '11F530 singleton context;116908 distinct-target no-op path proven by original source',
                    '1136F8/113778 freeze owner task callbacks','17A0E0 freeze active non-type4 tasks and19CE18 optional source callback'],
        frontend_events=['pointer_hide(channel0/1/2)','font_palette(primaryRGB,secondaryRGB)','task_callbacks(task,update,draw)','task_pause(task,true)'],
        required_unresolved=['mode1/2 forward scanning','Readback context update/render/exit loop after entry',
                             '19C868 progress callback if backward walk traverses intermediate unmarked records',
                             'Nonzero19CCA8/19CE18 callback registration','Nested history/variable snapshots beyond ordinary entry scope',
                             'Actual frontend implementation and save/restore of presented readback state'],
        tests=dict(native_contract='analysis/native-core/choice-pipeline-slot7.json',
                   original_machine='analysis/ghidra/oracle-choice-readback-v1/manifest.json',
                   native_differential='analysis/native-core/choice-readback-diff.json',
                   scope='14 original-machine samples:5 entry branches,9 eligibility branches. Complete persistent windows and all persistent writes plus v0 compared. Enhanced MMI engine; not PCSX2 observation.'))
    out=ROOT/'analysis/choice_readback_recovery.json';out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(report=str(out),source_functions=len(sources),fixture_guest_bytes=report['fixture']['guest_bytes'])))


if __name__=='__main__':main()
