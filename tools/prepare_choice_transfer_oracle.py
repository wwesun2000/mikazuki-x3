"""Source-only test inputs; no expected transition/state formula is evaluated."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ELF_SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA='46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'


def main():
    scalar='--scalar-cstring-input' in sys.argv[1:]
    source=ROOT/'analysis/observations/OBS-001/pcsx2/sstates/SLPM-66452 (0D03C0A3).07.p2s'
    if hashlib.sha256(source.read_bytes()).hexdigest()!=STATE_SHA:raise ValueError('State identity mismatch')
    with zipfile.ZipFile(source) as z:ram=z.read('eeMemory.bin')
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if hashlib.sha256(elf).hexdigest()!=ELF_SHA:raise ValueError('ELF identity mismatch')
    if ram[0x100000:0x204b38]!=elf[0x1000:0x105b38]:raise ValueError('Original code differs')
    u=lambda a:struct.unpack_from('<I',ram,a)[0]
    manager=u(0x235e40);script=u(manager+0x38);choice=u(manager+8)
    original_previous_name=u(script+0x184)
    name_end=ram.index(0,original_previous_name,original_previous_name+64)
    previous_name=ram[original_previous_name:name_end+1]
    cases=[]
    def patch(a,v,why):return dict(address=f'0x{a:08x}',hex=struct.pack('<I',v).hex(),reason=why)
    for option in range(u(choice+4)):
        variants=[('original',[],0),('force-tracker',[patch(script+0x180,1,'Force original progress callback branch')],0),
                  ('history-flags',[patch(script+0x14c,1,'Record scope flag'),patch(manager+0x740,1,'Manager history flag'),patch(manager+0x744,1,'Recorder active word')],0),
                  ('flag1',[],1),('recording-off',[patch(script+0x168,0,'Recording disabled branch')],0),
                  ('no-prior-id',[patch(script+0xd4,0xffffffff,'No prior public label')],0),
                  ('template-prior-selector',[patch(script+0xd0,32,'Previous template selector gate')],0),
                  ('no-media-id',[patch(script+0xe0,0xffffffff,'No current media id')],0),
                  ('pending-edge',[patch(script+0x150,1,'Exercise actual saved154/158 edge restoration')],0),
                  ('first-recording',[patch(script+0x184,0,'No previous recorded name')],0),
                  ('suspend-retained-tracker',[patch(script+0x180,1,'Force tracker call'),patch(0x237f94,1,'Suspend retained category/name updates')],0)]
        for name,patches,flag in variants:
            adjusted=[]
            if scalar:
                adjusted=[dict(address='0x01f80001',hex=previous_name.hex(),reason='Same original previous-name bytes at unaligned address; forces real strcmp scalar path instead of unsupported SLEIGH MMI'),
                          patch(script+0x184,0x1f80001,'Point previous-name field to exact unaligned copy; declared input adaptation, not an observed state')]
            cases.append(dict(id=f'choice-{option}-{name}',function_address='0x0010d868',return_defined=False,
                input=dict(registers={k:f'0x{v:016x}' for k,v in dict(a0=script,a1=u(choice+0x44+4*option),a2=u(choice+0x1c+4*option),a3=flag).items()},
                           memory=[patch(manager+0x40,u(0x235f3c),'118D68 installs actual default singleton before10D868'),*adjusted,*patches])))
    temporary=ROOT/'local/ghidra-oracle-inputs/choice-slot7-ee.bin';temporary.parent.mkdir(parents=True,exist_ok=True)
    if temporary.exists() and temporary.read_bytes()!=ram:raise ValueError('Refuse changing different existing oracle input')
    temporary.write_bytes(ram)
    plan=dict(schema=1,elf_sha256=ELF_SHA,archive_sha256=STATE_SHA,archive=str(source.relative_to(ROOT)),
              ram_sha256=hashlib.sha256(ram).hexdigest(),ram_size=len(ram),ram_input_path=str(temporary),
              case_kind='Original slot7 input plus declared branch-coverage patches; no computed expected values',
              string_alignment_adaptation=scalar,
              observed_regions=[dict(name=n,address=f'0x{a:08x}',size=s) for n,a,s in
                  [('script',script,0x200),('manager',manager,0x820),('history',u(script+0x138),u(script+0x134)*8),
                   ('tracker_globals',0x237f80,0x30),('tracker_name',0x1e4abb0,32)]],cases=cases)
    output=ROOT/('analysis/ghidra/oracle-choice-transfer-scalar-plan.json' if scalar else 'analysis/ghidra/oracle-choice-transfer-plan.json')
    output.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(plan=str(output),cases=len(cases),temporary_ram=str(temporary))))


if __name__=='__main__':main()
