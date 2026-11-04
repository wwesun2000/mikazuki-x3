"""Prepare unmodified observed base images and declared input-only samples."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ELF_SHA='50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


def prepare(slot):
    archive=ROOT/'analysis/observations/OBS-001/pcsx2/sstates'/f'SLPM-66452 (0D03C0A3).{slot:02}.p2s'
    identity=json.loads((ROOT/f'analysis/observations/OBS-001/state-analysis/slot-{slot:02}-slices.json').read_text())
    digest=lambda b:hashlib.sha256(b).hexdigest()
    if digest(archive.read_bytes())!=identity['archive_sha256'] or identity['elf_sha256']!=ELF_SHA:
        raise ValueError('Original snapshot identity mismatch')
    with zipfile.ZipFile(archive) as z:ram=z.read('eeMemory.bin')
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if digest(elf)!=ELF_SHA or ram[0x100000:0x204b38]!=elf[0x1000:0x105b38]:raise ValueError('Original ELF differs')
    ram_path=ROOT/'local/ghidra-oracle-inputs'/f'text-input-slot{slot}-ee.bin'
    ram_path.parent.mkdir(parents=True,exist_ok=True)
    if ram_path.exists() and digest(ram_path.read_bytes())!=digest(ram):raise ValueError('Refuse changed input scratch file')
    if not ram_path.exists():ram_path.write_bytes(ram)
    u=lambda a:struct.unpack_from('<I',ram,a)[0]
    manager=u(0x235e40);script=u(manager+0x38);context=u(manager+0x40);choice=u(manager+8);font=u(manager+0x3c)
    inputs=[]
    def patch(address,value,n,reason):return dict(address=hex(address),hex=value.to_bytes(n,'little').hex(),reason=reason)
    def sample(name,entry,patches):
        args=dict(a0=context,a1=manager) if entry==0x11e748 else dict(a0=manager,a1=0)
        inputs.append(dict(id=name,function_address=hex(entry),return_defined=True,input=dict(registers={k:hex(v) for k,v in (args|dict(a2=0,a3=0)).items()},memory=patches)))
    def device(held,previous):
        return [patch(0x1e41c68,held,2,'15F040 held input'),patch(0x1e41d18,held,2,'15F168 current sample'),
                patch(0x1e41d1a,previous,2,'15F168 previous sample'),patch(0x1e41d14,1,4,'Fresh button state')]
    sample(f'slot{slot}-original-gate',0x112f78,[])
    if slot==4:
        for name,held,previous in [('idle',0,0),('circle-edge',0x2000,0),('circle-held',0x2000,0x2000),('up-held',0x10,0x10)]:
            sample('slot4-'+name,0x112f78,device(held,previous))
    else:
        sample('slot7-down-gate',0x112f78,device(0x40,0))
        for name,held,previous in [('idle',0,0),('down-edge',0x40,0),('down-held',0x40,0x40),('right-edge',0x20,0),('cross-edge',0x4000,0)]:
            sample('slot7-choice-'+name,0x11e748,device(held,previous))
    observed=[('manager',manager,0x860),('script',script,0x200),('choice',choice,0x1d4),('devices',0x1e41c60,0x260),('pointer-sprites',0x1e44200,4*188)]
    for channel in [0,1]:
        pool=u(u(font+8+4*channel));observed.extend([(f'glyphs-{channel}',u(pool+8),u(pool+4)*56),(f'iterator-{channel}',u(pool+12),16)])
    result=dict(schema=1,elf_sha256=ELF_SHA,archive_sha256=identity['archive_sha256'],archive=str(archive.relative_to(ROOT)),
                ram_sha256=digest(ram),ram_size=len(ram),ram_input_path=str(ram_path),case_kind='Explicit original device fields; no expected values computed',
                observed_regions=[dict(name=n,address=hex(a),size=s) for n,a,s in observed if s],cases=inputs)
    output=ROOT/f'analysis/ghidra/oracle-manager-input-slot{slot}-plan.json';output.write_text(json.dumps(result,indent=2)+'\n')
    return dict(output=str(output),cases=len(inputs),archive_sha256=identity['archive_sha256'],ram_sha256=digest(ram))

if __name__=='__main__':print(json.dumps([prepare(4),prepare(7)]))
