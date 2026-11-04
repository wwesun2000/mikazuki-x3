"""Bind all remaining cue effect factories from the complete disc inventory."""
import json
from vm_handlers import Image,ROOT
image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes());anchors=[]
for effect in (11,26,27,31):
    factory=image.word(0x205640+8*effect)
    anchors.append(dict(address=f'{factory:08x}',creation_candidate=True,factory_table_index=effect,
                        role=f'Original ScenePack effect {effect} constructor'))
    if effect==11:
        assert image.word(0x1819ec)==0x08000000|(0x181a20>>2)
        factory=0x181a20
        anchors.append(dict(address=f'{factory:08x}',creation_candidate=True,entry_jump_pc='001819ec',
                            role='Original shared ripple constructor reached by effect 11 tail jump'))
    found=0
    for pc in range(factory,factory+128,4):
        word=image.word(pc);callee=(word&0x3ffffff)*4
        if word>>26!=3 or callee not in (0x179c40,0x179c48,0x179c58):continue
        delay=image.word(pc+4)
        assert delay>>16==0x24a5
        high_pc=next(a for a in range(pc-4,factory-4,-4) if image.word(a)>>16==0x3c05)
        high=image.word(high_pc);target=((high&65535)<<16)+((delay&65535)^0x8000)-0x8000
        anchors.append(dict(address=f'{target:08x}',creation_candidate=True,
            role=f'Original effect {effect} callback',registration_pc=f'{pc:08x}',registration_callee=f'{callee:08x}',
            lui_pc=f'{high_pc:08x}',lui_word=f'{high:08x}'));found+=1
    assert found==3,(effect,found)
p=ROOT/'tools/ghidra/remaining-cue-effects.json'
p.write_text(json.dumps(dict(schema=1,elf_sha256=image.sha256,language_id='r5900:LE:32:default',anchors=anchors),indent=2)+'\n')
print(len(anchors),'original entries')
