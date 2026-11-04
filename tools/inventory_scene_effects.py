"""Structural cue inventory from original 1397D8 operand readers.

This reads operands without executing waits, branches, audio or effects.
Per-command widths matter: 29 is u16 in 21/22, 27 is u32 in 19,
and 2A is a cstring in 23 but a length-prefixed blob in 08/09/0A.
"""
from pathlib import Path
import collections,hashlib,json,re,struct
from scenario_resources import ROOT,ResourceIndex
from vm_handlers import Image

ATTRS={
    1:(),4:(0x27,0x28),5:(),6:(0x27,0x28),7:(0x27,0x28),
    8:(0x28,0x2a),9:(0x28,0x2a),10:(0x28,0x2a),11:(0x28,0x29),
    12:(0x28,0x29,0x2b,0x2c,0x2d,0x2e,0x2f),13:(0x28,0x29,0x2b,0x2e),14:(),
    15:(0x28,0x29,0x2b,0x2e,0x2f),16:(0x28,0x29,0x2b,0x2c,0x2e),
    17:(0x28,0x29,0x2b,0x2d,0x2e),18:(0x28,0x2b,0x2e),19:(0x28,0x2b,0x2e),
    20:(0x27,0x28,0x2b,0x2e,0x2f),21:(0x28,0x2b,0x2e),22:(),23:(0x28,0x2b,0x2e,0x2f),
    25:(0x27,0x28,0x29),26:(0x29,),27:(0x29,),28:(0x27,0x28,0x31,0x33),
    29:(0x28,),30:(0x28,),31:(0x28,0x2b),32:(0x28,0x30,0x31),
    33:(0x28,0x29,0x34),34:(0x28,0x29),35:(0x28,0x2a),36:(0x27,),
}

def parse(data):
    at=0;commands=[]
    def word(offset):
        if offset+2>len(data):raise ValueError('Truncated command/tag')
        return int.from_bytes(data[offset:offset+2],'little')
    while at<len(data):
        start=at;opcode=word(at);at+=2
        if opcode not in ATTRS:raise ValueError(f'Unbound command {opcode:#x} at {start:#x}')
        if opcode==1:
            commands.append((start,opcode,{}))
            return commands,at
        values={}
        while at<len(data) and word(at)>0x24:
            tag=word(at);at+=2
            if tag not in ATTRS[opcode]:raise ValueError(f'Unbound attribute {opcode:#x}/{tag:#x}')
            begin=at
            if tag==0x27 and opcode!=0x19 or tag==0x33 or tag==0x2a and opcode==0x23:
                end=data.find(b'\0',at)
                if end<0:raise ValueError('Unterminated original string')
                at=end+1
            elif tag==0x2a:
                if at>=len(data):raise ValueError('Missing blob length')
                at+=1+data[at];begin+=1
            else:
                at+=12 if tag==0x31 else 4 if tag==0x29 and opcode not in (0x21,0x22) or tag==0x27 else 2
            if at>len(data):raise ValueError('Operand exceeds original cue region')
            values[tag]=data[begin:at]
        commands.append((start,opcode,values))
    raise ValueError('Missing original END')

def main():
    image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    inventory=[];unresolved=[];scope=[];tails=[];counts=collections.Counter()
    for program in ('sn2','sn4','sn4g'):
        path=ROOT/'local/assets/SCENARIO'/(program+'.spk');raw=path.read_bytes();seen=set();complete=0
        for block in ResourceIndex(raw).blocks:
            for scene in block['scenes']:
                for cue in scene['cues']:
                    key=(block['index'],cue['program_offset'])
                    if key in seen:continue
                    seen.add(key)
                    data=bytes.fromhex(cue['raw_hex'])
                    try:commands,consumed=parse(data)
                    except ValueError as error:
                        unresolved.append(dict(program=program,cue=cue['name'],error=str(error)));continue
                    complete+=1
                    if consumed<len(data):
                        tail=data[consumed:]
                        tails.append(dict(program=program,cue=cue['name'],bytes=len(tail),
                                          sha256=hashlib.sha256(tail).hexdigest(),all_zero=not any(tail),
                                          first_32_bytes=tail[:32].hex()))
                    for offset,opcode,values in commands:
                        counts[opcode]+=1
                        if opcode not in (8,9,10):continue
                        blob=values.get(0x2a,b'')
                        if len(blob)<4:raise ValueError('Missing original effect ID')
                        effect=int.from_bytes(blob[:4],'big')
                        if effect>=0x300:raise ValueError('Effect ID exceeds source table')
                        args=[]
                        if opcode!=9:
                            if len(blob)<5 or len(blob)!=5+4*blob[4]:raise ValueError('Malformed source effect arguments')
                            args=list(struct.unpack_from('>'+str(blob[4])+'i',blob,5))
                        elif len(blob)!=4:raise ValueError('Malformed effect-off arguments')
                        inventory.append(dict(program=program,cue=cue['name'],opcode=opcode,effect=effect,
                            factory=f'0x{image.word(0x205640+effect*8):x}',args=args,
                            offset=block['absolute_offset']+cue['program_offset']+offset))
        scope.append(dict(program=program,source_sha256=hashlib.sha256(raw).hexdigest(),regions=len(seen),parsed=complete))
    groups=[]
    for effect in sorted({r['effect'] for r in inventory if r['opcode']==8}):
        rows=[r for r in inventory if r['effect']==effect and r['opcode']==8]
        groups.append(dict(effect=effect,factory=rows[0]['factory'],occurrences=len(rows),
                           programs=sorted({r['program'] for r in rows}),arguments=sorted({tuple(r['args']) for r in rows})))
    evidence=ROOT/'analysis/ghidra/scene-cue-module-v4/functions/001397d8.json'
    out=dict(source_elf=image.sha256,operand_reference=str(evidence.relative_to(ROOT)),
        operand_reference_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),scope=scope,
        command_counts=dict(sorted(counts.items())),effects=groups,instances=inventory,unresolved=unresolved,
        bytes_after_first_end=tails,
        limitation='Each distinct cue entrypoint is read through its first original END. Trailing bytes are separately preserved in this report. Structural operands only, without proving reachability, wait completion, scheduling or rendered equivalence.')
    target=ROOT/'analysis/native-core/scene-effect-inventory.json';target.write_text(json.dumps(out,indent=2)+'\n')
    print(scope,'unresolved',len(unresolved),'effect factories',len(groups))
    print([(r['effect'],r['factory'],r['occurrences']) for r in groups])
if __name__=='__main__':main()
