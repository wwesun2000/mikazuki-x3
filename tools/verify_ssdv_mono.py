"""Check unmodified MIPS-I note-on/modify code against the native mono gain for every input."""
import hashlib
import json
from pathlib import Path
import struct


ROOT=Path(__file__).resolve().parents[1]
SHA='8e6627a3aba481b1145ad497d042e0e543701494a73bf25d925eb9a03fe951bf'
MASK=0xffffffff


def main():
    irx=(ROOT/'local/extracted/IRX/SSDV.IRX').read_bytes()
    if hashlib.sha256(irx).hexdigest()!=SHA:raise ValueError('SSDV.IRX identity changed')
    at=lambda p:struct.unpack_from('<I',irx,0xa0+p)[0]
    signed=lambda n: n-(1<<32) if n&0x80000000 else n
    def run(start,end,source,level):
        regs=[0]*32;regs[source]=0x20000;regs[17]=0x26; high=0;calls=[]
        def one(pc):
            nonlocal high
            w=at(pc);op=w>>26;r=w>>21&31;t=w>>16&31;d=w>>11&31;sa=w>>6&31;f=w&63;k=w&65535
            if not w:return
            if op==15:regs[t]=k<<16
            elif op==13:regs[t]=regs[r]|k
            elif op==12:regs[t]=regs[r]&k
            elif op==36 and regs[r]+k==0x1870:regs[t]=0 # Original mono flag.
            elif op==37 and regs[r]+k==0x2000e:regs[t]=level
            elif op==0:
                if f==0:regs[d]=(regs[t]<<sa)&MASK
                elif f==3:regs[d]=(signed(regs[t])>>sa)&MASK
                elif f==24:high=((signed(regs[r])*signed(regs[t]))>>32)&MASK
                elif f==16:regs[d]=high
                elif f==35:regs[d]=(regs[r]-regs[t])&MASK
                elif f==33:regs[d]=(regs[r]+regs[t])&MASK
                else:raise ValueError(f'Unexpected SPECIAL {w:08x} at {pc:x}')
            else:raise ValueError(f'Unexpected op {w:08x} at {pc:x}')
        pc=start
        while pc!=end:
            w=at(pc);op=w>>26
            if op==4:
                taken=regs[w>>21&31]==regs[w>>16&31]
                imm=struct.unpack('<h',struct.pack('<H',w&65535))[0]
                one(pc+4);pc=pc+4+imm*4 if taken else pc+8
            elif op==3:
                if (w&0x3ffffff)*4!=0x14ec:raise ValueError('Unexpected external call')
                one(pc+4);calls.append((regs[4],regs[5]));pc+=8
            else:one(pc);pc+=4
        return calls
    # IOP ssdvIopDispatch uses (command - 0x0AA00001) to index the 10-way
    # table at 1690. Entry 7 stores command payload byte 4 into ssdvStereoFlag.
    if at(0x16ac)!=0x4f4 or at(0x4f4)!=0x90c20004 or at(0x4fc)!=0xa0221870:
        raise ValueError('IOP output mode command changed')
    for v in range(16384):
        expected=[(0x26,8*v//10),(0x126,8*v//10)]
        if run(0xe2c,0xf50,20,v)!=expected or run(0x10d4,0x11e4,19,v)!=expected:
            raise AssertionError(f'Unexpected original gains for volume {v}')
    source=ROOT/'local/assets/SYS_MENU/sys_g01.dat'
    output=dict(schema=1,irx_sha256=SHA,chart='SSDV.IRX relative virtual addresses (text file offset 0xA0)',
                verified_noteon_and_modify_inputs=16384,register_calls_per_input=4,callee='0x14EC sceSdSetParam',
                ee_path=['0x15DE60','0x1B0ED0 command 13','0x1B04BC calls 0x1B0F58','0x1B0F10','0x1D0648','0x1D0D18'],
                iop_dispatch='0x3C8 ssdvIopDispatch / 0x0AA00008 / 0x4F4 -> byte 0x1870',
                noteon='0xD04 ssdvSetNoteon / branch 0xE38, mono 0xF0C',
                modify='0x1078 ssdvSetNoteModify / branch 0x10E0, mono 0x11A0',
                native_formula='For each affected voice VOLL = VOLR = floor(8*command_volume/10).',
                settings_atlas=dict(source=str(source.relative_to(ROOT)),sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                                   pixel_format='512 pixel rows, low then high nibble, trailing 16 RGBA entries',
                                   output_labels=['ステレオ','モノラル']))
    (ROOT/'analysis/native-core/original-ssdv-output-mode.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(output['verified_noteon_and_modify_inputs'])


if __name__=='__main__':main()
