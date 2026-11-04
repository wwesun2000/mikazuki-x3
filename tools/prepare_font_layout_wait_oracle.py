"""Select original wait vtables and controlled script/layout inputs from slot 7."""
import hashlib
import argparse
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def main():
    options=argparse.ArgumentParser();options.add_argument('--palette',action='store_true')
    palette=options.parse_args().palette
    plan = json.loads((ROOT/'analysis/ghidra/oracle-glyph-defaults-v1/input-plan.json').read_bytes())
    ram = Path(plan['ram_input_path']).read_bytes()
    assert hashlib.sha256(ram).hexdigest() == plan['ram_sha256']
    def get(address):
        return struct.unpack_from('<I', ram, address)[0]
    def patch(address, data):
        return dict(address=hex(address), hex=data.hex(), reason='Declared wait or font-layout operand')
    def word(address, value):
        return patch(address, struct.pack('<I', value))
    owner = get(0x235e40)
    font, script = get(owner+0x3c), get(owner+0x38)
    cursor, primary = get(script+0xd8), get(font)
    pool = get(get(font+8))
    cases = []
    def case(name, entry, self=0, a1=0, memory=()):
        cases.append(dict(id=name, function_address=hex(entry), return_defined=True, input=dict(
            registers=dict(a0=hex(self), a1=hex(a1), f20='0x0', f21='0x0', f22='0x0', f23='0x0',
                           fcsr='0x0'), memory=list(memory))))
    for getter, ctx in [(0x11ff20, get(0x235f34)), (0x120130, get(0x235f38))]:
        for index in range(5):
            case(f'wait-{getter:x}-predicate-{index}', getter, ctx, get(owner+0x280+4*index))
        for mode in (0,1):
            case(f'wait-{getter:x}-predicate-0-held-{mode}', getter, ctx, get(owner+0x280),
                 [word(owner+0x740,0), word(owner+0x44,1), word(0x2388d8,mode)])
    for style, size in ((0,16),(1,24),(255,0),(255,255)):
        case(f'font-style-{style}-{size}',0x128af0,memory=[patch(cursor,bytes((style,size)))])
    for value in (0,14,0xffffffff):
        case(f'line-spacing-{value}',0x1284f8,memory=[patch(cursor,value.to_bytes(4,'big'))])
    for name, x, width in [('plain',100,64),('wrap',get(font+24)-4,16),
                           ('margin',get(font+16),get(font+24)-get(font+16)+32),('zero',100,0)]:
        case(f'rule-{name}',0x1326e0,memory=[word(primary+4,x),patch(cursor,struct.pack('>H',width))])
    plan['observed_regions'] += [dict(name=name,address=hex(address),size=size) for name,address,size in (
        ('format',primary,40),('ruby',get(font+4),40),('primary-pool',pool,16),
        ('new-node',get(pool+8)+56*get(pool+4),56))]
    plan['cases'] = cases
    target=ROOT/'analysis/ghidra/oracle-font-layout-wait-plan.json'
    if palette:
        cases.clear()
        for header in (b'\x20',b'\x00\xc7\x31'):
            for rgb in (b'\x00\x00\x00',b'\xff\x07\xd1',b'\x80\xff\x01'):
                for entry in (0x129398,0x129460):
                    case(f'palette-{entry:x}-{len(header)}-{rgb.hex()}',entry,
                        memory=[patch(cursor,header+rgb),patch(primary+28,bytes.fromhex('77777767888888a7')),
                                patch(get(font+4)+28,bytes.fromhex('11223317445566b7'))])
        target=ROOT/'analysis/ghidra/oracle-font-rgb-plan.json'
    target.write_text(json.dumps(plan,indent=2)+'\n')
    print(f'{len(cases)} original wait predicates and font layout conditions')


if __name__ == '__main__':
    main()
