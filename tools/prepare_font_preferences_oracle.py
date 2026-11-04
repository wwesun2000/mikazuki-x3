"""Prepare original slot-7 calls to 12F1D0 with explicit branch inputs."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def main():
    src = ROOT / 'analysis/ghidra/oracle-page-control-v1/input-plan.json'
    plan = json.loads(src.read_text())
    ram = Path(plan['ram_input_path']).read_bytes()
    if hashlib.sha256(ram).hexdigest() != plan['ram_sha256']:
        raise ValueError('Original source RAM identity changed')

    def word(address):
        return struct.unpack_from('<I', ram, address)[0]

    def patch(address, value, size=4):
        return dict(address=hex(address), hex=(value % (1 << (size * 8))).to_bytes(size, 'little').hex(),
                    reason='Declared input to exercise original page preferences')

    manager = word(0x235e40)
    script = word(manager + 0x38)
    font = word(manager + 0x3c)
    primary = word(font)
    record = word(script + 0x138) + 8 * word(script + 0xd4)
    descriptor = word(0x236f30)
    prefs = manager + 0x308
    x, y = word(font + 0x10), word(font + 0x14)
    cases = []

    def case(name, patches):
        cases.append(dict(id=name, function_address='0x12f1d0', return_defined=False,
                          input=dict(registers=dict(a0='0', a1='0', a2='0', a3='0'), memory=patches)))

    case('actual-slot7', [])
    for read, flag in [(0, 0), (1, 0), (0, 1)]:
        case(f'read-{read}-manager740-{flag}', [
            patch(record, (word(record) & ~0x40000000) | (read << 30)),
            patch(manager + 0x740, flag), patch(manager + 0x2a4, 123)])
    for name, px, py in [('at-origin', x, y), ('clamp-xy', -3, -7), ('leave-xy', 500, 350),
                         ('clamp-only-y', 500, -4), ('clamp-only-x', -4, 350)]:
        case(name, [patch(primary + 4, px), patch(primary + 8, py), patch(font + 0x20, 99),
                    patch(prefs + 8, 17), patch(prefs + 4, 23), patch(prefs + 12, 31),
                    patch(prefs + 16, 41), patch(prefs + 24, -6), patch(prefs + 28, 7),
                    patch(prefs + 32, -12, 1)])
    case('font-size-ff-sentinel', [patch(descriptor + 16, 255), patch(primary + 12, 37)])
    case('font-size-changed', [patch(descriptor + 16, 29), patch(primary + 12, 37)])
    keep = {'manager', 'script', 'font', 'primary-format', 'ruby-format', 'channel-0', 'channel-1'}
    plan['observed_regions'] = [r for r in plan['observed_regions'] if r['name'] in keep]
    plan['observed_regions'].append(dict(name='read-state', address=hex(record), size=8))
    plan['cases'] = cases
    plan['case_kind'] = 'Page font preferences on original slot7 and explicitly patched source conditions'
    destination = ROOT / 'analysis/ghidra/oracle-font-preferences-plan.json'
    destination.write_text(json.dumps(plan, indent=2) + '\n')
    print(destination, len(cases))


if __name__ == '__main__':
    main()
