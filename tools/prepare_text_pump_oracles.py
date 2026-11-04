"""Declare bounded text and font inputs over the verified slot7 RAM fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "analysis/ghidra"
ELF_SHA = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"
ARCHIVE_SHA = "46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f"
OPERANDS = 0x01F80000
AUXILIARY = 0x01F80100


def raw(address, data, reason):
    assert 0x204b38 <= address <= 0x2000000 - len(data)
    return {"address": f"0x{address:08x}", "hex": data.hex(), "reason": reason}


def word(address, value, reason):
    return raw(address, struct.pack("<I", value & 0xffffffff), reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=["base", "active", "ready", "glyph", "ruby", "styles", "timer", "gate"])
    group = parser.parse_args().group
    source = json.loads((EVIDENCE / "oracle-choice-transfer-plan.json").read_text())
    ram = Path(source["ram_input_path"]).read_bytes()
    elf = (ROOT / "local/extracted/SLPM_664.52").read_bytes()
    assert len(ram) == 0x2000000 and hashlib.sha256(ram).hexdigest() == source["ram_sha256"]
    assert hashlib.sha256((ROOT / source["archive"]).read_bytes()).hexdigest() == ARCHIVE_SHA
    assert hashlib.sha256(elf).hexdigest() == ELF_SHA
    assert ram[0x100000:0x204b38] == elf[0x1000:0x105b38]

    def u32(address):
        return struct.unpack_from("<I", ram, address)[0]

    manager = u32(0x235e40)
    script = u32(manager + 0x38)
    special = u32(manager + 0x20)
    font = u32(manager + 0x3c)
    primary = u32(font)
    secondary = u32(font + 4)
    cases = []

    def add(name, entry, args, patches=(), defined=True):
        register_names = ["a0", "a1", "a2", "a3"]
        cases.append({"id": name, "function_address": f"0x{entry:08x}", "return_defined": defined,
                      "input": {"registers": {reg: f"0x{value & 0xffffffffffffffff:016x}"
                                              for reg, value in zip(register_names, args)},
                                "memory": list(patches)}})

    def stream(data):
        return [raw(OPERANDS, data, "Explicit bytes injected into a data-only guest scratch window"),
                word(script + 0xd8, OPERANDS, "Point main cursor at declared input")]

    def pump(data, ready=0, draw=0, ruby=0):
        return [*stream(data), word(manager + 0x2b4, 1, "Enable original text mode"),
                word(manager + 0x298, ready, "Select cadence readiness"),
                word(manager + 0x2bc, draw, "Select primary glyph emission"),
                word(manager + 0x2b8, ruby, "Select auxiliary ruby group"),
                word(special + 4, 0, "Select ordinary unchanged-codepoint branch")]

    if group == "base":
        for value in [0, 1, 0x7f, 0x80, 0xff, 0xffffffff, 0x1234567800000042]:
            add(f"setter-{value:x}", 0x111550, [manager, value],
                [word(manager + 0x294, 0x12345678, "Cadence accumulator write canary"),
                 word(manager + 0x298, 0x77777777, "Adjacent readiness canary")], False)
        for op, entry in [(0x40, 0x127240), (0x40, 0x127410), (0x40, 0x1272c0)]:
            handler = u32(manager + 0x5c + 4 * op)
            for value in [0, 1, 0x7f, 0x80, 0xff]:
                add(f"cadence-{entry:x}-{value:02x}", entry, [handler], stream(bytes([value, 0x03])))
        for value in [0, 0x12, 0xffffffff]:
            add(f"setting-constant-{value:x}", 0x175f78, [value])
        for entry in [0x122bf0, 0x122da0]:
            handler = u32(manager + 0x5c + 4 * 2)
            add(f"arm-{entry:x}", entry, [handler],
                [word(manager + 0x2b4, 0, "Initially inactive text state"),
                 word(manager + 0x2c0, 0, "Initially inactive text mark")])
        for value in [0, 1, 0x00460064, 0x80000000, 0xffffffff]:
            add(f"timer-{value:x}", 0x12acb0, [0], stream(value.to_bytes(4, "big")))
        for entry in [0x129998, 0x129c98]:
            for first, second in [(0, 0), (0x46, 0x64), (0x8000, 0xffff), (0xffff, 1)]:
                add(f"position-command-{entry:x}-{first:x}-{second:x}", entry, [0],
                    stream(struct.pack(">HH", first, second)))
        for entry in [0x16a8c8, 0x16a950]:
            for x, y in [(0, 0), (70, 100), (-24, -33), (0x7fffffff, 0xffffffff)]:
                add(f"position-helper-{entry:x}-{x}-{y}", entry, [font, x, y], defined=False)
        add("ruby-align", 0x169e68, [font], defined=False)
        for skip in [0, 1, 3, 8]:
            add(f"end-after-{skip}-skips", 0x1126e0, [manager], pump(b"!" * skip + b"\x03"))
        for skip in [0, 1, 3]:
            for unit in [0x8141, 0x82a0, 0xffff]:
                add(f"not-ready-{skip}-{unit:x}", 0x1126e0, [manager],
                    pump(b"!" * skip + unit.to_bytes(2, "big") + b"\x03\x0b"))
        for first, second in [(0, 0), (0, 1), (1, 0)]:
            for unit in [0x8140, 0x82a0, 0xffff]:
                add(f"transform-gates-{first}-{second}-{unit:x}", 0x119f80, [special, unit, 0],
                    [word(special + 4, first, "First transform gate"), word(special + 8, second, "Second transform gate")])
    elif group == "active":
        for probability in [0.0, 100.0, 50.0]:
            for lane in [0, 1]:
                patches = [word(special + 4, 1, "Enable first transform gate"),
                           word(special + 8, 1, "Enable second transform gate"),
                           raw(special + 0x28, struct.pack("<f", probability), "Explicit previous probability"),
                           word(special + 0x24, 5, "Replacement-count sentinel")]
                add(f"active-prob-{int(probability)}-lane-{lane}", 0x119f80,
                    [special, 0x82a0, lane], patches)
    elif group == "styles":
        for unit in (0x817e, 0x81a2, 0x81a0, 0x8146, 0x82a0):
            data = unit.to_bytes(2, "big") + bytes.fromhex("82a282a4030b")
            add(f"style9-{unit:x}", 0x1126e0, [manager],
                [*pump(data, ready=1, draw=1), word(primary + 0x10, 9, "Select original style9 at actual primary default size")])
        for control in ("1b", "4607"):
            data = bytes.fromhex("82a003" + control + "0b")
            add("lookahead-control-" + control, 0x1126e0, [manager], pump(data, ready=1, draw=1))
        # Room for exactly the current full-width space. The next closing
        # punctuation makes the source kinsoku branch advance to the next line.
        add("layout-kinsoku-close", 0x1126e0, [manager],
            [*pump(bytes.fromhex("8140814182a0030b"), ready=1, draw=1),
             word(manager + 0x2a4, 1, "Enable original three-slot layout check"),
             word(font + 0x18, u32(primary + 4) + u32(primary + 0xc), "Right boundary admits current space but not next closing punctuation")])
        add("ruby-distinct-sjis", 0x1126e0, [manager],
            [*pump(bytes.fromhex("82a082a282a4030b"), ready=1, draw=1, ruby=1),
             raw(AUXILIARY, bytes.fromhex("0282a20307"), "Actual ruby codepoint differs from primary 82A0"),
             word(script + 0xdc, AUXILIARY, "Declared auxiliary cursor")])
    elif group == "timer":
        timer = manager + 0x2e8
        for remaining in (0, 1, 2, 49, 50, 51, 0x7fffffff, 0x80000000, 0xffffffff):
            for enabled in (0, 1):
                patches = [word(timer, enabled, "Select input-cancel gate"),
                           word(timer + 4, remaining, "Declared original timer remaining")]
                add(f"timer-step-{enabled}-{remaining:08x}", 0x113818, [timer], patches, False)
            add(f"timer-busy-{remaining:08x}", 0x113888, [timer],
                [word(timer + 4, remaining, "Original nonzero busy predicate")])
    elif group == "gate":
        add("original-pre-input", 0x112f78, [manager])
        for interval, counter in ((0,0), (1,0), (4,1), (4,3), (4,4), (0xffffffff,0xfffffffe)):
            add(f"pre-input-cadence-{interval:x}-{counter:x}", 0x112f78, [manager],
                [word(manager + 0x29c, interval, "Cadence interval"), word(manager + 0x294, counter, "Cadence count"),
                 word(manager + 0x298, 0, "Initial not-ready flag")])
    else:
        flags = {"ready": (0, 0), "glyph": (1, 0), "ruby": (1, 1)}
        draw, ruby = flags[group]
        for unit in [0x8140, 0x82a0]:
            for lookahead in [0, 1]:
                data = unit.to_bytes(2, "big") + bytes.fromhex("82a282a4030b")
                patches = [*pump(data, ready=int(unit != 0x8140), draw=draw, ruby=ruby),
                           word(manager + 0x2a4, lookahead, "Select source layout lookahead"),
                           word(manager + 0x29c, 1, "Set nonzero cadence interval to observe post-layout ready clear")]
                if ruby:
                    patches.extend([raw(AUXILIARY, bytes.fromhex("0282a00307"), "One explicit auxiliary text group"),
                                    word(script + 0xdc, AUXILIARY, "Auxiliary cursor points at declared group")])
                add(f"{group}-{unit:x}-lookahead-{lookahead}", 0x1126e0, [manager], patches)

    regions = [("manager", manager, 0x870 if group in ("timer", "gate") else 0x820),
               ("script", script, 0x188), ("special", special, 0x40),
               ("font", font, 0x80), ("primary_formatter", primary, 0x60), ("ruby_formatter", secondary, 0x60),
               ("operand_window", OPERANDS, 0x120), ("rng_globals", 0x237280, 0x18),
               ("rng_state", 0x1e497e8, 624 * 4)]
    plan = {key: source[key] for key in ("schema", "elf_sha256", "archive_sha256", "archive",
                                          "ram_sha256", "ram_size", "ram_input_path")}
    plan.update(case_kind=f"Fixed slot7 RAM with declared text {group} inputs",
                observed_regions=[dict(name=n, address=f"0x{a:08x}", size=s) for n, a, s in regions],
                cases=cases)
    path = EVIDENCE / f"oracle-text-{group}-plan.json"
    data = json.dumps(plan, indent=2) + "\n"
    if path.exists() and path.read_text() != data:
        raise ValueError(f"Refusing to replace different existing text plan {path}")
    path.write_text(data)
    print(json.dumps(dict(plan=str(path.relative_to(ROOT)), cases=len(cases))))


if __name__ == "__main__":
    main()
