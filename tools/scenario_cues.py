"""Verified-build, deliberately partial ScenePack cue parser and tick scheduler.

Unknown commands/attributes block. Plans preserve original callback arguments;
they are not a completed picture/audio backend or an executable game timeline.
"""
from dataclasses import dataclass, field
import argparse
import json
from pathlib import Path
import struct

from scenario_resources import ROOT, ResourceIndex, sha, require
from vm_handlers import Image
from vm_presentation_semantics import extended_decode

# Names are the original ELF's diagnostic strings, with their exact addresses.
COMMANDS = {
    0x01: ('END', None, None, set()),
    0x07: ('MOVIE_LOOP_PLAY', 0x22b1e0, 0x139550, {0x27, 0x28}),
    0x08: ('EFFECT_ON', 0x22b1f0, 0x10c528, {0x28,0x2a}),
    0x09: ('EFFECT_OFF', 0x22b200, 0x10c5b8, {0x28,0x2a}),
    0x0b: ('EFFECT_WAIT', None, 0x10c5f8, {0x28,0x29}),
    0x0c: ('SE_PLAY', 0x2360d8, 0x140478, {0x29, 0x2f, 0x2c, 0x2d, 0x2b, 0x2e, 0x28}),
    0x0d: ('SE_STOP', 0x2360e0, 0x140540, {0x29, 0x2b, 0x2e, 0x28}),
    0x10: ('SE_CHANGE_PAN', 0x22b1a0, 0x140680, {0x29, 0x2c, 0x2b, 0x2e, 0x28}),
    0x13: ('SOUND_STOP', 0x22b1d0, 0x140aa8, {0x2b, 0x2e, 0x28}),
    0x14: ('BGM_PLAY', 0x22b160, 0x1408c0, {0x27,0x2f,0x2b,0x2e,0x28}),
    0x15: ('BGM_STOP', 0x22b180, 0x140988, {0x2b, 0x2e, 0x28}),
}
ATTRIBUTES = {
    0x27: ('filename', 'cstring'), 0x28: ('delay_ticks', '<H'),
    0x29: ('sound_id', '<I'), 0x2b: ('transition_parameter', '<H'),
    0x2a: ('effect_blob', 'blob8'),
    0x2c: ('pan', '<h'), 0x2d: ('pitch', '<h'),
    0x2e: ('completion_parameter', '<H'), 0x2f: ('volume', '<H'),
}
PRIORITY = ('pr0000_00', 'pr0000_10', 'pr5011m_00', 'pr1034_00')
REGIONS = [
    (0x138c90, 0x138e30), (0x139118, 0x139150),
    (0x139150, 0x139338), (0x139338, 0x139550),
    (0x139550, 0x1396b0), (0x1397d8, 0x13bde0),
    (0x1353a8, 0x1353c8), (0x13eff0, 0x13f010),
    (0x140478, 0x140540), (0x140540, 0x1405d8),
    (0x140680, 0x140728), (0x140988, 0x140a10),
    (0x140aa8, 0x140bb0),
]


class UnresolvedCue(ValueError):
    pass


def parse_program(data: bytes, origin=0):
    """Read u16 commands and command-specific attributes, preserving all bytes."""
    require(0 < len(data) <= 65536, 'Cue region outside admitted size')
    at, commands = 0, []
    while at < len(data):
        require(at + 2 <= len(data), 'Truncated cue command')
        start = at
        opcode, = struct.unpack_from('<H', data, at)
        at += 2
        if opcode not in COMMANDS:
            raise UnresolvedCue(f'Unresolved cue command {opcode:#x} at {origin+start:#x}')
        label, name_address, callback, allowed = COMMANDS[opcode]
        attrs, values = [], {name: '' if kind in ('cstring','blob8') else 0 for name, kind in ATTRIBUTES.values()}
        while at < len(data):
            require(at + 2 <= len(data), 'Truncated cue attribute/next command')
            tag, = struct.unpack_from('<H', data, at)
            if tag < 37:
                break
            attribute_at = at
            at += 2
            if tag not in allowed:
                raise UnresolvedCue(f'Unsupported attribute {tag:#x} for {opcode:#x} at {origin+attribute_at:#x}')
            name, kind = ATTRIBUTES[tag]
            if kind == 'blob8':
                require(at < len(data),'Truncated effect blob length')
                size=data[at];at+=1
                require(size > 0 and at+size <= len(data),'Truncated effect blob')
                value=data[at:at+size].hex();at+=size
            elif kind == 'cstring':
                stop = data.find(b'\0', at, min(len(data), at+1024))
                require(stop > at, 'Unterminated or empty cue filename')
                value = data[at:stop].decode('ascii')
                require('/' not in value and '\\' not in value and value not in ('.', '..'), 'Non-basename cue filename')
                at = stop + 1
            else:
                size = struct.calcsize(kind)
                require(at + size <= len(data), 'Truncated cue attribute payload')
                value, = struct.unpack_from(kind, data, at)
                at += size
            attrs.append(dict(tag=tag, name=name, value=value, offset=origin+attribute_at,
                              raw_hex=data[attribute_at:at].hex()))
            values[name] = value  # Original repeated attributes use the last value.
        row = dict(opcode=opcode, name=label, offset=origin+start, end_exclusive=origin+at,
                   diagnostic_string_address=name_address, callback_address=callback,
                   attributes=attrs, values=values, raw_hex=data[start:at].hex(), raw_sha256=sha(data[start:at]))
        commands.append(row)
        if opcode == 1:
            require(at == len(data), 'Unexplained bytes after END; padding not silently accepted')
            return commands
    raise ValueError('Cue has no END marker')


def callback_arguments(command):
    v, op = command['values'], command['opcode']
    if op==0x14:
        return [v['filename'],v['volume'],v['transition_parameter'],v['completion_parameter']]
    if op in (8,9):
        blob=bytes.fromhex(v['effect_blob'])
        require(len(blob)>=4,'Missing effect ID')
        effect_id,=struct.unpack_from('>I',blob)
        if op==9:
            require(len(blob)==4,'Unexpected EFFECT_OFF payload')
            return [effect_id]
        require(len(blob)>=5 and blob[4]<10 and len(blob)==5+4*blob[4], 'Invalid EFFECT_ON argument vector')
        return [effect_id,*struct.unpack_from('>'+str(blob[4])+'i',blob,5)]
    if op==0xb:
        require(v['delay_ticks']==0,'Effect wait delay operand is parsed but not used; nonzero not admitted')
        return [v['sound_id']]
    if op == 0x0c:
        return [v['sound_id'], v['volume'], v['transition_parameter'], v['pan'], v['pitch'], v['completion_parameter']]
    if op == 0x0d:
        return [v['sound_id'], v['transition_parameter'], v['completion_parameter']]
    if op == 0x10:
        return [v['sound_id'], v['pan'], v['transition_parameter'], v['completion_parameter']]
    if op in (0x13, 0x15):
        return [v['transition_parameter'], v['completion_parameter']]
    if op == 0x07:
        # 13AD68 passes zero, NOT the stored filename, to 139550.
        return [0]
    return []


def plan_cue(index: ResourceIndex, name: str):
    match = index.resolve(0x74, name)
    cue = match['selected_cue']
    commands = parse_program(bytes.fromhex(cue['raw_hex']),
                             match['spk_block_absolute_offset'] + cue['program_offset'])
    events = []
    for c in commands:
        if c['opcode'] == 1:
            continue
        v = c['values']
        event = dict(name=c['name'], offset=c['offset'], callback_address=c['callback_address'],
                     arguments=callback_arguments(c), delay_ticks=v['delay_ticks'],
                     schedule='immediate' if v['delay_ticks'] == 0 else 'relative-cue-scheduler-ticks',
                     completion_callback=0x139678 if v['completion_parameter'] and c['opcode'] != 7 else None)
        if c['opcode'] in (7,0x14):
            event.update(filename=v['filename'], asset=index.asset(v['filename']),
                         backend_status='prepared-media-movie-request' if c['opcode']==7 else 'original-bgm-source-and-raw-parameters')
        elif v['sound_id'] and c['name'].startswith('SE_'):
            event['asset'] = index.asset(f"{v['sound_id']:06d}")
        events.append(event)
    return dict(cue=name, spk_block=match['spk_block'], source_cue_sha256=cue['raw_sha256'],
                commands=commands, events=events, execution_status='partial-plan-not-complete-runtime',
                unknowns=['Prepared picture/movie buffer selection and frame advance still require the loader/backend contract.',
                          'END requires separate execute_end with explicit observed state and callbacks; it is not just termination.',
                          'Raw transition/volume/pan/pitch arguments retained; device scaling and wall-clock tick rate unresolved.',
                          'Sound bank codec/channel/rate/loop metadata is not decoded here.'])


@dataclass
class CueEndState:
    """Fields needed by 13BC64..13BDDC on the ordinary (s3=0) path."""
    fallback_media: bool = False         # global+140
    cleanup_done: bool = False            # global+112
    record_marker: bool = False          # global+3760: old effect count (legacy name)
    bgm_handled: bool = False             # global+116
    se_handled: bool = False              # global+120
    retained_sound_ids: list = field(default_factory=list)  # global+3584/3588
    current_program: int | None = None   # gp-21452


def execute_end(state: CueEndState, callbacks):
    """Exact ordinary END side-effect order through explicit backend callbacks.

    Does not implement external sound/recording helpers, bypass mode, or pending
    BGM_PLAY handling. Those remain separate required contracts.
    """
    require(len(state.retained_sound_ids) <= 16 and all(type(n) is int and 0 <= n <= 0xffffffff
            for n in state.retained_sound_ids), 'Invalid retained sound list')
    required = {0x139550} if state.fallback_media else set()
    if not state.cleanup_done:
        if state.record_marker:
            required.add(0x10c7c0)
        if not state.bgm_handled:
            required.add(0x140988)
        if not state.se_handled:
            required.update((0x140bb0, 0x1b2350, 0x140540))
    require(required <= callbacks.keys(), 'Missing END backend callback')
    if state.fallback_media:
        callbacks[0x139550](0)
    if not state.cleanup_done:
        if state.record_marker:
            callbacks[0x10c7c0]()
        if not state.bgm_handled:
            callbacks[0x140988](0, 0)
        if not state.se_handled:
            callbacks[0x140bb0]()
            active = callbacks[0x1b2350]()
            require(isinstance(active, list) and len(active) <= 64 and
                    all(type(n) is int and 0 <= n <= 0xffffffff for n in active), 'Invalid active sound query result')
            for sound_id in active:
                if sound_id not in state.retained_sound_ids:
                    callbacks[0x140540](sound_id, 0, 0)
    state.current_program = None
    state.cleanup_done = True


@dataclass
class CallbackScheduler:
    """139150/139338 ring: seven pending calls, explicit ticks, strict overflow.

    This models callback timing only, not cue END side effects or audio workers.
    Original silently drops queue overflow; this tooling rejects it explicitly.
    """
    slots: list = field(default_factory=lambda: [None] * 8)
    head: int = 0
    tail: int = 0

    @staticmethod
    def _validate(call, callbacks):
        require(type(call['delay_ticks']) is int and 0 <= call['delay_ticks'] <= 65535, 'Invalid delay')
        require(call['callback_address'] in callbacks, 'Missing required callback')
        if call.get('completion_callback') is not None:
            require(call['completion_callback'] in callbacks, 'Missing completion callback')

    @staticmethod
    def _call(call, callbacks):
        callbacks[call['callback_address']](*call['arguments'])
        if call.get('completion_callback') is not None:
            callbacks[call['completion_callback']]()

    def schedule(self, call, callbacks, bypass_delay=False):
        self._validate(call, callbacks)
        if not call['delay_ticks'] or bypass_delay:
            self._call(call, callbacks)
            return
        following = (self.tail + 1) % 8
        require(following != self.head, 'Cue callback ring is full')
        self.slots[self.tail] = dict(call, remaining=call['delay_ticks'])
        self.tail = following

    def advance_ticks(self, ticks, callbacks):
        require(type(ticks) is int and 0 <= ticks <= 0x7fffffff, 'Invalid scheduler delta')
        at = self.head
        while at != self.tail:
            if self.slots[at] is not None:
                self._validate(self.slots[at], callbacks)
            at = (at + 1) % 8
        if ticks == 0:
            return
        at = self.head
        while at != self.tail:
            call = self.slots[at]
            if call is not None:
                call['remaining'] -= ticks
                if call['remaining'] <= 0:
                    self._call(call, callbacks)
                    self.slots[at] = None
            at = (at + 1) % 8
        while self.head != self.tail and self.slots[self.head] is None:
            self.head = (self.head + 1) % 8


def build_report(root=ROOT):
    root = Path(root)
    image = Image((root / 'local/extracted/SLPM_664.52').read_bytes())
    index = ResourceIndex.from_project(root)
    strings = []
    for label, address, _, _ in COMMANDS.values():
        if address is None:
            continue
        at = image.offset(address, len(label)+1)
        raw = image.data[at:at+len(label)+1]
        require(raw == label.encode('ascii') + b'\0', 'Original cue diagnostic string differs')
        strings.append(dict(name=label, address=address, file_offset=at, raw_hex=raw.hex()))
    regions = []
    for start, end in REGIONS:
        region = image.region(start, end)
        for instruction in region['instructions']:
            address = int(instruction['address'], 16)
            instruction['decoded'] = extended_decode(image.word(address), address)
        regions.append(region)
    return dict(evidence_id='SCENARIO-CUES-001', elf_sha256=image.sha256,
                spk_sha256=index.spk_sha256, diagnostic_strings=strings,
                priority_plans=[plan_cue(index, name) for name in PRIORITY],
                scheduler=dict(enqueue=0x139150, tick=0x139338,
                               delay_attribute=0x28, storage_count=8, usable_capacity=7,
                               tick_accumulator_increment=0x1353bc,
                               units='original-update-count; no seconds/fps mapping asserted'),
                evidence_regions=regions,
                limitations=['Partial supported command subset; unsupported input raises, never no-ops.',
                             'Callback scheduler is independently verified; full cue postlude and render/audio backends remain unresolved.'])


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, default=ROOT/'analysis/scenario_cues.json')
    args = ap.parse_args()
    report = build_report()
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(cues=len(report['priority_plans']), regions=len(report['evidence_regions']))))
