"""Source-derived audio parameter / two-member MMV backend contract.

The caller owns the cue queue, active voices, the source audio-update clock,
and the explicit output mode.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct

from scenario_resources import ROOT, require, sha
from se_bank import parse_bank
from vm_handlers import Image
from vm_presentation_semantics import extended_decode

IOP_SHA = '8e6627a3aba481b1145ad497d042e0e543701494a73bf25d925eb9a03fe951bf'
# Original SSDV.IRX .rodata pantable, 17 pairs of signed 32-bit integers.
PAN_TABLE = ((0,16),(1,15),(2,14),(4,14),(6,13),(8,13),(10,13),(11,12),
             (12,12),(12,11),(13,10),(13,8),(13,6),(14,4),(14,2),(15,1),(16,0))


def f32(x):
    return struct.unpack('<f', struct.pack('<f', x))[0]


def pan_index(raw_pan: int) -> int:
    require(type(raw_pan) is int and -32768 <= raw_pan <= 32767, 'Invalid signed pan')
    return max(0, min(16, int(f32(f32(f32(raw_pan) * f32(.01)) * 8)) + 8))


def volume_factor(raw_volume: int) -> float:
    require(type(raw_volume) is int and 0 <= raw_volume <= 65535, 'Invalid volume')
    return f32(f32(raw_volume) / 100)


def volume_register(base_volume: int, factor: float, fade_factor=1.0) -> int:
    """Original 1D3530: multiply both envelopes then truncate / clamp."""
    require(0 <= base_volume <= 65535, 'Invalid original volume')
    return max(0, min(16383, int(f32(f32(f32(base_volume) * f32(factor)) * f32(fade_factor)))))


def legacy_pitch_factor(raw_pitch: int) -> float:
    """1B0D38's legacy 100-unit steps; deliberately NOT equal-tempered cents."""
    require(type(raw_pitch) is int and -32768 <= raw_pitch <= 32767, 'Invalid pitch')
    whole = int(raw_pitch / 100)  # original signed DIV truncates toward zero
    fraction = raw_pitch - whole * 100
    value = 1.0
    while whole >= 12:
        value = f32(value + value)
        whole -= 12
    while whole <= -12:
        value = f32(value * .5)
        whole += 12
    factor = f32(1.0833) if whole > 0 else f32(.91667)
    for _ in range(abs(whole)):
        value = f32(value * factor)
    if fraction:
        fine = f32(f32(f32(fraction) * f32(.08333)) / 100)
        value = f32(value * f32(1.0 + fine))
    return value


def pitch_register(base_pitch: int, factor: float) -> int:
    return max(0, min(4095, int(f32(f32(base_pitch) * f32(factor)))))


def voice_layout(record: dict) -> dict:
    """Static raw-bank path. No presumed choice of the second stored stream."""
    flag = record['raw_playback_flags']
    stereo_source = bool(flag & 0x80)
    require(not stereo_source or record['stored_stream_count'] == 2,
            'Stereo source flag without a second stored stream')
    delays = [0, 0] if stereo_source else list(record['raw_route_bytes'])
    require(len(delays) == 2 and all(type(x) is int and 0 <= x < 255 for x in delays),
            'Unsupported initial voice delay')
    return dict(source_streams=[0, 1 if stereo_source else 0],
                raw_delay_ticks=delays,
                key_on_update_numbers=[max(1, x) for x in delays],
                paired_start=delays == [0, 0],
                # The update which starts the first voice is offset 0.
                relative_start_ticks=[max(1, x) - min(max(1, y) for y in delays) for x in delays])


def channel_registers(volume: int, pan: int, stereo_output: bool, paired_start: bool) -> list[list[int]]:
    """SSDV Noteon/NoteModify: rows=SPU voices, columns=output L/R.

    Delayed starts attenuate the opposite side by integer division by eight.
    Source stereo and output stereo are separate original fields.
    """
    require(type(stereo_output) is bool and type(paired_start) is bool, 'Explicit output mode required')
    require(0 <= volume <= 16383 and 0 <= pan <= 16, 'Bad mixer register input')
    if not stereo_output:
        gain = volume * 8 // 10
        return [[gain, gain], [gain, gain]]
    # IOP 0xEC0 multiplies volume by table[1] for VOLL; 0xEE8 uses
    # table[0] for VOLR. The on-disk table is ordered R,L.
    right, left = PAN_TABLE[pan]
    if paired_start:
        return [[volume * left // 16, volume * right // 16] for _ in range(2)]
    return [[volume * left // 16, volume * (right // 8) // 16],
            [volume * (left // 8) // 16, volume * right // 16]]


def queued_play_volume(raw_volume: int, transition: int, sound_id: int, following: list[dict]) -> int:
    """13F750: suppress an immediate onset preceding queued zero-volume fade."""
    if transition == 0 and any(c['command'] == 'SE_CHANGE_VOLUME' and
                             c['args'][0] == sound_id and c['args'][1] == 0 and
                             c['args'][2] != 0 for c in following):
        return 0
    return raw_volume


def play_contract(record: dict, args: list[int], *, stereo_output: bool,
                  active_loop_ids=(), following_queue=()) -> dict:
    require(len(args) == 6 and all(type(x) is int for x in args), 'SE_PLAY requires six raw arguments')
    sound_id, raw_volume, transition, raw_pan, ignored_pitch, completion = args
    require(str(sound_id).zfill(6) == record['name'] and 0 <= transition <= 65535,
            'Sound identity / transition invalid')
    if record['raw_loop_flag'] and sound_id in active_loop_ids:
        return dict(action='no-op-existing-loop', sound_id=sound_id,
                    restart=False, alter_existing_parameters=False, completion_wait_ticks=0)
    volume = queued_play_volume(raw_volume, transition, sound_id, following_queue)
    layout = voice_layout(record)
    target = volume_factor(volume)
    register = volume_register(record['base_volume'], target)
    matrix = channel_registers(register, pan_index(raw_pan), stereo_output, layout['paired_start'])
    return dict(action='start', sound_id=sound_id, **layout,
                raw_args=args, consumed_raw_pitch=False, ignored_raw_pitch=ignored_pitch,
                initial_pitch_factor=1.0, pitch_register=pitch_register(record['base_pitch'], 1.0),
                volume_target_factor=target, volume_initial_factor=0.0 if transition else target,
                volume_step_per_update=f32(target / transition) if transition else 0.0,
                volume_register_at_target=register, pan_index=pan_index(raw_pan),
                target_output_registers=matrix,
                target_output_linear_gains=[[x / 16384 for x in row] for row in matrix],
                transition_ticks=transition, nominal_transition_seconds=transition / 60,
                completion_wait_ticks=transition + 1 if completion and transition > 0 else 0,
                loop_enabled=record['raw_loop_flag'],
                gain_boundary='per-voice-before-ADSR-reverb-core-master-and-modern-user-bus')


@dataclass
class LinearRamp:
    """Original per-audio-update slope and endpoint clamp, not an easing curve."""
    current: float
    target: float
    step: float

    @classmethod
    def begin(cls, current, target, transition):
        require(type(transition) is int and 0 <= transition <= 65535, 'Invalid transition')
        if transition == 0:
            return cls(f32(target), f32(target), 0.0)
        return cls(f32(current), f32(target), f32(f32(f32(target) - f32(current)) / transition))

    def tick(self):
        if self.step:
            value = f32(self.current + self.step)
            if (self.step > 0 and value >= self.target) or (self.step < 0 and value <= self.target):
                value, self.step = self.target, 0.0
            self.current = value
        return self.current


def change_contract(command: str, args: list[int], current: float) -> dict:
    require(command in ('SE_STOP', 'SE_CHANGE_VOLUME', 'SE_CHANGE_PAN', 'SE_CHANGE_PITCH'),
            'Unsupported audio callback')
    require(len(args) == (3 if command == 'SE_STOP' else 4), 'Wrong callback arity')
    if command == 'SE_STOP':
        sound_id, transition, completion = args
        target, parameter = 0.0, 'stop_fade_factor'
    else:
        sound_id, raw, transition, completion = args
        parameter = {'SE_CHANGE_VOLUME': 'volume_factor', 'SE_CHANGE_PAN': 'pan_factor',
                     'SE_CHANGE_PITCH': 'pitch_factor'}[command]
        target = (volume_factor(raw) if command == 'SE_CHANGE_VOLUME' else
                  f32(f32(raw) * f32(.01)) if command == 'SE_CHANGE_PAN' else legacy_pitch_factor(raw))
    ramp = LinearRamp.begin(current, target, transition)
    return dict(sound_id=sound_id, parameter=parameter, apply_to='all-matching-live-voices',
                initial=ramp.current, target=ramp.target, step=ramp.step,
                transition_ticks=transition, nominal_transition_seconds=transition / 60,
                completion_wait_ticks=transition + 1 if completion else 0,
                key_off_at_zero=command == 'SE_STOP',
                remove_active_loop_bookkeeping_immediately=command == 'SE_STOP')


@dataclass
class MmvPlayback:
    """198158 thread contract: exactly two members; 0 once then 1 only."""
    loop_tail: bool
    member: int = 0
    tail_iterations: int = 0
    state: str = 'playing'

    def end_member(self):
        require(self.state == 'playing', 'MMV is not playing')
        if self.member == 0:
            self.member = 1
        elif self.loop_tail:
            self.tail_iterations += 1
        else:
            self.state = 'completed-awaiting-drain'
        return self.member if self.state == 'playing' else None

    def stop(self):
        self.state = 'stopped'


def iop_region(data, start, end):
    # This IRX has .text/.rodata at file offset +0xA0; hash-bound below.
    return dict(module='SSDV.IRX', start=hex(start), end_exclusive=hex(end),
                raw_sha256=sha(data[start + 0xa0:end + 0xa0]),
                instructions=[dict(address=hex(a), raw=hex(struct.unpack_from('<I', data, a + 0xa0)[0]),
                                   decoded=extended_decode(struct.unpack_from('<I', data, a + 0xa0)[0], a))
                              for a in range(start, end, 4)])


def report(root=ROOT):
    root = Path(root)
    im = Image((root / 'local/extracted/SLPM_664.52').read_bytes())
    iop = (root / 'local/extracted/IRX/SSDV.IRX').read_bytes()
    require(sha(iop) == IOP_SHA, 'SSDV module identity mismatch')
    table = tuple(struct.unpack_from('<ii', iop, 0x17d4 + 0xa0 + i * 8) for i in range(17))
    require(table == PAN_TABLE, 'Original pan table changed')
    rows = parse_bank((root / 'local/assets/SOUND/SSDVDAT/se.dat').read_bytes())
    by_name = {r['name']: r for r in rows}
    regions = [(0x13fa20,0x13fa94),(0x1b15f0,0x1b1744),(0x1b0ce8,0x1b0ea8),
               (0x1b1ae8,0x1b1e88),(0x1b22c0,0x1b2304),(0x1d24dc,0x1d2534),
               (0x1d25f8,0x1d2610),(0x1d2f34,0x1d3348),(0x1d34d0,0x1d3568),
               (0x1b0338,0x1b0370),(0x138518,0x1385a4),(0x1389f8,0x138a40),
               (0x138420,0x138438),(0x13f498,0x13f4e0),(0x195568,0x195598),
               (0x1953dc,0x1953ec),(0x197c10,0x197c60),(0x198214,0x1982e4),
               (0x197cb0,0x197d28)]
    return dict(evidence_id='AUDIO-MEDIA-CONTRACT-001', elf_sha256=im.sha256,
                iop_sha256=IOP_SHA, pan_table=table,
                examples={name: play_contract(by_name[name], args, stereo_output=True)
                          for name,args in [('537002',[537002,80,240,0,0,0]),
                                            ('532019',[532019,15,0,-30,0,0]),
                                            ('101039',[101039,100,0,0,0,0])]},
                mmv=dict(asset='pr5011m.mmv', member_order=[0,1], member0_once=True,
                         member1_loops=True, source_member_frames=[90,90],
                         loop_flag_chain=['type_table[mmv]+36=1','dependency.flags|=1',
                                          'manager+84=1','13F038','195150',
                                          '195378','197C10','decoder+512 bit0']),
                modern_adapter=dict(required=['original source stream selection', 'two voice start offsets',
                                              'per-voice L/R gain matrix', 'source loop sample indexes',
                                              'raw cue ordering and active-loop duplicate suppression',
                                              'linear transition endpoint and original pitch mapping'],
                                    allowed=['device resampler and final sample format',
                                             'declared master/user bus gain',
                                             'smooth interpolation between original 60-Hz control steps',
                                             'first-pass PCM loop rather than SPU2 predictor-state replay',
                                             'documented ADSR/reverb approximation']),
                evidence_windows=[im.region(a,b) for a,b in regions],
                iop_windows=[iop_region(iop,a,b) for a,b in [(0xd04,0xf50),(0x1078,0x11e4)]])


if __name__ == '__main__':
    output = ROOT / 'analysis/audio_media_contract.json'
    output.write_text(json.dumps(report(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(output)
