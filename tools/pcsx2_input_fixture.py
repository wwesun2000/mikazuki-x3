"""Build offline PCSX2 v2.8.2 input fixtures from a stopped Save State recording.

Sequence JSON: {"total_frames": 180, "events": [
  {"start_frame": 12, "end_frame": 19, "buttons": ["circle"], "port": 0}
]}. Event endpoints are inclusive. Frame 0 and terminal frame total_frames are
always released. Ports are 0/1; overlapping events on the same port are rejected.

This writes new .p2m2 + matching _SaveState.p2s files and a provenance report;
it never edits emulator configuration or drives the running emulator. The source
recording must be stopped. The paired state must use a DualShock2 controller.
Controller observations are caller-supplied: this tool does not decode the state
to prove controller type. Jogcon/unverified baselines are marked unsuitable.
These are emulator debugging fixtures, NOT native-port or in-game save files.

Version-pinned format sources:
https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/Recording/InputRecordingFile.h
https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/Recording/InputRecordingFile.cpp
https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/Recording/PadData.cpp
https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/VMManager.cpp#L2720-L2738
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

HEADER_SIZE = 570
PORT_BYTES = 18
FRAME_BYTES = 36
MAX_TOTAL_FRAMES = 1_000_000
MAX_EVENTS = 10_000
MAX_SEQUENCE_BYTES = 1_048_576
SUPPORTED_EMULATOR = b'PCSX2-v2.8.2'
NEUTRAL = bytes([255, 255, 127, 127, 127, 127] + [0] * 12)
# (compact flag byte, active-low bit, optional pressure-byte index)
BUTTONS = {'circle': (1, 0x20, 11), 'cross': (1, 0x40, 12),
           'triangle': (1, 0x10, 10), 'start': (0, 0x08, None),
           'up': (0, 0x10, 8), 'down': (0, 0x40, 9)}
SOURCE_URLS = [
    'https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/Recording/' + filename
    for filename in ('InputRecordingFile.h', 'InputRecordingFile.cpp', 'PadData.cpp', 'InputRecording.cpp')
] + ['https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/VMManager.cpp#L2720-L2738']


class FixtureError(ValueError):
    pass


def _strict_int(value, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FixtureError(f'{label} must be an integer in {minimum}..{maximum}')
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f'Duplicate JSON key: {key}')
        result[key] = value
    return result


def parse_sequence_json(text: str) -> dict:
    if len(text.encode('utf-8')) > MAX_SEQUENCE_BYTES:
        raise FixtureError('Sequence exceeds 1 MiB safety limit')
    def reject_constant(value):
        raise FixtureError(f'Non-finite JSON number: {value}')
    return validate_sequence(json.loads(text, object_pairs_hook=_unique_object, parse_constant=reject_constant))


def validate_sequence(sequence: dict) -> dict:
    if type(sequence) is not dict or set(sequence) != {'total_frames', 'events'}:
        raise FixtureError('Sequence requires exactly total_frames and events')
    total = _strict_int(sequence['total_frames'], 'total_frames', 1, MAX_TOTAL_FRAMES)
    events = sequence['events']
    if type(events) is not list or len(events) > MAX_EVENTS:
        raise FixtureError(f'events must be a list of at most {MAX_EVENTS} entries')
    normalized = []
    for index, event in enumerate(events):
        if type(event) is not dict or not {'start_frame', 'end_frame', 'buttons'} <= set(event) or set(event) - {'start_frame', 'end_frame', 'buttons', 'port'}:
            raise FixtureError(f'Invalid event fields at {index}')
        start = _strict_int(event['start_frame'], 'start_frame', 1, total - 1)
        end = _strict_int(event['end_frame'], 'end_frame', start, total - 1)
        port = _strict_int(event.get('port', 0), 'port', 0, 1)
        buttons = event['buttons']
        if type(buttons) is not list or not buttons or any(type(b) is not str or b not in BUTTONS for b in buttons):
            raise FixtureError(f'buttons must be a nonempty list from {sorted(BUTTONS)}')
        if len(buttons) != len(set(buttons)) or {'up', 'down'} <= set(buttons):
            raise FixtureError('Duplicate or opposing buttons in one event')
        normalized.append({'start_frame': start, 'end_frame': end, 'buttons': sorted(buttons), 'port': port})
    normalized.sort(key=lambda e: (e['start_frame'], e['port'], e['end_frame']))
    last_end = [-1, -1]
    for event in normalized:
        port = event['port']
        if event['start_frame'] <= last_end[port]:
            raise FixtureError('Overlapping events on the same port')
        last_end[port] = event['end_frame']
    return {'total_frames': total, 'events': normalized}


def pad_bytes(buttons: list[str]) -> bytes:
    data = bytearray(NEUTRAL)
    for button in buttons:
        if button not in BUTTONS:
            raise FixtureError(f'Unsupported button: {button}')
        index, mask, pressure = BUTTONS[button]
        data[index] &= ~mask
        if pressure is not None:
            data[pressure] = 255
    return bytes(data)


def frame_blocks(sequence: dict):
    sequence = validate_sequence(sequence)
    changes = {}
    for event in sequence['events']:
        changes.setdefault(event['start_frame'], []).append((event['port'], pad_bytes(event['buttons'])))
        changes.setdefault(event['end_frame'] + 1, []).append((event['port'], NEUTRAL))
    ports = [NEUTRAL, NEUTRAL]
    for frame in range(sequence['total_frames'] + 1):
        for port, data in changes.get(frame, ()):
            ports[port] = data
        yield ports[0] + ports[1]


def safe_path(path: Path) -> Path:
    path = Path(path)
    if '..' in path.parts:
        raise FixtureError('Parent traversal is not allowed')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
    for part in path.parts:
        if part == path.anchor:
            continue
        if (part.rstrip(' .') != part or part.split('.')[0].upper() in reserved
                or any(ord(c) < 32 or ord(c) == 127 or c in ':<>"|?*' for c in part)):
            raise FixtureError(f'Unsafe path component: {part!r}')
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or (hasattr(candidate, 'is_junction') and candidate.is_junction()):
            raise FixtureError('Symlink/junction paths are not allowed')
    return path.resolve()


def _identity(path: Path) -> tuple:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise FixtureError(f'Expected a regular file: {path}')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _hash(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_baseline(source: Path) -> tuple[bytes, dict]:
    source = safe_path(source)
    if source.suffix.lower() != '.p2m2':
        raise FixtureError('Source recording must have .p2m2 extension')
    before = _identity(source)
    with source.open('rb') as stream:
        header = stream.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[0] != 1 or header[569] != 1:
        raise FixtureError('Baseline must have a complete version-1 Save State header')
    emulator = header[1:51].split(b'\0', 1)[0]
    if emulator != SUPPORTED_EMULATOR:
        raise FixtureError('Only the verified PCSX2-v2.8.2 baseline is supported')
    total, undo = struct.unpack_from('<II', header, 561)
    payload_size = before[2] - HEADER_SIZE
    if payload_size % FRAME_BYTES or (total > 0 and payload_size < (total + 1) * FRAME_BYTES):
        raise FixtureError('Baseline payload is truncated or inconsistent with its frame bound')
    digest = _hash(source)
    if _identity(source) != before:
        raise FixtureError('Baseline changed while being read; stop recording first')
    return header, {'path': str(source), 'size': before[2], 'sha256': digest,
                    'header_sha256': hashlib.sha256(header).hexdigest(), 'emulator': emulator.decode('ascii'),
                    'format_version': 1, 'from_savestate': True, 'total_frames': total, 'undo_count': undo}


def generate(source: Path, output: Path, sequence: dict, report_path: Path,
             baseline_controller: str = 'unverified', notes: list[str] | None = None) -> dict:
    if baseline_controller not in ('dualshock2', 'jogcon', 'unverified'):
        raise FixtureError('baseline_controller must be dualshock2, jogcon, or unverified')
    notes = [] if notes is None else notes
    if type(notes) is not list or len(notes) > 64 or any(type(note) is not str or len(note) > 4096 for note in notes):
        raise FixtureError('notes must contain at most 64 strings of at most 4096 characters')
    sequence = validate_sequence(sequence)
    source = safe_path(source)
    state_source = safe_path(Path(str(source) + '_SaveState.p2s'))
    output = safe_path(output)
    state_output = safe_path(Path(str(output) + '_SaveState.p2s'))
    report_path = safe_path(report_path)
    if output.suffix.lower() != '.p2m2' or report_path.suffix.lower() != '.json':
        raise FixtureError('Output must be .p2m2 and report must be .json')
    destinations = [output, state_output, report_path]
    if len(set(destinations)) != 3:
        raise FixtureError('Output paths overlap')
    for path in destinations:
        if path.exists() or path in (source, state_source):
            raise FixtureError(f'Refusing to overwrite an existing path: {path}')
    source_identity, state_identity = _identity(source), _identity(state_source)
    if state_identity[2] == 0:
        raise FixtureError('Paired Save State is empty')
    header, source_info = read_baseline(source)
    state_digest = _hash(state_source)
    if _identity(state_source) != state_identity:
        raise FixtureError('Paired Save State changed while being read')
    new_header = bytearray(header)
    struct.pack_into('<II', new_header, 561, sequence['total_frames'], 0)
    created = []
    def open_output(path):
        safe_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_path(path)
        stream = path.open('xb')
        created.append((path, os.fstat(stream.fileno()).st_ino))
        return stream
    try:
        fixture_digest = hashlib.sha256()
        with open_output(output) as stream:
            stream.write(new_header)
            fixture_digest.update(new_header)
            for block in frame_blocks(sequence):
                stream.write(block)
                fixture_digest.update(block)
            stream.flush()
            os.fsync(stream.fileno())
        copied_digest = hashlib.sha256()
        with state_source.open('rb') as stream, open_output(state_output) as target:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                target.write(block)
                copied_digest.update(block)
            target.flush()
            os.fsync(target.fileno())
        if copied_digest.hexdigest() != state_digest or _identity(state_source) != state_identity or _identity(source) != source_identity or _hash(source) != source_info['sha256']:
            raise FixtureError('Source baseline changed during generation')
        fixture_sha = fixture_digest.hexdigest()
        if _hash(output) != fixture_sha or _hash(state_output) != state_digest:
            raise FixtureError('Written output digest verification failed')
        note = ('Caller reports a DualShock2 baseline; emulator playback remains untested.'
                if baseline_controller == 'dualshock2' else
                'Baseline controller is Jogcon or unverified: this fixture is NOT approved for playback; regenerate from a confirmed DualShock2 baseline.')
        report = {
            'schema_version': 1, 'evidence_id': 'INPUT-FIXTURE-001',
            'generated_at_utc': datetime.now(timezone.utc).isoformat(),
            'purpose': 'emulator-debug-input-fixture; not a native-port or in-game save',
            'source_movie': source_info,
            'source_state': {'path': str(state_source), 'size': state_identity[2], 'sha256': state_digest},
            'source_files_unchanged': True, 'sequence': sequence,
            'sequence_sha256': hashlib.sha256(json.dumps(sequence, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'output_movie': {'path': str(output), 'size': output.stat().st_size, 'sha256': fixture_sha,
                             'format_version': 1, 'header_size': HEADER_SIZE, 'bytes_per_frame': FRAME_BYTES,
                             'frame_records': sequence['total_frames'] + 1,
                             'terminal_frame_is_released': True, 'from_savestate': True},
            'output_state': {'path': str(state_output), 'size': state_output.stat().st_size, 'sha256': state_digest},
            'controller_baseline': {'expected': 'DualShock2', 'caller_observation': baseline_controller,
                                    'verified_from_state': False, 'note': note},
            'playback_validated': False, 'format_sources': SOURCE_URLS, 'notes': notes,
            'limitations': ['No emulator process, configuration, or memory is accessed by this tool.',
                           'The paired save state is copied byte-for-byte, not decoded or validated by PCSX2.',
                           'Use a disposable movie/state copy for UI playback: v2.8.2 may switch to recording and write the terminal frame.',
                           'Stop input recording after the terminal pause before returning to ordinary gameplay.',
                           'Source stat/hash checks do not provide a filesystem-wide atomic snapshot.']}
        with open_output(report_path) as stream:
            stream.write((json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        return report
    except BaseException:
        # Remove only files exclusively created by this invocation, retaining any
        # path whose identity was replaced by another actor.
        for path, inode in reversed(created):
            if path.exists() and not path.is_symlink() and path.stat().st_ino == inode:
                path.unlink()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--baseline-controller', choices=['dualshock2', 'jogcon', 'unverified'], default='unverified',
                        help='Caller-observed type in paired state; does not constitute automatic verification')
    parser.add_argument('--note', action='append', default=[], help='Provenance note retained in the report')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sequence', type=Path, help='UTF-8 JSON file, at most 1 MiB')
    group.add_argument('--sequence-json', help='Inline JSON with total_frames and inclusive events')
    args = parser.parse_args(argv)
    if args.sequence:
        path = safe_path(args.sequence)
        if path.stat().st_size > MAX_SEQUENCE_BYTES:
            raise FixtureError('Sequence exceeds 1 MiB safety limit')
        text = path.read_text(encoding='utf-8')
    else:
        text = args.sequence_json
    report = generate(args.source, args.output, parse_sequence_json(text), args.report, args.baseline_controller, args.note)
    print(json.dumps({key: report[key] for key in ('output_movie', 'output_state', 'controller_baseline', 'playback_validated')}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
