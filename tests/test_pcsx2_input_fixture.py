"""Byte-level input fixture tests. Synthetic states are not real PCSX2 states."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('pcsx2_input_fixture', Path(__file__).resolve().parents[1] / 'tools/pcsx2_input_fixture.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def sequence(**changes):
    return {'total_frames': 180, 'events': [{'start_frame': 12, 'end_frame': 19, 'buttons': ['circle'] }]} | changes


class SequenceTests(unittest.TestCase):
    def test_exact_button_flags_and_pressure_bytes(self):
        expected = {'circle': (1, 0xDF, 11), 'cross': (1, 0xBF, 12),
                    'triangle': (1, 0xEF, 10), 'start': (0, 0xF7, None),
                    'up': (0, 0xEF, 8), 'down': (0, 0xBF, 9)}
        for button, (flag_index, flags, pressure_index) in expected.items():
            with self.subTest(button=button):
                value = bytearray([255, 255, 127, 127, 127, 127] + [0] * 12)
                value[flag_index] = flags
                if pressure_index is not None:
                    value[pressure_index] = 255
                self.assertEqual(fixture.pad_bytes([button]), bytes(value))

    def test_inclusive_hold_and_release_with_terminal_buffer(self):
        frames = list(fixture.frame_blocks(sequence()))
        self.assertEqual(len(frames), 181)
        self.assertEqual({len(frame) for frame in frames}, {36})
        neutral = bytes([255, 255, 127, 127, 127, 127] + [0] * 12)
        for index, frame in enumerate(frames):
            self.assertEqual(frame[18:], neutral)
            self.assertEqual(frame[:18], fixture.pad_bytes(['circle']) if 12 <= index <= 19 else neutral)

    def test_adjacent_events_start_after_previous_release(self):
        seq = {'total_frames': 10, 'events': [
            {'start_frame': 1, 'end_frame': 3, 'buttons': ['circle']},
            {'start_frame': 4, 'end_frame': 6, 'buttons': ['cross']}]}
        frames = list(fixture.frame_blocks(seq))
        self.assertEqual(frames[3][:18], fixture.pad_bytes(['circle']))
        self.assertEqual(frames[4][:18], fixture.pad_bytes(['cross']))
        self.assertEqual(frames[7][:18], fixture.NEUTRAL)

    def test_other_port_can_overlap(self):
        seq = {'total_frames': 10, 'events': [
            {'start_frame': 2, 'end_frame': 4, 'buttons': ['up'], 'port': 0},
            {'start_frame': 3, 'end_frame': 5, 'buttons': ['start'], 'port': 1}]}
        frames = list(fixture.frame_blocks(seq))
        self.assertEqual(frames[3], fixture.pad_bytes(['up']) + fixture.pad_bytes(['start']))

    def test_invalid_total_frames(self):
        for total in (0, -1, True, 2.5, '180', fixture.MAX_TOTAL_FRAMES + 1):
            with self.subTest(total=total), self.assertRaises(fixture.FixtureError):
                fixture.validate_sequence(sequence(total_frames=total))

    def test_invalid_event_bounds_and_fields(self):
        event = sequence()['events'][0]
        cases = [{'start_frame': 0}, {'end_frame': 180}, {'end_frame': 11},
                 {'start_frame': True}, {'port': 2}, {'port': False}, {'extra': 1},
                 {'buttons': []}, {'buttons': 'circle'}, {'buttons': ['left']},
                 {'buttons': ['circle', 'circle']}, {'buttons': ['up', 'down']}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(fixture.FixtureError):
                fixture.validate_sequence(sequence(events=[event | changes]))
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_sequence(sequence(events=[{'buttons': ['circle']}]))

    def test_overlapping_same_port_rejected(self):
        event = sequence()['events'][0]
        with self.assertRaisesRegex(fixture.FixtureError, 'Overlapping'):
            fixture.validate_sequence(sequence(events=[event, event | {'start_frame': 19, 'end_frame': 25}]))

    def test_strict_json_rejects_duplicate_or_unknown_keys(self):
        bad = ['{"total_frames":2,"total_frames":3,"events":[]}',
               '{"total_frames":NaN,"events":[]}',
               '{"total_frames":2,"events":[],"unexpected":1}', '[]']
        for text in bad:
            with self.subTest(text=text), self.assertRaises(fixture.FixtureError):
                fixture.parse_sequence_json(text)

    def test_oversized_sequence_rejected(self):
        with self.assertRaisesRegex(fixture.FixtureError, '1 MiB'):
            fixture.parse_sequence_json(' ' * (fixture.MAX_SEQUENCE_BYTES + 1))


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'baseline.p2m2'
        self.source_state = Path(str(self.source) + '_SaveState.p2s')
        self.output = self.root / 'circle.p2m2'
        self.output_state = Path(str(self.output) + '_SaveState.p2s')
        self.report = self.root / 'report.json'
        header = bytearray(570)
        header[0] = 1
        header[1:51] = b'PCSX2-v2.8.2'.ljust(50, b'\0')
        header[51:306] = b'Fixture test'.ljust(255, b'\0')
        header[306:561] = b'\x82\xa0opaque-game-name'.ljust(255, b'\0')
        struct.pack_into('<I', header, 565, 7)
        header[569] = 1
        self.original = bytes(header)
        self.source.write_bytes(self.original)
        self.source_state.write_bytes(b'Synthetic state bytes; not a real emulator state')

    def generate(self, **changes):
        args = {'source': self.source, 'output': self.output, 'sequence': sequence(),
                'report_path': self.report, 'baseline_controller': 'dualshock2'}
        args.update(changes)
        return fixture.generate(**args)

    def test_generation_preserves_source_and_records_digests(self):
        state = self.source_state.read_bytes()
        report = self.generate()
        data = self.output.read_bytes()
        self.assertEqual(len(data), 570 + 181*36)
        self.assertEqual(data[:561], self.original[:561])
        self.assertEqual(struct.unpack_from('<II', data, 561), (180, 0))
        self.assertEqual(data[569], 1)
        self.assertEqual(data[570 + 12*36:570 + 12*36 + 18], fixture.pad_bytes(['circle']))
        self.assertEqual(data[-36:], fixture.NEUTRAL * 2)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.source_state.read_bytes(), state)
        self.assertEqual(self.output_state.read_bytes(), state)
        self.assertEqual(report['output_movie']['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(report['output_state']['sha256'], hashlib.sha256(state).hexdigest())
        self.assertFalse(report['playback_validated'])
        self.assertFalse(report['controller_baseline']['verified_from_state'])
        self.assertEqual(json.loads(self.report.read_text(encoding='utf-8')), report)

    def test_jogcon_baseline_explicitly_unsuitable_for_playback(self):
        report = self.generate(baseline_controller='jogcon')
        self.assertIn('NOT approved for playback', report['controller_baseline']['note'])
        self.assertFalse(report['playback_validated'])

    def test_existing_destination_report_or_state_rejected_before_writes(self):
        for path in (self.output, self.output_state, self.report):
            with self.subTest(path=path.name):
                path.write_bytes(b'preserve')
                with self.assertRaisesRegex(fixture.FixtureError, 'overwrite'):
                    self.generate()
                self.assertEqual(path.read_bytes(), b'preserve')
                path.unlink()
                self.assertFalse(any(p.exists() for p in (self.output, self.output_state, self.report)))

    def test_source_as_output_rejected(self):
        with self.assertRaisesRegex(fixture.FixtureError, 'overwrite'):
            self.generate(output=self.source)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_bad_header_version_or_state_flag_rejected(self):
        for index, value in ((0, 2), (569, 0), (569, 2)):
            data = bytearray(self.original)
            data[index] = value
            self.source.write_bytes(data)
            with self.subTest(index=index, value=value), self.assertRaisesRegex(fixture.FixtureError, 'version-1'):
                self.generate()
        self.assertFalse(self.output.exists())

    def test_truncated_header_and_payload_rejected(self):
        for data in (self.original[:-1], self.original + b'\0'):
            self.source.write_bytes(data)
            with self.subTest(length=len(data)), self.assertRaises(fixture.FixtureError):
                self.generate()
        data = bytearray(self.original)
        struct.pack_into('<I', data, 561, 10)
        self.source.write_bytes(data)
        with self.assertRaisesRegex(fixture.FixtureError, 'truncated'):
            self.generate()

    def test_other_emulator_version_rejected(self):
        data = bytearray(self.original)
        data[1:51] = b'PCSX2-v2.9.0'.ljust(50, b'\0')
        self.source.write_bytes(data)
        with self.assertRaisesRegex(fixture.FixtureError, 'v2.8.2'):
            self.generate()

    def test_missing_or_empty_paired_state_rejected(self):
        self.source_state.unlink()
        with self.assertRaises(FileNotFoundError):
            self.generate()
        self.source_state.write_bytes(b'')
        with self.assertRaisesRegex(fixture.FixtureError, 'empty'):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_path_traversal_and_device_names_rejected(self):
        for output in (self.root/'..'/'escape.p2m2', self.root/'NUL.p2m2', self.root/'bad\x01.p2m2'):
            with self.subTest(output=str(output)), self.assertRaises(fixture.FixtureError):
                self.generate(output=output)

    def test_failed_write_cleans_only_own_outputs(self):
        with patch.object(fixture.os, 'fsync', side_effect=OSError('injected write failure')):
            with self.assertRaisesRegex(OSError, 'injected'):
                self.generate()
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse(any(p.exists() for p in (self.output, self.output_state, self.report)))

    def test_changing_source_during_generation_is_detected(self):
        original_fsync = fixture.os.fsync
        changed = False
        def change_once(fd):
            nonlocal changed
            original_fsync(fd)
            if not changed:
                changed = True
                self.source.write_bytes(self.original + bytes(36))
        with patch.object(fixture.os, 'fsync', side_effect=change_once):
            with self.assertRaisesRegex(fixture.FixtureError, 'changed during'):
                self.generate()
        self.assertFalse(any(p.exists() for p in (self.output, self.output_state, self.report)))

    def test_symlink_output_root_rejected(self):
        destination = self.root / 'destination'
        destination.mkdir()
        alias = self.root / 'alias'
        try:
            alias.symlink_to(destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow symlinks: {error}')
        with self.assertRaisesRegex(fixture.FixtureError, 'Symlink'):
            self.generate(output=alias / 'movie.p2m2')

    def test_cli_sequence_file(self):
        seq_path = self.root / 'sequence.json'
        seq_path.write_text(json.dumps(sequence()), encoding='utf-8')
        with redirect_stdout(io.StringIO()):
            fixture.main(['--source', str(self.source), '--output', str(self.output), '--report', str(self.report),
                          '--sequence', str(seq_path), '--baseline-controller', 'dualshock2'])
        self.assertTrue(self.output.exists())
        self.assertEqual(self.source.read_bytes(), self.original)


if __name__ == '__main__':
    unittest.main()
