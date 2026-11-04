"""Synthetic FAD corruption tests; never modify or reread the 3.6 GB source ISO."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('fad', Path(__file__).resolve().parents[1] / 'tools' / 'fad.py')
fad = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fad)
S = 2048
NONE = 0xFFFFFFFF


def record(name=b'ROOT', kind=1, size=0, sector=NONE, parent=NONE, child=1, extension=b'txt'):
    result = bytearray(32)
    struct.pack_into('<I', result, 0, kind)
    if kind == 1:
        result[4:16] = name.ljust(12, b'\0')[:12]
    else:
        result[4:12] = name.ljust(8, b'\0')[:8]
        result[12:15] = extension.ljust(3, b'\0')[:3]
    struct.pack_into('<4I', result, 16, size, sector, parent, child)
    return bytes(result)


def file_record(name=b'sample', size=5, sector=1, parent=0, child=NONE):
    return record(name, 0, size, sector, parent, child)


def table(sector=1, name=b'sample', size=5):
    return (record() + file_record(name, size, sector)).ljust(S, b'\0')


class IndexTests(unittest.TestCase):
    def test_hierarchy_locations_and_padding(self):
        rows = fad.parse_index(table())
        self.assertEqual([r['path'] for r in rows], ['ROOT', 'ROOT/sample.txt'])
        self.assertEqual(rows[1]['index_offset'], 32)
        self.assertEqual(rows[1]['sector'], 1)
        self.assertEqual(rows[1]['size'], 5)

    def test_truncated_record_rejected(self):
        for length in (1, 31, 33, 63):
            with self.subTest(length=length), self.assertRaises(ValueError):
                fad.parse_index(table()[:length])

    def test_nonzero_after_padding_rejected(self):
        with self.assertRaisesRegex(ValueError, 'padding'):
            fad.parse_index(bytes(32) + record())

    def test_unknown_record_kind(self):
        with self.assertRaisesRegex(ValueError, 'kind'):
            fad.parse_index(record(kind=2))

    def test_file_cannot_have_directory_fields(self):
        for child, sector in ((0, 1), (NONE, NONE)):
            with self.subTest(child=child, sector=sector), self.assertRaises(ValueError):
                fad.parse_index(record() + file_record(child=child, sector=sector))

    def test_invalid_parent_and_child_indices(self):
        cases = [
            record() + file_record(parent=99),
            record() + file_record(parent=1),
            record(child=99) + file_record(),
            record(child=0) + file_record(),
        ]
        for index, data in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                fad.parse_index(data)

    def test_parent_cycle_is_rejected(self):
        data = record(b'A', parent=1, child=1) + record(b'B', parent=0, child=0)
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            fad.parse_index(data)

    def test_case_insensitive_duplicate_paths(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            fad.parse_index(record() + file_record(b'sample') + file_record(b'SAMPLE'))

    def test_windows_device_and_malformed_names(self):
        bad_names = [b'', b'.', b'..', b'../bad', b'A\\B', b'C:BAD', b'BAD?', b'BAD*',
                     b'NUL', b'con', b'COM1', b'lpt9', b'PRN.foo', b'END.', b'bad\x01', b'bad\x7f']
        for name in bad_names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                fad.component(name)

    def test_non_ascii_name_is_not_silently_replaced(self):
        with self.assertRaises(ValueError):
            fad.component(b'BAD\xff')

    def test_payload_boundary_exact_and_overrun(self):
        row = {'path': 'ROOT/sample.txt', 'sector': 1, 'size': 5}
        self.assertEqual(fad.bound_range(row, S, 2*S + 5), (2*S, 2*S + 5))
        for base, limit in ((S, 2*S + 4), (-1, 99999)):
            with self.subTest(base=base, limit=limit), self.assertRaises(ValueError):
                fad.bound_range(row, base, limit)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.iso = self.root / 'fixture.iso'
        self.extracted = self.root / 'indices'
        self.extracted.mkdir()
        self.output = self.root / 'report.json'
        self.outdir = self.root / 'assets'
        self.make_fixture()

    def tearDown(self):
        self.temp.cleanup()

    def make_fixture(self, sector=1, size=5):
        # Main stream is DISC + DISC1 + DISC2 + DISC3. Other indices contain
        # intentionally unresolved large sector references, which must never extract.
        indices = {'DISC.FAD': table(sector, size=size),
                   'DISC4.FAD': table(99999, b'other4'),
                   'DISCE.FAD': table(99999, b'othere')}
        data = bytearray(6*S)
        data[:S] = indices['DISC.FAD']
        data[S:S+5] = b'hello'
        data[4*S:5*S] = indices['DISC4.FAD']
        data[5*S:6*S] = indices['DISCE.FAD']
        self.iso.write_bytes(data)
        for name, payload in indices.items():
            (self.extracted / name).write_bytes(payload)
        self.manifest = {
            'source': {'path': str(self.iso), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
            'entries': [{'path': name, 'offset': i*S, 'size': S}
                        for i, name in enumerate(('DISC.FAD', 'DISC1.FAD', 'DISC2.FAD', 'DISC3.FAD', 'DISC4.FAD', 'DISCE.FAD'))],
        }

    def analyze(self, **overrides):
        options = {'iso': self.iso, 'iso_manifest': self.manifest, 'extracted': self.extracted,
                   'output': self.output, 'output_root': self.outdir, 'patterns': ['*']}
        options.update(overrides)
        return fad.analyze(**options)

    def test_only_main_archive_extracts_and_report_is_reusable(self):
        report = self.analyze()
        self.assertEqual((self.outdir / 'ROOT/sample.txt').read_bytes(), b'hello')
        self.assertEqual(len(list(self.outdir.rglob('*.txt'))), 1)
        self.assertEqual(report['archives'][0]['records'][1]['iso_offset'], S)
        self.assertEqual(report['archives'][0]['records'][1]['sha256'], hashlib.sha256(b'hello').hexdigest())
        for archive in report['archives'][1:]:
            self.assertIsNone(archive['payload_base'])
            self.assertNotIn('iso_offset', archive['records'][1])
            self.assertNotIn('extracted_path', archive['records'][1])
        self.assertEqual(json.loads(self.output.read_text(encoding='utf-8')), report)
        self.assertFalse(self.output.with_name('report.json.tmp').exists())
        self.assertEqual(self.analyze(), report)

    def test_payload_cannot_point_into_index(self):
        self.make_fixture(sector=0)
        with self.assertRaisesRegex(ValueError, 'inside index'):
            self.analyze()

    def test_payload_cannot_overrun_main_stream(self):
        self.make_fixture(sector=4)
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.analyze()

    def test_iso_same_size_content_change_is_rejected(self):
        with self.iso.open('r+b') as stream:
            stream.seek(S)
            stream.write(b'HELLO')
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.analyze()

    def test_truncated_iso_is_rejected(self):
        with self.iso.open('r+b') as stream:
            stream.truncate(6*S-1)
        with self.assertRaisesRegex(ValueError, 'size'):
            self.analyze()

    def test_extracted_index_must_match_source(self):
        (self.extracted / 'DISC.FAD').write_bytes(table(name=b'changed'))
        with self.assertRaisesRegex(ValueError, 'index differs'):
            self.analyze()

    def test_noncontiguous_stream_is_rejected(self):
        self.manifest['entries'][2]['offset'] += 1
        with self.assertRaisesRegex(ValueError, 'contiguous'):
            self.analyze()

    def test_manifest_cannot_admit_beyond_physical_iso(self):
        self.manifest['entries'][3]['size'] = 99*S
        with self.assertRaisesRegex(ValueError, 'outside ISO'):
            self.analyze(output_root=None, patterns=[])

    def test_negative_extent_size_rejected(self):
        self.manifest['entries'][3]['size'] = -1
        with self.assertRaisesRegex(ValueError, 'outside ISO'):
            self.analyze()

    def test_changed_existing_asset_is_preserved(self):
        self.outdir.joinpath('ROOT').mkdir(parents=True)
        target = self.outdir / 'ROOT/sample.txt'
        target.write_bytes(b'edited')
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            self.analyze()
        self.assertEqual(target.read_bytes(), b'edited')

    def test_report_cannot_overwrite_iso_or_index(self):
        for source in (self.iso, self.extracted / 'DISC.FAD', self.extracted / 'DISC4.FAD', self.extracted / 'DISCE.FAD'):
            original = source.read_bytes()
            with self.subTest(source=source.name), self.assertRaisesRegex(ValueError, 'aliases'):
                self.analyze(output=source)
            self.assertEqual(source.read_bytes(), original)

    def test_report_hardlink_to_iso_is_rejected(self):
        alias = self.root / 'source_alias.json'
        try:
            os.link(self.iso, alias)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow hardlinks: {error}')
        original = self.iso.read_bytes()
        with self.assertRaisesRegex(ValueError, 'aliases'):
            self.analyze(output=alias)
        self.assertEqual(self.iso.read_bytes(), original)

    def test_report_pending_temp_is_never_overwritten(self):
        pending = self.output.with_name('report.json.tmp')
        pending.write_text('previous unfinished operation', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            self.analyze()
        self.assertEqual(pending.read_text(encoding='utf-8'), 'previous unfinished operation')

    def test_output_path_cannot_escape_root(self):
        for path in ('../escaped.txt', 'A/../../escaped.txt', str(self.root / 'escaped.txt')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                fad.safe_output(self.outdir, path)

    def test_symlink_output_root_is_rejected(self):
        destination = self.root / 'destination'
        destination.mkdir()
        alias = self.root / 'alias'
        try:
            alias.symlink_to(destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow symlinks: {error}')
        with self.assertRaisesRegex(ValueError, 'link'):
            fad.safe_output(alias, 'ROOT/sample.txt')

    def test_symlink_nested_destination_is_rejected(self):
        destination = self.root / 'destination'
        destination.mkdir()
        self.outdir.mkdir()
        alias = self.outdir / 'ROOT'
        try:
            alias.symlink_to(destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow symlinks: {error}')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            fad.safe_output(self.outdir, 'ROOT/sample.txt')


if __name__ == '__main__':
    unittest.main()
