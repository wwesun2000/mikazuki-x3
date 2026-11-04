from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('iso9660', Path(__file__).resolve().parents[1] / 'tools' / 'iso9660.py')
iso9660 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(iso9660)
S = 2048


def u16(value):
    return struct.pack('<H', value) + struct.pack('>H', value)


def u32(value):
    return struct.pack('<I', value) + struct.pack('>I', value)


def record(name, extent, size, flags=0):
    length = 33 + len(name) + (len(name) % 2 == 0)
    data = bytearray(length)
    data[0] = length
    data[2:10] = u32(extent)
    data[10:18] = u32(size)
    data[25] = flags
    data[28:32] = u16(1)
    data[32] = len(name)
    data[33:33 + len(name)] = name
    return data


def image(name=b'HELLO.TXT;1', extent=21, size=5, flags=0, extra=None):
    data = bytearray(24 * S)
    pvd = bytearray(S)
    pvd[0:7] = b'\x01CD001\x01'
    pvd[8:40] = b'TEST'.ljust(32)
    pvd[40:72] = b'TEST_DISC'.ljust(32)
    pvd[80:88] = u32(24)
    pvd[120:124] = u16(1)
    pvd[124:128] = u16(1)
    pvd[128:132] = u16(S)
    pvd[156:190] = record(b'\x00', 20, S, flags=2)
    data[16*S:17*S] = pvd
    data[17*S:17*S+7] = b'\xffCD001\x01'
    directory = record(b'\x00', 20, S, 2) + record(b'\x01', 20, S, 2) + record(name, extent, size, flags)
    if extra is not None:
        directory += extra
    data[20*S:20*S+len(directory)] = directory
    data[21*S:21*S+5] = b'hello'
    return data


class IsoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'sample.iso'

    def tearDown(self):
        self.temp.cleanup()

    def write(self, data):
        self.path.write_bytes(data)
        return iso9660.Iso9660(self.path)

    def test_inventory_hash_and_extract(self):
        with self.write(image()) as iso:
            entries = iso.inventory()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]['offset'], 21*S)
            self.assertEqual(entries[0]['path'], 'HELLO.TXT')
            manifest = iso.manifest()
            self.assertEqual(manifest['file_count'], 1)
            self.assertEqual(len(manifest['source']['sha256']), 64)
            receipt = iso.extract('HELLO.TXT', self.root / 'out')
            self.assertEqual(Path(receipt['path']).read_bytes(), b'hello')
            with self.assertRaisesRegex(iso9660.IsoError, 'overwrite'):
                iso.extract('HELLO.TXT', self.root / 'out')

    def test_extent_out_of_image(self):
        with self.write(image(extent=24, size=1)) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'outside'):
                iso.inventory()

    def test_reject_multi_extent(self):
        with self.write(image(flags=0x80)) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'Multi-extent'):
                iso.inventory()

    def test_reject_record_path_traversal(self):
        for name in (b'../EVIL;1', b'A\\B;1', b'C:EVIL;1', b'CON;1', b'NUL.TXT;1',
                     b'COM1.TXT;1', b'LPT9;1', b'BAD?;1', b'BAD\x01;1', b'BAD\x7f;1',
                     b'TRAILING.;1', b'TRAILING ;1'):
            with self.subTest(name=name), self.write(image(name=name)) as iso:
                with self.assertRaises(iso9660.IsoError):
                    iso.inventory()

    def test_reject_caller_path_traversal(self):
        with self.write(image()) as iso:
            iso.inventory()
            for member in ('../HELLO.TXT', '/HELLO.TXT', 'A/../HELLO.TXT', 'A\\HELLO.TXT', 'C:HELLO.TXT'):
                with self.subTest(member=member), self.assertRaises(iso9660.IsoError):
                    iso.extract(member, self.root / 'out')

    def test_endian_disagreement(self):
        data = image()
        data[16*S+84] ^= 1
        with self.write(data) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'dual-endian'):
                iso.inventory()

    def test_truncated_image(self):
        with self.write(image()[:-1]) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'beyond image'):
                iso.inventory()

    def test_duplicate_normalized_names(self):
        with self.write(image(extra=record(b'HELLO.TXT;2', 21, 5))) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'Duplicate'):
                iso.inventory()

    def test_directory_cycle(self):
        with self.write(image(name=b'LOOP', extent=20, size=S, flags=2)) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'cycle'):
                iso.inventory()

    def test_record_crosses_sector(self):
        data = image()
        # A length at the last byte cannot fit into its current sector.
        data[20*S:21*S] = bytes(S)
        cursor = 20*S
        while cursor < 21*S - 40:
            rec = record(b'\x00', 20, S, 2)
            data[cursor:cursor+len(rec)] = rec
            cursor += len(rec)
        data[cursor] = 255
        with self.write(data) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, 'crosses'):
                iso.inventory()

    def test_non_2048_sector_rejected(self):
        data = image()
        data[16*S+128:16*S+132] = u16(4096)
        with self.write(data) as iso:
            with self.assertRaisesRegex(iso9660.IsoError, '2048'):
                iso.inventory()

    def test_read_bounds(self):
        with self.write(image()) as iso:
            for offset, size in ((-1, 1), (0, -1), (24*S, 1)):
                with self.subTest(offset=offset, size=size), self.assertRaises(iso9660.IsoError):
                    iso.read(offset, size)

    def run_cli(self, *args):
        with redirect_stdout(io.StringIO()):
            iso9660.main([str(self.path), *(str(arg) for arg in args)])

    def test_cli_manifest_cannot_overwrite_source_iso(self):
        original = bytes(image())
        self.path.write_bytes(original)
        with self.assertRaisesRegex(iso9660.IsoError, 'aliases'):
            self.run_cli('--manifest', self.path)
        self.assertEqual(self.path.read_bytes(), original)

    def test_cli_manifest_cannot_overwrite_extracted_member(self):
        output_root = self.root / 'out'
        with self.write(image()) as iso:
            iso.inventory()
            receipt = iso.extract('HELLO.TXT', output_root)
        target = Path(receipt['path'])
        with self.assertRaisesRegex(iso9660.IsoError, 'aliases'):
            self.run_cli('--manifest', target, '--output', output_root)
        self.assertEqual(target.read_bytes(), b'hello')

    def test_cli_manifest_cannot_occupy_future_extraction_target(self):
        self.path.write_bytes(image())
        output_root = self.root / 'out'
        target = output_root / 'HELLO.TXT'
        with self.assertRaisesRegex(iso9660.IsoError, 'aliases'):
            self.run_cli('--manifest', target, '--output', output_root, '--extract', 'HELLO.TXT')
        self.assertFalse(target.exists())

    def test_cli_writes_complete_manifest_and_extracts_without_touching_source(self):
        original = bytes(image())
        self.path.write_bytes(original)
        report = self.root / 'analysis' / 'report.json'
        report.parent.mkdir()
        report.write_text('old report', encoding='utf-8')
        output_root = self.root / 'out'
        self.run_cli('--manifest', report, '--output', output_root, '--extract', 'HELLO.TXT')
        saved = json.loads(report.read_text(encoding='utf-8'))
        self.assertEqual(saved['file_count'], 1)
        self.assertEqual(saved['source']['size'], len(original))
        self.assertEqual((output_root / 'HELLO.TXT').read_bytes(), b'hello')
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(report.parent.iterdir()), [report])

    def test_manifest_serialization_failure_preserves_old_report(self):
        report = self.root / 'report.json'
        report.write_text('previous valid report', encoding='utf-8')
        with self.assertRaises(TypeError):
            iso9660.write_manifest(report, {'not_serializable': object()}, [self.path])
        self.assertEqual(report.read_text(encoding='utf-8'), 'previous valid report')
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_manifest_flush_failure_preserves_old_report(self):
        report = self.root / 'report.json'
        report.write_text('previous valid report', encoding='utf-8')
        with patch.object(iso9660.os, 'fsync', side_effect=OSError('injected disk failure')):
            with self.assertRaisesRegex(OSError, 'disk failure'):
                iso9660.write_manifest(report, {'ok': True}, [self.path])
        self.assertEqual(report.read_text(encoding='utf-8'), 'previous valid report')
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_manifest_hardlink_to_source_rejected(self):
        self.path.write_bytes(image())
        alias = self.root / 'source_alias.json'
        try:
            os.link(self.path, alias)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow hardlinks: {error}')
        original = self.path.read_bytes()
        with self.assertRaisesRegex(iso9660.IsoError, 'aliases'):
            self.run_cli('--manifest', alias)
        self.assertEqual(self.path.read_bytes(), original)

    def test_manifest_symlink_to_source_rejected(self):
        self.path.write_bytes(image())
        alias = self.root / 'source_alias.json'
        try:
            alias.symlink_to(self.path)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow symlinks: {error}')
        original = self.path.read_bytes()
        with self.assertRaisesRegex(iso9660.IsoError, 'symlink'):
            self.run_cli('--manifest', alias)
        self.assertEqual(self.path.read_bytes(), original)

    def test_extraction_root_symlink_rejected(self):
        destination = self.root / 'destination'
        destination.mkdir()
        alias = self.root / 'alias'
        try:
            alias.symlink_to(destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(f'Filesystem does not allow symlinks: {error}')
        with self.write(image()) as iso:
            iso.inventory()
            with self.assertRaisesRegex(iso9660.IsoError, 'symlink'):
                iso.extract('HELLO.TXT', alias)
        self.assertEqual(list(destination.iterdir()), [])

    @unittest.skipUnless(os.name == 'nt' and hasattr(Path, 'is_junction'), 'Windows junction API required')
    def test_junction_manifest_parent_and_extraction_root_rejected(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if shell is None:
            self.skipTest('No PowerShell available for the junction fixture')
        destination = self.root / 'destination'
        destination.mkdir()
        alias = self.root / 'alias'
        script = self.root / 'create_junction.ps1'
        script.write_text('param([string]$LinkPath, [string]$TargetPath)\n'
                          'New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath -ErrorAction Stop | Out-Null\n',
                          encoding='utf-8')
        try:
            result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-File', str(script), str(alias), str(destination)],
                                    capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.skipTest(f'Junction fixture unavailable: {error}')
        if result.returncode != 0:
            self.skipTest('Sandbox/filesystem denied creation of the junction fixture')
        self.assertTrue(alias.is_junction())
        with self.write(image()) as iso:
            iso.inventory()
            with self.assertRaisesRegex(iso9660.IsoError, 'junction'):
                iso.extract('HELLO.TXT', alias)
        with self.assertRaisesRegex(iso9660.IsoError, 'junction'):
            self.run_cli('--manifest', alias / 'report.json')
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
