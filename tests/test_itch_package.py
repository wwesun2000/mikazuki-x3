"""Packaging boundary tests; synthetic PE headers are not playable release files."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_itch', ROOT/'tools/package_itch.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

class PackageTests(unittest.TestCase):
    def test_allowlist_and_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            binary = bytearray(256)
            binary[:2] = b'MZ'
            struct.pack_into('<I', binary, 60, 128)
            binary[128:132] = b'PE\0\0'
            struct.pack_into('<H', binary, 132, 0x8664)
            exe = root/'test.exe'
            exe.write_bytes(binary)
            legal = root/'legal'
            legal.mkdir()
            for name in ('FFmpeg-LICENSE.txt', 'FFmpeg-SOURCE.txt', 'THIRD-PARTY-NOTICES.txt'):
                (legal/name).write_text('TEST FIXTURE ONLY — NOT A RELEASE LICENSE. '*3, encoding='utf-8')
            for name in ('game.iso', 'bios.bin', 'disc.img', 'video.pss', 'secret.env'):
                (legal/name).write_text('DO NOT SHIP')
            out = root/'dist'
            package.package(exe, exe, exe, legal, out)
            with zipfile.ZipFile(out.with_suffix('.zip')) as z:
                names = z.namelist()
                self.assertEqual(len(names), 9)
                self.assertFalse(any('bios' in n or n.endswith(('.iso', '.bin', '.img', '.pss', '.env')) for n in names))
                manifest = tomllib.loads(z.read('.itch.toml').decode())
                self.assertEqual(manifest['actions'][0]['path'], 'MikazukiX3.exe')
                self.assertEqual(manifest['actions'][0]['platform'], 'windows')
            with self.assertRaises(FileExistsError):
                package.package(exe, exe, exe, legal, out)
            struct.pack_into('<H', binary, 132, 0x14c)
            with self.assertRaises(ValueError):
                package.pe64(binary)

    def test_missing_legal_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(FileNotFoundError):
                package.package(root/'missing', root/'missing', root/'missing', root, root/'dist')
            self.assertFalse((root/'dist').exists())

if __name__ == '__main__':
    unittest.main()
