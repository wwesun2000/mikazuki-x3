"""Test local media provenance; fixture bytes are not actual game captures."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("capture_catalog", Path(__file__).parents[1] / "tools" / "capture_catalog.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class CaptureCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "local").mkdir()
        self.media = self.root / "local" / "fixture.bin"
        self.media.write_bytes(b"synthetic media bytes")
        self.metadata = dict(kind="source-video", status="extracted", source_sha256="a" * 64,
                             source_asset_id="synthetic:movie-01", recorded_at="2026-10-30T10:00:00-05:00",
                             language="ja", render_settings={}, stage="reverse-engineering",
                             spoiler="major", description="Synthetic fixture", notes="test-only")

    def register(self, path=None, **changes):
        return capture.register(self.root, path or self.media, **(self.metadata | changes))

    def rows(self):
        return [json.loads(line) for line in (self.root / "captures" / "catalog.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_first_registration_leaves_original_unchanged(self):
        result = self.register()
        self.assertEqual(result["result"], "asset_registered")
        self.assertEqual(self.media.read_bytes(), b"synthetic media bytes")
        row = self.rows()[0]
        self.assertEqual(row["provenance"]["status"], "extracted")
        self.assertEqual(row["provenance"]["path"], "local/fixture.bin")
        self.assertNotIn("runtime", row["provenance"]["kind"])
        self.assertFalse((self.root / "captures" / ".catalog.lock").exists())

    def test_exact_duplicate_is_idempotent(self):
        self.register()
        self.assertEqual(self.register()["result"], "unchanged")
        self.assertEqual(len(self.rows()), 1)

    def test_equal_bytes_keep_second_source_without_new_asset(self):
        first = self.register()
        copy_path = self.root / "local" / "copy.bin"
        copy_path.write_bytes(self.media.read_bytes())
        second = self.register(copy_path, source_asset_id="synthetic:other-origin")
        self.assertEqual(first["asset_id"], second["asset_id"])
        self.assertEqual(second["result"], "provenance_added")
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.rows()[1]["provenance"]["source_asset_id"], "synthetic:other-origin")

    def test_updated_render_notes_add_provenance(self):
        self.register()
        self.register(notes="Additional audited metadata")
        self.assertEqual(len(self.rows()), 2)

    def test_extracted_source_cannot_claim_captured(self):
        with self.assertRaisesRegex(ValueError, "must be extracted"):
            self.register(status="captured")

    def test_runtime_requires_capture_status(self):
        with self.assertRaisesRegex(ValueError, "actual running game"):
            self.register(kind="runtime-video")

    def test_runtime_requires_renderer_metadata(self):
        with self.assertRaisesRegex(ValueError, "render_settings"):
            self.register(kind="runtime-video", status="captured")

    def test_actual_runtime_record_is_distinct_metadata(self):
        self.register(kind="runtime-screenshot", status="captured",
                      render_settings={"renderer": "synthetic-test-renderer", "fullscreen": False})
        self.assertEqual(self.rows()[0]["provenance"]["status"], "captured")

    def test_identical_bytes_cannot_be_relabeled_runtime(self):
        self.register()
        with self.assertRaisesRegex(ValueError, "different extracted/captured origin"):
            self.register(kind="runtime-video", status="captured", render_settings={"renderer": "test"})
        self.assertEqual(len(self.rows()), 1)

    def test_outside_project_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            path = Path(outside) / "outside.bin"
            path.write_bytes(b"outside")
            with self.assertRaisesRegex(ValueError, "inside the project"):
                self.register(path)

    def test_parent_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError, "parent traversal"):
            self.register("local/../local/fixture.bin")

    def test_directory_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.register(self.root / "local")

    def test_symlink_source_rejected(self):
        link = self.root / "local" / "link.bin"
        try:
            link.symlink_to(self.media)
        except OSError as exc:
            self.skipTest(f"platform does not allow symlink creation: {exc}")
        with self.assertRaisesRegex(ValueError, "symlink/reparse"):
            self.register(link)

    def test_symlink_output_directory_rejected(self):
        directory = self.root / "real-output"
        directory.mkdir()
        try:
            (self.root / "captures").symlink_to(directory, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"platform does not allow symlink creation: {exc}")
        with self.assertRaisesRegex(ValueError, "symlink/reparse"):
            self.register()

    def test_windows_reparse_attribute_detected_without_symlink_privilege(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400)):
            self.assertTrue(capture._has_link(self.media))

    def test_detected_reparse_path_is_rejected(self):
        original = capture._has_link
        with patch.object(capture, "_has_link", side_effect=lambda path: path == self.media or original(path)):
            with self.assertRaisesRegex(ValueError, "symlink/reparse"):
                self.register()

    def test_timezone_required(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.register(recorded_at="2026-10-30T10:00:00")

    def test_invalid_source_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.register(source_sha256="not-a-hash")

    def test_lock_preserves_existing_lock(self):
        directory = self.root / "captures"
        directory.mkdir()
        lock = directory / ".catalog.lock"
        lock.write_text("existing-owner", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "locked"):
            self.register()
        self.assertEqual(lock.read_text(encoding="utf-8"), "existing-owner")

    def test_corrupt_catalog_is_not_overwritten(self):
        directory = self.root / "captures"
        directory.mkdir()
        path = directory / "catalog.jsonl"
        path.write_text("broken-json", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.register()
        self.assertEqual(path.read_text(encoding="utf-8"), "broken-json")
        self.assertFalse((directory / ".catalog.lock").exists())

    def test_registering_catalog_itself_is_rejected(self):
        self.register()
        with self.assertRaisesRegex(ValueError, "cannot be registered"):
            self.register(self.root / "captures" / "catalog.jsonl", kind="debug-log")

    def test_catalog_trailing_newline_required_before_append(self):
        self.register()
        path = self.root / "captures" / "catalog.jsonl"
        path.write_text(path.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8")
        original = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "interrupted write"):
            self.register(notes="would append")
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
