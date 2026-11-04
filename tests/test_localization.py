"""Synthetic strings exercise gates; they are not text extracted from the game."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("localization", Path(__file__).parents[1] / "tools" / "localization.py")
loc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loc)


def fixture():
    entries = []
    for index, original in enumerate(("テスト{X}です{X}", "検証用")):
        entries.append({"entry_id": f"synthetic:{index}", "original": original,
                        "source_hash": loc.text_hash(original), "context": "test-only",
                        "location": {"path": "synthetic.bin", "offset": index * 100, "length": 80},
                        "tokens": ["{X}"] if index == 0 else []})
    baseline = {"schema_version": 1, "kind": "source-baseline", "artifact_sha256": "a" * 64,
                "entry_count": len(entries), "entries": entries,
                "coverage": {"status": "complete", "evidence": ["synthetic-test-only"]}}
    baseline["source_digest"] = loc.source_digest(baseline)
    catalog = copy.deepcopy(baseline)
    catalog.pop("source_digest")
    catalog.pop("coverage")
    catalog.update(kind="localization-catalog", baseline_digest=baseline["source_digest"], holistic_reviews={})
    for entry in catalog["entries"]:
        text = "Test{X}{X}" if entry["tokens"] else "Test"
        entry["targets"] = {locale: {"text": text, "status": "reviewed", "reviewed_by": "test-reviewer",
                                    "reviewed_at": "2026-10-29T15:00:00-05:00",
                                    "reviewed_source_hash": entry["source_hash"],
                                    "reviewed_text_hash": loc.text_hash(text)} for locale in loc.LOCALES}
    for locale in loc.LOCALES:
        catalog["holistic_reviews"][locale] = {
            "status": "approved", "scope": "full-project", "reviewed_by": "test-editor",
            "reviewed_at": "2026-10-29T16:00:00-05:00", "catalog_digest": loc.locale_digest(catalog, locale)}
    return catalog, baseline


class LocalizationGateTests(unittest.TestCase):
    def assert_rejected(self, catalog, baseline, fragment):
        result = loc.validate(catalog, baseline, release=True)
        self.assertFalse(result["ok"], result)
        self.assertTrue(any(fragment in error for error in result["errors"]), result)

    def test_complete_review_passes(self):
        self.assertTrue(loc.validate(*fixture(), release=True)["ok"])

    def test_missing_translation(self):
        catalog, baseline = fixture()
        catalog["entries"][0]["targets"]["zh-Hans"] = {"text": "", "status": "untranslated"}
        self.assert_rejected(catalog, baseline, "requires reviewed")

    def test_source_edit_with_recomputed_hash_still_rejected(self):
        catalog, baseline = fixture()
        entry = catalog["entries"][0]
        entry["original"] += "変更"
        entry["source_hash"] = loc.text_hash(entry["original"])
        self.assert_rejected(catalog, baseline, "differs from baseline")

    def test_missing_entry_even_with_count_adjusted(self):
        catalog, baseline = fixture()
        catalog["entries"].pop()
        catalog["entry_count"] -= 1
        self.assert_rejected(catalog, baseline, "missing source IDs")

    def test_duplicate_id(self):
        catalog, baseline = fixture()
        catalog["entries"].append(copy.deepcopy(catalog["entries"][0]))
        catalog["entry_count"] += 1
        self.assert_rejected(catalog, baseline, "duplicate entry_id")

    def test_token_count_not_just_presence(self):
        catalog, baseline = fixture()
        target = catalog["entries"][0]["targets"]["zh-Hans"]
        target["text"] = "Test{X}"
        target["reviewed_text_hash"] = loc.text_hash(target["text"])
        self.assert_rejected(catalog, baseline, "token multiplicity")

    def test_draft_cannot_release(self):
        catalog, baseline = fixture()
        catalog["entries"][0]["targets"]["zh-Hans"]["status"] = "draft"
        self.assert_rejected(catalog, baseline, "requires reviewed")

    def test_missing_whole_project_review(self):
        catalog, baseline = fixture()
        catalog["holistic_reviews"].pop("zh-Hans")
        self.assert_rejected(catalog, baseline, "holistic review required")

    def test_whole_review_becomes_stale_after_valid_line_rereview(self):
        catalog, baseline = fixture()
        target = catalog["entries"][1]["targets"]["zh-Hans"]
        target["text"] = "Updated translation"
        target["reviewed_text_hash"] = loc.text_hash(target["text"])
        self.assert_rejected(catalog, baseline, "holistic approval is stale")

    def test_edited_translation_invalidates_line_review(self):
        catalog, baseline = fixture()
        catalog["entries"][1]["targets"]["zh-Hans"]["text"] += " change"
        self.assert_rejected(catalog, baseline, "review is stale for translation")

    def test_partial_source_extraction_cannot_release(self):
        catalog, baseline = fixture()
        baseline["coverage"]["status"] = "partial"
        self.assert_rejected(catalog, baseline, "complete extraction coverage")

    def test_changed_coverage_evidence_invalidates_holistic_review(self):
        catalog, baseline = fixture()
        baseline["coverage"]["evidence"].append("additional-source-audit")
        baseline["source_digest"] = loc.source_digest(baseline)
        catalog["baseline_digest"] = baseline["source_digest"]
        self.assert_rejected(catalog, baseline, "holistic approval is stale")

    def test_holistic_review_must_follow_line_review(self):
        catalog, baseline = fixture()
        catalog["holistic_reviews"]["zh-Hans"]["reviewed_at"] = "2026-10-28T16:00:00-05:00"
        self.assert_rejected(catalog, baseline, "must follow every line review")

    def test_coverage_claim_requires_evidence(self):
        catalog, baseline = fixture()
        baseline["coverage"]["evidence"] = []
        self.assert_rejected(catalog, baseline, "complete extraction coverage")

    def test_draft_validation_works_without_pretending_release_ready(self):
        catalog, baseline = fixture()
        catalog["holistic_reviews"] = {}
        for entry in catalog["entries"]:
            entry["targets"] = {locale: {"text": "", "status": "untranslated"} for locale in loc.LOCALES}
        result = loc.validate(catalog, baseline)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["counts"]["zh-Hans"]["untranslated"], 2)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text('{"entries": [], "entries": [1]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                loc.load_json(path)

    def test_release_locale_selection_still_checks_all_source(self):
        catalog, baseline = fixture()
        catalog["holistic_reviews"].pop("en")
        for entry in catalog["entries"]:
            entry["targets"]["en"] = {"text": "", "status": "untranslated"}
        self.assertTrue(loc.validate(catalog, baseline, release=True, locales=("zh-Hans",))["ok"])

    def test_malformed_source_is_reported_without_traceback(self):
        catalog, baseline = fixture()
        catalog["entries"][0]["location"] = None
        catalog["entries"][0]["tokens"] = [None]
        self.assertFalse(loc.validate(catalog, baseline)["ok"])


if __name__ == "__main__":
    unittest.main()
