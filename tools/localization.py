"""Offline source-integrity and review gates; no game text is inferred here."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

LOCALES = ("zh-Hans", "en")
STATES = ("untranslated", "draft", "reviewed")
SOURCE_FIELDS = ("entry_id", "original", "source_hash", "context", "location", "tokens")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def text_hash(value: str) -> str:
    """Exact UTF-8 text hash: no normalization, trimming, or newline conversion."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def json_hash(value) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json(path: Path):
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON key: {key}")
            obj[key] = value
        return obj
    def reject_constant(value):
        raise ValueError(f"non-JSON numeric constant: {value}")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def _timestamp(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def _nonempty(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha(value) -> bool:
    return isinstance(value, str) and HEX256.fullmatch(value) is not None


def _index(document, label, errors):
    if not isinstance(document, dict):
        errors.append(f"{label}: must be a JSON object")
        return {}
    if type(document.get("schema_version")) is not int or document.get("schema_version") != 1:
        errors.append(f"{label}: schema_version must be 1")
    if not _sha(document.get("artifact_sha256")):
        errors.append(f"{label}: artifact_sha256 must be a lowercase SHA-256")
    entries = document.get("entries")
    if not isinstance(entries, list):
        errors.append(f"{label}: entries must be an array")
        return {}
    if type(document.get("entry_count")) is not int or document["entry_count"] != len(entries):
        errors.append(f"{label}: entry_count does not match entries")
    indexed = {}
    for index, entry in enumerate(entries):
        prefix = f"{label}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: entry must be an object")
            continue
        entry_id = entry.get("entry_id")
        if not _nonempty(entry_id):
            errors.append(f"{prefix}: entry_id is required")
            continue
        prefix = f"{label}/{entry_id}"
        if entry_id in indexed:
            errors.append(f"{prefix}: duplicate entry_id")
        indexed[entry_id] = entry
        original = entry.get("original")
        if not isinstance(original, str):
            errors.append(f"{prefix}: original must be a string")
        elif entry.get("source_hash") != text_hash(original):
            errors.append(f"{prefix}: source_hash differs from exact original UTF-8")
        if not isinstance(entry.get("context"), str):
            errors.append(f"{prefix}: context must be a string")
        location = entry.get("location")
        if (not isinstance(location, dict) or not _nonempty(location.get("path"))
                or type(location.get("offset")) is not int or location["offset"] < 0
                or type(location.get("length")) is not int or location["length"] < 0):
            errors.append(f"{prefix}: location needs path and nonnegative byte offset/length")
        tokens = entry.get("tokens")
        if (not isinstance(tokens, list) or any(not _nonempty(t) for t in tokens)):
            errors.append(f"{prefix}: tokens must be an array of nonempty literal strings")
        elif len(set(tokens)) != len(tokens):
            errors.append(f"{prefix}: tokens must list each literal once")
        elif isinstance(original, str):
            for token in tokens:
                if token not in original:
                    errors.append(f"{prefix}: declared token {token!r} absent from source")
    return indexed


def source_digest(document) -> str:
    """A retained baseline digest; order-independent, exact source metadata."""
    return json_hash({
        "artifact_sha256": document["artifact_sha256"],
        "coverage": document.get("coverage"),
        "entries": [{field: e[field] for field in SOURCE_FIELDS}
                    for e in sorted(document["entries"], key=lambda row: row["entry_id"])],
    })


def locale_digest(catalog, locale: str) -> str:
    """Bind holistic approval to the complete source and one target locale."""
    return json_hash({
        "baseline_digest": catalog["baseline_digest"],
        "source_digest": source_digest(catalog), "locale": locale,
        "entries": [{"entry_id": e["entry_id"], "target": e["targets"][locale]}
                    for e in sorted(catalog["entries"], key=lambda row: row["entry_id"])],
    })


def validate(catalog, baseline, *, release=False, locales=LOCALES):
    errors, warnings = [], []
    baseline_index = _index(baseline, "baseline", errors)
    catalog_index = _index(catalog, "catalog", errors)
    if not isinstance(catalog, dict) or not isinstance(baseline, dict):
        return {"ok": False, "errors": errors, "warnings": warnings, "counts": {}}
    if baseline.get("kind") != "source-baseline":
        errors.append("baseline: kind must be source-baseline")
    coverage = baseline.get("coverage")
    if (not isinstance(coverage, dict) or coverage.get("status") not in ("partial", "complete")
            or not isinstance(coverage.get("evidence"), list)
            or any(not _nonempty(item) for item in coverage.get("evidence", []))):
        errors.append("baseline: coverage requires partial/complete status and evidence list")
    elif release and (coverage["status"] != "complete" or not coverage["evidence"]):
        errors.append("baseline: release requires complete extraction coverage with evidence")
    if catalog.get("kind") != "localization-catalog":
        errors.append("catalog: kind must be localization-catalog")
    if catalog.get("artifact_sha256") != baseline.get("artifact_sha256"):
        errors.append("catalog: artifact SHA-256 differs from baseline")
    missing = sorted(set(baseline_index) - set(catalog_index))
    extra = sorted(set(catalog_index) - set(baseline_index))
    if missing:
        errors.append(f"catalog: missing source IDs: {', '.join(missing)}")
    if extra:
        errors.append(f"catalog: unknown source IDs: {', '.join(extra)}")
    for entry_id in sorted(set(catalog_index) & set(baseline_index)):
        for field in SOURCE_FIELDS:
            if catalog_index[entry_id].get(field) != baseline_index[entry_id].get(field):
                errors.append(f"{entry_id}: source field {field} differs from baseline")
    counts = {locale: Counter({state: 0 for state in STATES}) for locale in LOCALES}
    for entry_id, entry in catalog_index.items():
        targets = entry.get("targets")
        if not isinstance(targets, dict) or set(targets) != set(LOCALES):
            errors.append(f"{entry_id}: targets must contain exactly zh-Hans and en")
            continue
        for locale, target in targets.items():
            prefix = f"{entry_id}/{locale}"
            if not isinstance(target, dict):
                errors.append(f"{prefix}: target must be an object")
                continue
            state, text = target.get("status"), target.get("text")
            if state not in STATES:
                errors.append(f"{prefix}: invalid translation status")
            else:
                counts[locale][state] += 1
            if not isinstance(text, str):
                errors.append(f"{prefix}: text must be a string")
                continue
            if state == "untranslated" and text:
                errors.append(f"{prefix}: untranslated text must be empty; use draft")
            if state in ("draft", "reviewed") and not text.strip():
                errors.append(f"{prefix}: translation is empty")
            if state in ("draft", "reviewed"):
                original, tokens = entry.get("original"), entry.get("tokens")
                if isinstance(original, str) and isinstance(tokens, list):
                    for token in tokens:
                        if isinstance(token, str) and token and text.count(token) != original.count(token):
                            errors.append(f"{prefix}: token multiplicity changed: {token!r}")
            if state == "reviewed":
                if target.get("reviewed_source_hash") != entry.get("source_hash"):
                    errors.append(f"{prefix}: review is stale for source")
                if target.get("reviewed_text_hash") != text_hash(text):
                    errors.append(f"{prefix}: review is stale for translation")
                if not _nonempty(target.get("reviewed_by")) or not _timestamp(target.get("reviewed_at")):
                    errors.append(f"{prefix}: reviewer and timezone-aware reviewed_at required")
            if release and locale in locales and state != "reviewed":
                errors.append(f"{prefix}: release requires reviewed translation")
    if not baseline_index:
        (errors if release else warnings).append("baseline has no extracted source entries")
    # Do not compute fingerprints over malformed structures.
    digests = {}
    if not errors:
        digest = source_digest(baseline)
        if baseline.get("source_digest") != digest:
            errors.append("baseline: source_digest is missing or inconsistent")
        if catalog.get("baseline_digest") != digest:
            errors.append("catalog: baseline_digest differs from verified baseline")
        if not errors:
            digests = {locale: locale_digest(catalog, locale) for locale in LOCALES}
    holistic = catalog.get("holistic_reviews")
    if not isinstance(holistic, dict):
        errors.append("catalog: holistic_reviews must be an object")
        holistic = {}
    for locale in LOCALES:
        approval = holistic.get(locale)
        if approval is None:
            if release and locale in locales:
                errors.append(f"{locale}: full-project holistic review required before release")
            continue
        if not isinstance(approval, dict):
            errors.append(f"{locale}: holistic review must be an object")
            continue
        if (approval.get("status") != "approved" or approval.get("scope") != "full-project"
                or not _nonempty(approval.get("reviewed_by"))
                or not _timestamp(approval.get("reviewed_at"))):
            errors.append(f"{locale}: holistic approval needs full-project scope, reviewer, timestamp")
        if locale in digests and approval.get("catalog_digest") != digests[locale]:
            errors.append(f"{locale}: holistic approval is stale; complete review again")
        if counts[locale]["untranslated"] or counts[locale]["draft"]:
            errors.append(f"{locale}: holistic approval cannot cover unfinished line reviews")
        if _timestamp(approval.get("reviewed_at")):
            holistic_time = datetime.fromisoformat(approval["reviewed_at"].replace("Z", "+00:00"))
            for entry in catalog_index.values():
                targets = entry.get("targets")
                target = targets.get(locale) if isinstance(targets, dict) else None
                line_time = target.get("reviewed_at") if isinstance(target, dict) else None
                if _timestamp(line_time) and datetime.fromisoformat(line_time.replace("Z", "+00:00")) > holistic_time:
                    errors.append(f"{locale}: holistic review must follow every line review")
                    break
    return {"ok": not errors, "mode": "release" if release else "validate",
            "errors": errors, "warnings": warnings,
            "counts": {locale: dict(counts[locale]) for locale in LOCALES},
            "source_entries": len(baseline_index), "catalog_entries": len(catalog_index),
            "locale_digests": digests}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "release-check", "fingerprint"))
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--locale", choices=LOCALES, action="append",
                        help="release locales; default both. Source completeness always checked.")
    args = parser.parse_args(argv)
    try:
        catalog, baseline = load_json(args.catalog), load_json(args.baseline)
        result = validate(catalog, baseline, release=args.command == "release-check",
                          locales=tuple(args.locale or LOCALES))
        # Fingerprinting never grants approval or changes a file.
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0 if result["ok"] else 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
