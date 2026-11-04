"""Register local production media without uploading or inventing runtime evidence."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KINDS = ("source-video", "source-audio", "decoded-image", "runtime-video",
         "runtime-screenshot", "debug-log")
STATUSES = ("extracted", "captured")
SPOILERS = ("none", "minor", "major", "ending")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
REPARSE_POINT = 0x400  # Windows symlink/junction/cloud and other reparse objects.


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _reject_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_loads(value):
    return json.loads(value, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def _timestamp(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO 8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO 8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} requires timezone")
    return parsed.isoformat()


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _has_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def safe_path(root: Path, supplied, *, must_exist=True, file_required=True) -> Path:
    """Reject outside paths and every symlink/junction under the project root."""
    root = root.resolve(strict=True)
    raw = Path(supplied)
    if ".." in raw.parts:
        raise ValueError("parent traversal is not allowed")
    candidate = raw if raw.is_absolute() else root / raw
    # abspath removes harmless dot components, without following links.
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("path must remain inside the project") from exc
    if not relative.parts:
        raise ValueError("path must name a project child")
    current = root
    for component in relative.parts:
        if os.name == "nt" and ":" in component:
            raise ValueError("alternate data streams are not allowed")
        current = current / component
        if current.exists() or current.is_symlink():
            if _has_link(current):
                raise ValueError(f"symlink/reparse point is not allowed: {current.name}")
    if must_exist and not candidate.exists():
        raise ValueError("source path does not exist")
    if candidate.exists():
        # Recheck the resolved containment as well as lexical containment.
        try:
            candidate.resolve(strict=True).relative_to(root)
        except ValueError as exc:
            raise ValueError("resolved path escapes the project") from exc
        if file_required and not candidate.is_file():
            raise ValueError("source must be a regular file")
    return candidate


def _hash_file(path):
    before = path.stat()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("media changed during hashing; register after capture finishes")
    if size != after.st_size:
        raise ValueError("media size changed during hashing")
    return digest.hexdigest(), size


@contextmanager
def _catalog_lock(root, catalog_dir):
    lock = safe_path(root, catalog_dir / ".catalog.lock", must_exist=False)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("catalog is locked; another registration may be running") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.close(descriptor)
        descriptor = None
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        lock.unlink()


def _read_catalog(path):
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                raise ValueError(f"catalog line {line_number} lacks a final newline; possible interrupted write")
            if not line.strip():
                raise ValueError(f"catalog line {line_number} is empty")
            item = _json_loads(line)
            if (not isinstance(item, dict) or item.get("schema_version") != 1
                    or item.get("event") not in ("asset_registered", "provenance_added")
                    or not isinstance(item.get("provenance"), dict)
                    or not isinstance(item.get("sha256"), str)
                    or not HEX256.fullmatch(item["sha256"])
                    or item.get("asset_id") != "sha256:" + item["sha256"]
                    or type(item.get("size_bytes")) is not int or item["size_bytes"] < 0):
                raise ValueError(f"invalid catalog record at line {line_number}")
            records.append(item)
    return records


def register(root: Path, media_path, *, kind, status, source_sha256, source_asset_id,
             recorded_at, language, render_settings, stage, spoiler, description, notes=""):
    root = root.resolve(strict=True)
    media = safe_path(root, media_path)
    if kind not in KINDS or status not in STATUSES or spoiler not in SPOILERS:
        raise ValueError("invalid kind, status, or spoiler level")
    if kind in ("source-video", "source-audio", "decoded-image") and status != "extracted":
        raise ValueError("source or decoded media must be extracted, never runtime-captured")
    if kind in ("runtime-video", "runtime-screenshot") and status != "captured":
        raise ValueError("runtime media must be captured from an actual running game")
    if not isinstance(source_sha256, str) or not HEX256.fullmatch(source_sha256):
        raise ValueError("source_sha256 must be a lowercase SHA-256 of the source artifact")
    if not isinstance(render_settings, dict):
        raise ValueError("render_settings must be a JSON object")
    if kind in ("runtime-video", "runtime-screenshot") and not render_settings:
        raise ValueError("runtime media requires actual render_settings")
    if not isinstance(notes, str):
        raise ValueError("notes must be a string")
    # Validate JSON before writing or creating the catalog directory.
    _canonical(render_settings)
    provenance = {
        "path": media.relative_to(root).as_posix(), "kind": kind, "status": status,
        "source_sha256": source_sha256, "source_asset_id": _text(source_asset_id, "source_asset_id"),
        "recorded_at": _timestamp(recorded_at, "recorded_at"), "language": _text(language, "language"),
        "render_settings": render_settings, "stage": _text(stage, "stage"), "spoiler": spoiler,
        "description": _text(description, "description"), "notes": notes,
    }
    digest, size = _hash_file(media)
    # Ensure the path is still safe after hashing.
    safe_path(root, media)
    catalog_dir = safe_path(root, "captures", must_exist=False, file_required=False)
    catalog_dir.mkdir(exist_ok=True)
    catalog = safe_path(root, catalog_dir / "catalog.jsonl", must_exist=False)
    if media == catalog or media == catalog_dir / ".catalog.lock":
        raise ValueError("catalog and lock files cannot be registered as media")
    asset_id = "sha256:" + digest
    with _catalog_lock(root, catalog_dir):
        safe_path(root, catalog, must_exist=False)
        records = _read_catalog(catalog)
        same_asset = [record for record in records if record["sha256"] == digest]
        if any(record["size_bytes"] != size for record in same_asset):
            raise ValueError("existing catalog has contradictory content identity")
        if any(record["provenance"] == provenance for record in same_asset):
            return {"ok": True, "result": "unchanged", "asset_id": asset_id,
                    "catalog": catalog.relative_to(root).as_posix()}
        # Identical bytes cannot be relabeled as runtime evidence after extraction.
        if any(record["provenance"].get("status") != status for record in same_asset):
            raise ValueError("same bytes already have a different extracted/captured origin; do not relabel evidence")
        record = {"schema_version": 1,
                  "event": "provenance_added" if same_asset else "asset_registered",
                  "asset_id": asset_id, "sha256": digest, "size_bytes": size,
                  "registered_at": datetime.now(timezone.utc).isoformat(), "provenance": provenance}
        with catalog.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return {"ok": True, "result": record["event"], "asset_id": asset_id,
            "catalog": catalog.relative_to(root).as_posix(), "record": record}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("register")
    command.add_argument("media_path", type=Path)
    command.add_argument("--kind", choices=KINDS, required=True)
    command.add_argument("--status", choices=STATUSES, required=True)
    command.add_argument("--source-sha256", required=True)
    command.add_argument("--source-asset-id", required=True)
    command.add_argument("--at", dest="recorded_at", required=True,
                         help="actual extraction/capture time, ISO 8601 with timezone")
    command.add_argument("--language", required=True)
    command.add_argument("--render-settings", default="{}", help="JSON object; required nonempty for runtime media")
    command.add_argument("--stage", required=True)
    command.add_argument("--spoiler", choices=SPOILERS, required=True)
    command.add_argument("--description", required=True)
    command.add_argument("--notes", default="")
    args = vars(parser.parse_args(argv))
    args.pop("command")
    try:
        args["render_settings"] = _json_loads(args["render_settings"])
        result = register(PROJECT_ROOT, **args)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
