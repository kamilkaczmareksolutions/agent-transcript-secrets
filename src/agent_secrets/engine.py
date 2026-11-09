from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agent_secrets.detectors import iter_line_spans, redact_text
from agent_secrets.discover import classify

MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Hit:
    path: Path
    line: int
    kind: str
    preview: str
    source: str
    experimental: bool


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
    except OSError:
        return None, "unreadable"
    if size > MAX_FILE_BYTES:
        return None, "too-large"
    try:
        data = path.read_bytes()
    except OSError:
        return None, "unreadable"
    if b"\0" in data[:8192]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), None


def scan_file(path: Path) -> tuple[list[Hit], str | None]:
    text, reason = _read_text(path)
    if text is None:
        return [], reason
    source, experimental = classify(path)
    hits = [
        Hit(path, number, span.kind, span.preview, source, experimental)
        for number, span in iter_line_spans(text)
    ]
    return hits, None


def scan_files(paths: list[Path]) -> tuple[list[Hit], int]:
    hits: list[Hit] = []
    skipped = 0
    for path in paths:
        found, reason = scan_file(path)
        if reason is not None:
            skipped += 1
            continue
        hits.extend(found)
    hits.sort(key=lambda hit: (hit.path.as_posix(), hit.line, hit.kind, hit.preview))
    return hits, skipped


def _backup(path: Path) -> Path | None:
    backup = path.with_name(path.name + ".bak")
    if backup.exists():
        return None
    shutil.copy2(path, backup)
    return backup


def _write_text(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def redact_file(path: Path, dry_run: bool) -> tuple[list[Hit], Path | None, bool]:
    text, reason = _read_text(path)
    if text is None or reason is not None:
        return [], None, True
    rewritten, found = redact_text(text)
    if not found or rewritten == text:
        return [], None, False
    source, experimental = classify(path)
    hits = [
        Hit(path, number, span.kind, span.preview, source, experimental)
        for number, span in found
    ]
    backup: Path | None = None
    if not dry_run:
        backup = _backup(path)
        _write_text(path, rewritten)
    return hits, backup, False


def redact_files(paths: list[Path], dry_run: bool) -> tuple[list[Hit], int, list[Path]]:
    hits: list[Hit] = []
    backups: list[Path] = []
    skipped = 0
    for path in paths:
        try:
            found, backup, skipped_file = redact_file(path, dry_run)
        except OSError:
            skipped += 1
            continue
        if skipped_file:
            skipped += 1
            continue
        hits.extend(found)
        if backup is not None:
            backups.append(backup)
    hits.sort(key=lambda hit: (hit.path.as_posix(), hit.line, hit.kind))
    return hits, skipped, backups
