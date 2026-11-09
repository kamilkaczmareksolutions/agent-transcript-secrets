from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_secrets import __version__
from agent_secrets.discover import default_files, explicit_files
from agent_secrets.engine import Hit, redact_files, scan_files
from agent_secrets.hook import HookError, install_hook, staged_files


class CliError(Exception):
    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-secrets",
        description="Find and redact secrets in local AI agent transcripts and settings.",
    )
    parser.add_argument("--version", action="version", version=f"agent-secrets {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Report secrets. Exit 1 when any are found.")
    scan.add_argument("paths", nargs="*", type=Path)
    scan.add_argument("--json", action="store_true", help="Print a JSON report.")
    scan.add_argument("--staged", action="store_true", help="Scan staged transcript and settings files.")

    redact = commands.add_parser("redact", help="Replace secrets with [REDACTED:<kind>] tokens.")
    redact.add_argument("path", type=Path)
    redact.add_argument("--dry-run", action="store_true", help="Show changes and write nothing.")

    commands.add_parser("install-hook", help="Install a git pre-commit hook that runs scan --staged.")
    return parser


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _payload(hits: list[Hit], skipped: int) -> dict[str, object]:
    return {
        "findings": [
            {
                "path": display_path(hit.path),
                "line": hit.line,
                "kind": hit.kind,
                "preview": hit.preview,
                "source": hit.source,
                "experimental": hit.experimental,
            }
            for hit in hits
        ],
        "count": len(hits),
        "skipped": skipped,
    }


def _table(hits: list[Hit]) -> str:
    rows = [("file", "line", "type", "preview")]
    rows.extend((display_path(hit.path), str(hit.line), hit.kind, hit.preview) for hit in hits)
    widths = [max(len(row[index]) for row in rows) for index in range(4)]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[column]) for column, cell in enumerate(row)).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)


def _summary(count: int, verb: str) -> str:
    if count == 0:
        return "No secrets found."
    noun = "secret" if count == 1 else "secrets"
    return f"{count} {noun} {verb}."


def _note_skipped(skipped: int) -> None:
    if skipped:
        print(f"skipped {skipped} files", file=sys.stderr)


def _resolve_scan_paths(paths: list[Path], staged: bool) -> tuple[list[Path], int]:
    if staged and paths:
        raise CliError("pass either --staged or paths")
    if staged:
        try:
            return staged_files(), 0
        except HookError as exc:
            raise CliError(str(exc)) from exc
    if not paths:
        return default_files(), 0
    found: list[Path] = []
    skipped = 0
    for path in paths:
        if not path.exists():
            raise CliError(f"path not found: {path}")
        files, walk_skipped = explicit_files(path)
        found.extend(files)
        skipped += walk_skipped
    return found, skipped


def cmd_scan(paths: list[Path], staged: bool, as_json: bool) -> int:
    files, walk_skipped = _resolve_scan_paths(paths, staged)
    hits, skipped = scan_files(files)
    skipped += walk_skipped
    _note_skipped(skipped)
    if as_json:
        print(json.dumps(_payload(hits, skipped), indent=2, ensure_ascii=False))
    elif hits:
        print(_table(hits))
        print(_summary(len(hits), "found"))
    else:
        print(_summary(0, "found"))
    return 1 if hits else 0


def cmd_redact(path: Path, dry_run: bool) -> int:
    if not path.exists():
        raise CliError(f"path not found: {path}")
    files, walk_skipped = explicit_files(path)
    hits, skipped, backups = redact_files(files, dry_run)
    _note_skipped(skipped + walk_skipped)
    for hit in hits:
        print(
            f"{display_path(hit.path)}:{hit.line} {hit.kind} "
            f"{hit.preview} -> [REDACTED:{hit.kind}]"
        )
    for backup in backups:
        print(f"backup {display_path(backup)}")
    if dry_run:
        print(_summary(len(hits), "would be redacted"))
    else:
        print(_summary(len(hits), "redacted"))
    return 1 if hits else 0


def cmd_install_hook() -> int:
    try:
        path = install_hook()
    except HookError as exc:
        raise CliError(str(exc)) from exc
    print(f"installed {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args.paths, args.staged, args.json)
        if args.command == "redact":
            return cmd_redact(args.path, args.dry_run)
        if args.command == "install-hook":
            return cmd_install_hook()
    except CliError as exc:
        print(exc, file=sys.stderr)
        return exc.code
    print(f"unknown command {args.command}", file=sys.stderr)
    return 2
