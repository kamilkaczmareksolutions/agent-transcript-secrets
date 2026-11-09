from __future__ import annotations

import os
import re
from pathlib import Path

TEXT_SUFFIXES = {".json", ".jsonl", ".log", ".md", ".txt", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".pytest_cache", ".venv", "__pycache__", "node_modules", "venv"}

_CODEX_LIVE = re.compile(r"sessions/(?:\d{4}/\d{2}/\d{2}/)?rollout-[^/]+\.jsonl$")
_CODEX_ARCH = re.compile(r"archived_sessions/rollout-[^/]+\.jsonl$")


def _claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))


def _classify_claude_root(path: Path, name: str) -> tuple[str, bool] | None:
    try:
        relative = path.resolve().relative_to(_claude_dir().resolve())
    except (OSError, ValueError):
        return None
    if name.endswith(".jsonl") and "projects" in relative.parts:
        return "claude", False
    if name.startswith("settings") and name.endswith(".json") and len(relative.parts) == 1:
        return "claude-settings", False
    return None


def classify(path: Path) -> tuple[str, bool]:
    text = path.as_posix()
    name = path.name[:-4] if path.name.endswith(".bak") else path.name
    parts = path.parts
    if "agent-transcripts" in parts and name.endswith(".jsonl"):
        return "cursor", True
    if name.endswith(".jsonl") and ".claude" in parts and "projects" in parts:
        return "claude", False
    if name.startswith("settings") and name.endswith(".json") and ".claude" in parts:
        return "claude-settings", False
    if _CODEX_LIVE.search(text) or _CODEX_ARCH.search(text):
        return "codex", False
    rooted = _classify_claude_root(path, name)
    if rooted is not None:
        return rooted
    return "file", False


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        try:
            key = path.resolve()
        except OSError:
            continue
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        unique.append(path)
    return unique


def default_files() -> list[Path]:
    home = Path.home()
    claude = _claude_dir()
    codex = Path(os.environ.get("CODEX_HOME", str(home / ".codex")))
    cursor = Path(os.environ.get("CURSOR_CONFIG_DIR", str(home / ".cursor")))
    found: list[Path] = []
    projects = claude / "projects"
    if projects.is_dir():
        found.extend(projects.rglob("*.jsonl"))
    if claude.is_dir():
        found.extend(claude.glob("settings*.json"))
    cwd_claude = Path.cwd() / ".claude"
    if cwd_claude.is_dir():
        found.extend(cwd_claude.glob("settings*.json"))
    sessions = codex / "sessions"
    if sessions.is_dir():
        found.extend(path for path in sessions.rglob("rollout-*.jsonl") if classify(path)[0] == "codex")
    archived = codex / "archived_sessions"
    if archived.is_dir():
        found.extend(path for path in archived.glob("rollout-*.jsonl") if classify(path)[0] == "codex")
    cursor_projects = cursor / "projects"
    if cursor_projects.is_dir():
        found.extend(
            path
            for path in cursor_projects.rglob("*.jsonl")
            if "agent-transcripts" in path.parts
        )
    return _dedupe(found)


def explicit_files(root: Path) -> tuple[list[Path], int]:
    if root.is_file():
        return [root], 0
    found: list[Path] = []
    skipped = 0

    def onerror(_err: OSError) -> None:
        nonlocal skipped
        skipped += 1

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".bak"):
                continue
            path = Path(dirpath) / name
            if path.suffix.lower() in TEXT_SUFFIXES:
                found.append(path)
    return _dedupe(found), skipped


def is_hook_candidate(path: Path) -> bool:
    name = path.name
    probe = path
    if name.endswith(".bak"):
        probe = path.with_name(name[:-4])
        name = probe.name
    text = probe.as_posix()
    if name.endswith(".jsonl"):
        return True
    if name.startswith("settings") and name.endswith(".json"):
        return True
    if "/.claude/" in f"/{text}" or "/agent-transcripts/" in f"/{text}":
        return True
    if _CODEX_LIVE.search(text) or _CODEX_ARCH.search(text):
        return True
    return False
