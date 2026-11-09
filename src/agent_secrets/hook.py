from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

from agent_secrets.discover import is_hook_candidate

BEGIN = "# >>> agent-secrets >>>"
END = "# <<< agent-secrets <<<"
_BLOCK = re.compile(r"# >>> agent-secrets >>>\n.*?# <<< agent-secrets <<<\n?", re.S)


class HookError(Exception):
    pass


def hook_block() -> str:
    return (
        f"{BEGIN}\n"
        "if ! command -v agent-secrets >/dev/null 2>&1; then\n"
        '  echo "agent-secrets: not on PATH" >&2\n'
        "  exit 2\n"
        "fi\n"
        "agent-secrets scan --staged || exit $?\n"
        f"{END}\n"
    )


def git_root() -> Path:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise HookError("git is not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise HookError("not a git repository") from exc
    return Path(proc.stdout.strip())


def staged_files() -> list[Path]:
    root = git_root()
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACM"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise HookError("git is not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise HookError("not a git repository") from exc
    names = [name for name in proc.stdout.decode().split("\0") if name]
    files: list[Path] = []
    for name in names:
        path = root / name
        if path.is_file() and is_hook_candidate(path):
            files.append(path)
    return files


def install_hook() -> Path:
    root = git_root()
    path = root / ".git" / "hooks" / "pre-commit"
    path.parent.mkdir(parents=True, exist_ok=True)
    block = hook_block()
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if _BLOCK.search(existing):
        updated = _BLOCK.sub(block, existing, count=1)
    elif existing.strip() == "":
        updated = "#!/bin/sh\n" + block
    else:
        separator = "" if existing.endswith("\n") else "\n"
        updated = existing + separator + block
    path.write_text(updated, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
