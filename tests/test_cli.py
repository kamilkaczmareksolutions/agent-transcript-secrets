import io
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from agent_secrets.cli import main

ROOT = Path(__file__).resolve().parents[1]

RAW = (
    "FAKEEXAMPLETOKEN",
    "sk-ant-FAKEEXAMPLEKEY",
    "AKIAfakeEXAMPLEKEY12",
    "sk-FAKE-EXAMPLE-OPENAI",
    "ghp_FAKE_EXAMPLE_TOKEN",
    "gho_FAKE_EXAMPLE_TOKEN",
    "github_pat_FAKE_EXAMPLE_TOKEN",
    "FakeExamplePass99",
    "sk_live_FAKEEXAMPLE",
    "xoxb-FAKE-EXAMPLE-TOKEN",
    "AIzaFAKEEXAMPLE",
    "xai-FAKEEXAMPLEKEY",
    "-----BEGIN FAKE PRIVATE KEY EXAMPLE-----",
    "notrealFAKEexampleVALUE99",
)

EXPECTED_KINDS = {
    "anthropic-api-key": 1,
    "aws-access-key": 1,
    "bearer-token": 1,
    "github-token": 3,
    "google-api-key": 1,
    "high-entropy-assignment": 1,
    "openai-api-key": 1,
    "private-key": 1,
    "slack-token": 1,
    "stripe-live-key": 1,
    "url-password": 1,
    "xai-api-key": 1,
}


def invoke(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def assert_hidden(stdout: str, stderr: str) -> None:
    for secret in RAW:
        assert secret not in stdout
        assert secret not in stderr


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    monkeypatch.setenv("CURSOR_CONFIG_DIR", str(home / ".cursor"))
    monkeypatch.chdir(tmp_path)
    return home


def test_scan_examples_reports_each_kind_and_hides_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    code, stdout, stderr = invoke(["scan", "--json", "examples"])
    assert code == 1
    assert_hidden(stdout, stderr)
    report = json.loads(stdout)
    counts = Counter(item["kind"] for item in report["findings"])
    assert counts == EXPECTED_KINDS
    assert report["count"] == 14
    assert report["skipped"] == 0
    paths = [item["path"] for item in report["findings"]]
    assert all("placeholders" not in path for path in paths)
    cursor = [item for item in report["findings"] if "agent-transcripts" in item["path"]]
    assert cursor
    assert all(item["experimental"] is True and item["source"] == "cursor" for item in cursor)
    claude = [item for item in report["findings"] if item["source"] == "claude"]
    assert claude
    assert all(item["experimental"] is False for item in claude)
    for item in report["findings"]:
        assert item["preview"]
        assert item["line"] >= 1


def test_scan_table_mentions_kind_without_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    code, stdout, stderr = invoke(["scan", "examples"])
    assert code == 1
    assert "anthropic-api-key" in stdout
    assert "14 secrets found." in stdout
    assert "file" in stdout
    assert_hidden(stdout, stderr)


def test_clean_placeholders_are_silent(isolated: Path, tmp_path: Path) -> None:
    target = tmp_path / "placeholders.json"
    shutil.copy(ROOT / "examples" / "clean" / "placeholders.json", target)
    code, stdout, stderr = invoke(["scan", str(target)])
    assert code == 0
    assert stdout.strip() == "No secrets found."
    assert stderr == ""


def test_missing_path_exits_2(isolated: Path) -> None:
    code, _stdout, stderr = invoke(["scan", "missing-path"])
    assert code == 2
    assert "path not found" in stderr


def test_staged_with_paths_exits_2(isolated: Path) -> None:
    code, _stdout, stderr = invoke(["scan", "--staged", "examples"])
    assert code == 2
    assert "either" in stderr


def test_default_locations_skip_unrelated_files(isolated: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = isolated
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    (home / ".claude" / "projects" / "demo").mkdir(parents=True)
    (home / ".claude" / "projects" / "demo" / "session.jsonl").write_text(
        "sk-ant-FAKEEXAMPLEKEY\n", encoding="utf-8"
    )
    (home / ".claude" / "projects" / "demo" / "subagents").mkdir()
    (home / ".claude" / "projects" / "demo" / "subagents" / "child.jsonl").write_text(
        "sk-FAKE-EXAMPLE-OPENAI\n", encoding="utf-8"
    )
    (home / ".claude" / "settings.local.json").write_text(
        "Authorization: Bearer FAKEEXAMPLETOKEN\n", encoding="utf-8"
    )
    (home / ".claude" / "notes.txt").write_text("sk-ant-DECOYSHOULDNOTSHOW\n", encoding="utf-8")
    codex = home / ".codex" / "sessions" / "2026" / "11" / "09"
    codex.mkdir(parents=True)
    (codex / "rollout-demo.jsonl").write_text("sk_live_FAKEEXAMPLE\n", encoding="utf-8")
    (home / ".codex" / "sessions" / "notes.jsonl").write_text("ghp_DECOY_EXAMPLE_TOKEN\n", encoding="utf-8")
    cursor = home / ".cursor" / "projects" / "p" / "agent-transcripts" / "s"
    cursor.mkdir(parents=True)
    (cursor / "s.jsonl").write_text("-----BEGIN FAKE PRIVATE KEY EXAMPLE-----\n", encoding="utf-8")
    (home / ".cursor" / "projects" / "p" / "other.jsonl").write_text(
        "AIzaFAKEEXAMPLE\n", encoding="utf-8"
    )
    (project / ".claude").mkdir()
    (project / ".claude" / "settings.local.json").write_text(
        "AWS_ACCESS_KEY_ID=AKIAfakeEXAMPLEKEY12\n", encoding="utf-8"
    )
    code, stdout, stderr = invoke(["scan", "--json"])
    assert code == 1
    assert "DECOY" not in stdout
    assert_hidden(stdout, stderr)
    report = json.loads(stdout)
    assert report["count"] == 6
    sources = Counter(item["source"] for item in report["findings"])
    assert sources["cursor"] == 1
    assert all(item["experimental"] for item in report["findings"] if item["source"] == "cursor")


def test_redact_dry_run_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    before = {
        path: path.read_bytes()
        for path in (ROOT / "examples").rglob("*")
        if path.is_file()
    }
    code, stdout, stderr = invoke(["redact", "--dry-run", "examples"])
    assert code == 1
    assert "[REDACTED:anthropic-api-key]" in stdout
    assert "would be redacted" in stdout
    assert "backup " not in stdout
    assert_hidden(stdout, stderr)
    after = {
        path: path.read_bytes()
        for path in (ROOT / "examples").rglob("*")
        if path.is_file()
    }
    assert before == after
    assert list((ROOT / "examples").rglob("*.bak")) == []


def test_redact_writes_backup_and_second_run_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "session.jsonl"
    original = "OPENAI_API_KEY=sk-FAKE-EXAMPLE-OPENAI\nAPI_TOKEN=notrealFAKEexampleVALUE99\n"
    target.write_text(original, encoding="utf-8")
    code, stdout, stderr = invoke(["redact", "session.jsonl"])
    assert code == 1
    assert_hidden(stdout, stderr)
    assert "backup session.jsonl.bak" in stdout
    backup = tmp_path / "session.jsonl.bak"
    assert backup.read_text(encoding="utf-8") == original
    redacted = target.read_text(encoding="utf-8")
    assert "sk-FAKE-EXAMPLE-OPENAI" not in redacted
    assert "[REDACTED:openai-api-key]" in redacted
    assert "[REDACTED:high-entropy-assignment]" in redacted
    backup_bytes = backup.read_bytes()
    again, stdout2, stderr2 = invoke(["redact", "session.jsonl"])
    assert again == 0
    assert stdout2.strip() == "No secrets found."
    assert stderr2 == ""
    assert backup.read_bytes() == backup_bytes
    clean, clean_out, _clean_err = invoke(["scan", "session.jsonl"])
    assert clean == 0
    assert "No secrets found." in clean_out


def test_install_hook_is_idempotent_and_blocks_a_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shim = bindir / "agent-secrets"
    shim.write_text(f"#!/bin/sh\nexec {sys.executable} -m agent_secrets \"$@\"\n", encoding="utf-8")
    shim.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = str(ROOT / "src")
    env["HOME"] = str(tmp_path / "home")
    env["CODEX_HOME"] = str(tmp_path / "codex")
    env["CURSOR_CONFIG_DIR"] = str(tmp_path / "cursor")
    env["GIT_AUTHOR_NAME"] = "Dev"
    env["GIT_AUTHOR_EMAIL"] = "dev@example.test"
    env["GIT_COMMITTER_NAME"] = "Dev"
    env["GIT_COMMITTER_EMAIL"] = "dev@example.test"

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    git("init")
    git("config", "user.email", "dev@example.test")
    git("config", "user.name", "Dev")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho kept\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    code, stdout, _stderr = invoke(["install-hook"])
    assert code == 0
    assert "installed" in stdout
    again, _stdout2, _stderr2 = invoke(["install-hook"])
    assert again == 0
    text = hook.read_text(encoding="utf-8")
    assert text.count("# >>> agent-secrets >>>") == 1
    assert "echo kept" in text
    secret = repo / "chat.jsonl"
    secret.write_text("sk-ant-FAKEEXAMPLEKEY\n", encoding="utf-8")
    git("add", "chat.jsonl")
    blocked = subprocess.run(
        ["git", "commit", "-m", "add transcript"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    assert blocked.returncode != 0
    assert "sk-ant-FAKEEXAMPLEKEY" not in blocked.stdout
    assert "sk-ant-FAKEEXAMPLEKEY" not in blocked.stderr
    git("reset")
    secret.unlink()
    (repo / "readme.md").write_text("hello\n", encoding="utf-8")
    git("add", "readme.md")
    allowed = subprocess.run(
        ["git", "commit", "-m", "add readme"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )
    assert allowed.returncode == 0


def test_module_entrypoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(ROOT)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    env["HOME"] = str(tmp_path)
    env["CODEX_HOME"] = str(tmp_path / "codex")
    env["CURSOR_CONFIG_DIR"] = str(tmp_path / "cursor")
    proc = subprocess.run(
        [sys.executable, "-m", "agent_secrets", "scan", "examples"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "14 secrets found." in proc.stdout
    assert_hidden(proc.stdout, proc.stderr)


def test_package_does_not_import_network_clients() -> None:
    banned = ("urllib", "http.client", "httpx", "aiohttp", "requests", "socket")
    for path in (ROOT / "src" / "agent_secrets").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in banned:
            assert f"import {name}" not in text
            assert f"from {name}" not in text
        assert "https://" not in text
        assert "http://" not in text
        assert "telemetry" not in text
