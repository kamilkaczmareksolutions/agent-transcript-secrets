from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

PLACEHOLDERS = frozenset(
    {
        "<api-key>",
        "<key>",
        "<token>",
        "api-key",
        "api_key",
        "apikey",
        "changeme",
        "dummy",
        "example",
        "fake",
        "insert-key",
        "none",
        "null",
        "password",
        "placeholder",
        "redacted",
        "secret",
        "sk-ant-xxx",
        "sk-xxx",
        "test",
        "token",
        "todo",
        "xxx",
        "your-api-key",
        "your-token",
        "your_api_key",
        "your_token",
    }
)

PEM_FOLLOW_LINES = 80

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----")
_B64_LINE = re.compile(r"[A-Za-z0-9+/=]{16,}")


@dataclass(frozen=True)
class Span:
    kind: str
    start: int
    end: int
    preview: str


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    group: int
    accept: Callable[[str], bool]
    preview: Callable[[str], str]


def is_placeholder(value: str) -> bool:
    text = value.strip().strip("\"'")
    lowered = text.lower()
    if lowered in PLACEHOLDERS:
        return True
    if lowered.startswith("<") and lowered.endswith(">") and len(lowered) > 2:
        return True
    if re.fullmatch(r"sk-(ant-)?x+", lowered):
        return True
    if re.fullmatch(r"[x*.-]{4,}", lowered):
        return True
    if "your-api-key" in lowered or "your_api_key" in lowered or "<token>" in lowered:
        return True
    return False


def _shannon(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_ok(value: str) -> bool:
    if len(value) < 16 or is_placeholder(value):
        return False
    if _shannon(value) < 3.5:
        return False
    has_lower = any(char.islower() for char in value)
    has_upper = any(char.isupper() for char in value)
    has_digit = any(char.isdigit() for char in value)
    return (has_lower and has_upper) or has_digit


def mask_secret(secret: str) -> str:
    if secret.startswith("-----BEGIN"):
        return "-----BEGIN …-----"
    prefixes = (
        "github_pat_",
        "sk-ant-",
        "sk_live_",
        "sk-",
        "ghp_",
        "gho_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "AIza",
        "AKIA",
        "xai-",
    )
    prefix = next((item for item in prefixes if secret.startswith(item)), "")
    if prefix and len(secret) > len(prefix) + 4:
        shown = f"{prefix}…{secret[-4:]}"
    elif len(secret) <= 8:
        shown = "…"
    else:
        shown = f"{secret[:3]}…{secret[-3:]}"
    if secret in shown or shown.replace("…", "") == secret:
        return "…"
    return shown


def _mask_password(_secret: str) -> str:
    return "…"


def _not_placeholder(value: str) -> bool:
    return not is_placeholder(value)


def _detectors() -> tuple[Detector, ...]:
    return (
        Detector(
            "private-key",
            _PEM_BEGIN,
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "url-password",
            re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^/\s@]{4,})(@)"),
            2,
            _not_placeholder,
            _mask_password,
        ),
        Detector(
            "anthropic-api-key",
            re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "openai-api-key",
            re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "github-token",
            re.compile(r"(?<![A-Za-z0-9])(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "aws-access-key",
            re.compile(r"(?<![A-Za-z0-9])AKIA[A-Za-z0-9]{16}(?![A-Za-z0-9])"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "slack-token",
            re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "stripe-live-key",
            re.compile(r"sk_live_[A-Za-z0-9]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "google-api-key",
            re.compile(r"AIza[0-9A-Za-z_-]{10,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "xai-api-key",
            re.compile(r"(?<![A-Za-z0-9])xai-[A-Za-z0-9_-]{8,}"),
            0,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "bearer-token",
            re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{8,}={0,2})"),
            1,
            _not_placeholder,
            mask_secret,
        ),
        Detector(
            "high-entropy-assignment",
            re.compile(
                r"(?i)(?<![A-Za-z0-9_])[A-Za-z0-9_]*(?:key|token|password|secret)\b"
                r"\s*[=:]\s*[\"']?([^\s\"'\\,;)\[\]]{16,})"
            ),
            1,
            _entropy_ok,
            mask_secret,
        ),
    )


DETECTORS = _detectors()


def _overlaps(left: Span, right: Span) -> bool:
    return left.start < right.end and right.start < left.end


def find_spans(line: str) -> list[Span]:
    kept: list[Span] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(line):
            value = match.group(detector.group)
            if not detector.accept(value):
                continue
            span = Span(
                detector.kind,
                match.start(detector.group),
                match.end(detector.group),
                detector.preview(value),
            )
            if any(_overlaps(span, prior) for prior in kept):
                continue
            kept.append(span)
    kept.sort(key=lambda span: (span.start, span.kind))
    return kept


def split_lines(text: str) -> tuple[list[str], list[str]]:
    if text == "":
        return [], []
    parts = re.split(r"(\r\n|\n|\r)", text)
    lines = parts[0::2]
    separators = parts[1::2]
    if lines and lines[-1] == "" and separators:
        lines = lines[:-1]
    return lines, separators


def iter_line_spans(text: str) -> list[tuple[int, Span]]:
    lines, _separators = split_lines(text)
    found: list[tuple[int, Span]] = []
    in_pem = False
    budget = 0
    for number, line in enumerate(lines, start=1):
        if in_pem:
            stripped = line.strip()
            closes = _PEM_END.search(line) is not None
            if closes or (stripped != "" and _B64_LINE.fullmatch(stripped) is not None):
                found.append((number, Span("private-key", 0, len(line), "-----BEGIN …-----")))
                if closes or budget <= 1:
                    in_pem = False
                else:
                    budget -= 1
                continue
            in_pem = False
        spans = find_spans(line)
        found.extend((number, span) for span in spans)
        if any(span.kind == "private-key" and _PEM_END.search(line) is None for span in spans):
            in_pem = True
            budget = PEM_FOLLOW_LINES
    return found


def redact_text(text: str) -> tuple[str, list[tuple[int, Span]]]:
    lines, separators = split_lines(text)
    found = iter_line_spans(text)
    by_line: dict[int, list[Span]] = {}
    for number, span in found:
        by_line.setdefault(number, []).append(span)
    rewritten: list[str] = []
    for number, line in enumerate(lines, start=1):
        updated = line
        for span in sorted(by_line.get(number, []), key=lambda item: item.start, reverse=True):
            token = f"[REDACTED:{span.kind}]"
            updated = updated[: span.start] + token + updated[span.end :]
        rewritten.append(updated)
    parts: list[str] = []
    for index, line in enumerate(rewritten):
        parts.append(line)
        if index < len(separators):
            parts.append(separators[index])
    return "".join(parts), found
