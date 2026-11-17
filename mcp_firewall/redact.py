"""Replace credential-shaped substrings with a placeholder.

The pattern list is adapted from offload/credentials.py in
https://github.com/oguzhanozfe/llm-offload (MIT). There it only detects;
here each pattern also says what to replace, and the key=value pattern keeps
the key so the result still reads sensibly.
"""
from __future__ import annotations

import re
from typing import Any

# (name, pattern). A pattern with a group named "value" only has that group replaced.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("openai_or_anthropic_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"refresh[_-]?token|client[_-]?secret|private[_-]?key)\b['\"]?\s*[:=]\s*['\"]?"
        r"(?P<value>[^\s'\",;]{8,})")),
]

# Object keys whose whole string value is treated as a secret, whatever it looks like.
SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|bearer[_-]?token|private[_-]?key|authorization|cookie)")


def is_binary(parent: dict, key: str) -> bool:
    """True for base64 payloads the spec defines: image/audio `data` and resource `blob`."""
    if key == "data":
        return parent.get("type") in ("image", "audio")
    return key == "blob" and "uri" in parent


def redact_text(text: str, extra: list[re.Pattern[str]] = ()) -> tuple[str, list[str]]:
    """Return (redacted text, names of the patterns that matched)."""
    hits: list[str] = []
    for name, pat in [*PATTERNS, *(("custom", p) for p in extra)]:
        def sub(m: re.Match[str], name: str = name) -> str:
            hits.append(name)
            if "value" in pat.groupindex:
                start, end = m.span("value")
                s = m.start()
                return m.group(0)[: start - s] + f"[REDACTED:{name}]" + m.group(0)[end - s:]
            return f"[REDACTED:{name}]"
        text = pat.sub(sub, text)
    return text, hits


def redact(value: Any, extra: list[re.Pattern[str]] = ()) -> tuple[Any, list[str]]:
    """Redact every string leaf of a JSON value. Returns (new value, hit names)."""
    hits: list[str] = []

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            new, h = redact_text(v, extra)
            hits.extend(h)
            return new
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                if isinstance(x, str) and is_binary(v, k):
                    out[k] = x
                elif isinstance(x, str) and x and SENSITIVE_KEY.fullmatch(k):
                    hits.append("sensitive_key")
                    out[k] = "[REDACTED:sensitive_key]"
                else:
                    out[k] = walk(x)
            return out
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(value), hits
