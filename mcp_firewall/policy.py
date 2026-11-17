"""Load a policy file and decide whether a tool call may go through."""
from __future__ import annotations

import json
import posixpath
import re
import time
from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Callable

INJECTION_ACTIONS = ("off", "flag", "annotate", "strip", "block")


class PolicyError(ValueError):
    pass


@dataclass
class ArgRule:
    regex: re.Pattern[str] | None = None
    path_prefix: list[str] = field(default_factory=list)
    max_length: int | None = None

    def check(self, name: str, value: Any) -> str | None:
        """Return a reason string if the value breaks the rule, else None."""
        if value is None:
            return None
        text = value if isinstance(value, str) else json.dumps(value)
        if self.max_length is not None and len(text) > self.max_length:
            return f"argument {name!r} is {len(text)} chars, limit {self.max_length}"
        if (self.regex or self.path_prefix) and not isinstance(value, str):
            return f"argument {name!r} must be a string"
        if self.regex and not self.regex.fullmatch(value):
            return f"argument {name!r} does not match {self.regex.pattern!r}"
        if self.path_prefix:
            # Normalise lexically so "/work/../etc" cannot pass as "/work/".
            # ponytail: no symlink resolution; the upstream's filesystem may not be ours.
            if "\x00" in value:
                return f"argument {name!r} contains a NUL byte"
            p = posixpath.normpath(value.replace("\\", "/"))
            ok = any(p == pre.rstrip("/") or p.startswith(pre.rstrip("/") + "/") for pre in self.path_prefix)
            if not ok:
                return f"argument {name!r} path {p!r} is outside {self.path_prefix}"
        return None


class RateLimiter:
    """Sliding-window limit: at most `calls` in any `per_seconds` window."""

    def __init__(self, calls: int, per_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.calls, self.per, self.clock = calls, per_seconds, clock
        self.hits: deque[float] = deque()

    def allow(self) -> bool:
        now = self.clock()
        while self.hits and now - self.hits[0] >= self.per:
            self.hits.popleft()
        if len(self.hits) >= self.calls:
            return False
        self.hits.append(now)
        return True


@dataclass
class Policy:
    allow: list[str] | None = None  # None = every tool not denied
    deny: list[str] = field(default_factory=list)
    args: dict[str, dict[str, ArgRule]] = field(default_factory=dict)
    limits: dict[str, RateLimiter] = field(default_factory=dict)
    redact: bool = True
    redact_extra: list[re.Pattern[str]] = field(default_factory=list)
    injection: str = "annotate"
    audit_log: str | None = None

    def tool_allowed(self, tool: str) -> bool:
        if any(fnmatchcase(tool, pat) for pat in self.deny):
            return False
        return self.allow is None or any(fnmatchcase(tool, pat) for pat in self.allow)

    def check_call(self, tool: str, arguments: dict[str, Any] | None) -> str | None:
        """Return a denial reason, or None to let the call through."""
        if not self.tool_allowed(tool):
            return f"tool {tool!r} is not allowed by policy"
        arguments = arguments or {}
        for name, rule in self._rules_for(tool).items():
            reason = rule.check(name, arguments.get(name))
            if reason:
                return reason
        limiter = self._limiter_for(tool)
        if limiter and not limiter.allow():
            return f"rate limit for {tool!r} reached ({limiter.calls} per {limiter.per:g}s)"
        return None

    def _rules_for(self, tool: str) -> dict[str, ArgRule]:
        out: dict[str, ArgRule] = {}
        for pat, rules in self.args.items():  # later, more specific patterns win per argument
            if fnmatchcase(tool, pat):
                out.update(rules)
        return out

    def _limiter_for(self, tool: str) -> RateLimiter | None:
        # Exact name first, then the first matching glob (one shared bucket per glob).
        if tool in self.limits:
            return self.limits[tool]
        return next((lim for pat, lim in self.limits.items() if fnmatchcase(tool, pat)), None)


def _compile(pattern: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as e:
        raise PolicyError(f"{where}: bad regex {pattern!r}: {e}") from None


def from_dict(d: dict[str, Any], clock: Callable[[], float] = time.monotonic) -> Policy:
    known = {"tools", "per_tool", "redact", "injection", "audit_log"}
    if unknown := set(d) - known:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")
    tools = d.get("tools", {})
    pol = Policy(allow=tools.get("allow"), deny=tools.get("deny", []))
    for tool, spec in d.get("per_tool", {}).items():
        rules = {}
        for arg, r in spec.get("args", {}).items():
            where = f"per_tool.{tool}.args.{arg}"
            if unknown := set(r) - {"regex", "path_prefix", "max_length"}:
                raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
            prefixes = r.get("path_prefix", [])
            rules[arg] = ArgRule(
                regex=_compile(r["regex"], where) if "regex" in r else None,
                path_prefix=[prefixes] if isinstance(prefixes, str) else list(prefixes),
                max_length=r.get("max_length"),
            )
        pol.args[tool] = rules
        if rl := spec.get("rate_limit"):
            if int(rl["calls"]) < 1 or float(rl["per_seconds"]) <= 0:
                raise PolicyError(f"per_tool.{tool}.rate_limit must have calls >= 1 and per_seconds > 0")
            pol.limits[tool] = RateLimiter(int(rl["calls"]), float(rl["per_seconds"]), clock)
    red = d.get("redact", {})
    pol.redact = red.get("enabled", True)
    pol.redact_extra = [_compile(p, "redact.extra_patterns") for p in red.get("extra_patterns", [])]
    pol.injection = d.get("injection", {}).get("action", "annotate")
    if pol.injection not in INJECTION_ACTIONS:
        raise PolicyError(f"injection.action must be one of {INJECTION_ACTIONS}")
    pol.audit_log = d.get("audit_log")
    return pol


def load(path: str | Path) -> Policy:
    path = Path(path)
    raw = path.read_bytes()
    if path.suffix == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:
            raise PolicyError("TOML policies need Python 3.11+; use JSON on 3.10") from None
        data = tomllib.loads(raw.decode())
    else:
        data = json.loads(raw)
    return from_dict(data)
