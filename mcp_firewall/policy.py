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

from .classifier import Classifier

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
    classifier: Classifier | None = None  # optional local-model lane, off by default
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


def _obj(d: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    """Every level is checked, so a typo ("allowlist", "arg") fails loudly instead of open."""
    if not isinstance(d, dict):
        raise PolicyError(f"{where}: must be an object")
    if unknown := set(d) - allowed:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    return d


def _strs(v: Any, where: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise PolicyError(f"{where}: must be a list of strings")
    return v


def _num(v: Any, where: str, minimum: float, integer: bool = False) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (integer and not isinstance(v, int)) or v < minimum:
        raise PolicyError(f"{where}: must be a {'whole ' if integer else ''}number >= {minimum}")
    return v


def from_dict(d: dict[str, Any], clock: Callable[[], float] = time.monotonic) -> Policy:
    _obj(d, "policy", {"tools", "per_tool", "redact", "injection", "audit_log"})
    tools = _obj(d.get("tools", {}), "tools", {"allow", "deny"})
    pol = Policy(allow=_strs(tools["allow"], "tools.allow") if "allow" in tools else None,
                 deny=_strs(tools.get("deny", []), "tools.deny"))
    for tool, spec in _obj(d.get("per_tool", {}), "per_tool", set(d.get("per_tool") or {})).items():
        w = f"per_tool.{tool}"
        spec = _obj(spec, w, {"args", "rate_limit"})
        rules = {}
        for arg, r in _obj(spec.get("args", {}), f"{w}.args", set(spec.get("args") or {})).items():
            wa = f"{w}.args.{arg}"
            r = _obj(r, wa, {"regex", "path_prefix", "max_length"})
            prefixes = r.get("path_prefix", [])
            prefixes = [prefixes] if isinstance(prefixes, str) else _strs(prefixes, f"{wa}.path_prefix")
            if any(not p.startswith("/") for p in prefixes):
                raise PolicyError(f"{wa}.path_prefix: prefixes must be absolute paths")
            if "regex" in r and not isinstance(r["regex"], str):
                raise PolicyError(f"{wa}.regex: must be a string")
            rules[arg] = ArgRule(
                regex=_compile(r["regex"], wa) if "regex" in r else None,
                path_prefix=prefixes,
                max_length=int(_num(r["max_length"], f"{wa}.max_length", 0, True)) if "max_length" in r else None,
            )
        pol.args[tool] = rules
        if "rate_limit" in spec:
            rl = _obj(spec["rate_limit"], f"{w}.rate_limit", {"calls", "per_seconds"})
            if set(rl) != {"calls", "per_seconds"}:
                raise PolicyError(f"{w}.rate_limit: needs both calls and per_seconds")
            pol.limits[tool] = RateLimiter(int(_num(rl["calls"], f"{w}.rate_limit.calls", 1, True)),
                                           float(_num(rl["per_seconds"], f"{w}.rate_limit.per_seconds", 0.001)), clock)
    red = _obj(d.get("redact", {}), "redact", {"enabled", "extra_patterns"})
    if not isinstance(red.get("enabled", True), bool):
        raise PolicyError("redact.enabled: must be true or false")
    pol.redact = red.get("enabled", True)
    pol.redact_extra = [_compile(p, "redact.extra_patterns") for p in _strs(red.get("extra_patterns", []), "redact.extra_patterns")]
    inj = _obj(d.get("injection", {}), "injection", {"action", "classifier"})
    pol.injection = inj.get("action", "annotate")
    if "classifier" in inj:
        c = _obj(inj["classifier"], "injection.classifier",
                 {"provider", "model", "base_url", "api_key_env", "timeout_s", "max_chars"})
        for k in ("provider", "model", "base_url", "api_key_env"):
            if k in c and not isinstance(c[k], str):
                raise PolicyError(f"injection.classifier.{k}: must be a string")
        try:
            pol.classifier = Classifier(
                provider=c.get("provider", "gemini"), model=c.get("model"), base_url=c.get("base_url"),
                api_key_env=c.get("api_key_env"),
                timeout_s=float(_num(c.get("timeout_s", 30), "injection.classifier.timeout_s", 0.1)),
                max_chars=int(_num(c.get("max_chars", 6000), "injection.classifier.max_chars", 1, True)))
        except ValueError as e:
            raise PolicyError(f"injection.classifier: {e}") from None
    if pol.injection not in INJECTION_ACTIONS:
        raise PolicyError(f"injection.action must be one of {INJECTION_ACTIONS}")
    pol.audit_log = d.get("audit_log")
    if pol.audit_log is not None and not isinstance(pol.audit_log, str):
        raise PolicyError("audit_log: must be a string path")
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
