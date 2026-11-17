"""mcp-firewall --policy POLICY [--audit FILE] -- upstream-command [args...]
   mcp-firewall demo [--replay] [--html PATH]   (scripted session, no key needed)"""
from __future__ import annotations

import argparse
import sys

from . import policy as policy_mod
from .proxy import Firewall, run


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["demo"]:
        from .demo import main as demo
        return demo(argv[1:])
    ap = argparse.ArgumentParser(prog="mcp-firewall", description=__doc__)
    ap.add_argument("--policy", required=True, help="policy file (.json, or .toml on Python 3.11+)")
    ap.add_argument("--audit", help="JSONL audit log path; overrides the policy's audit_log; '-' = stderr")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="upstream server command, after --")
    a = ap.parse_args(argv)
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not command:
        ap.error("missing upstream command after --")
    try:
        pol = policy_mod.load(a.policy)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"mcp-firewall: cannot load policy {a.policy}: {e}", file=sys.stderr)
        return 2
    target = a.audit or pol.audit_log or "-"
    audit = sys.stderr if target == "-" else open(target, "a", encoding="utf-8")
    try:
        return run(Firewall(pol, audit), command)
    except FileNotFoundError as e:
        print(f"mcp-firewall: cannot start upstream: {e}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
