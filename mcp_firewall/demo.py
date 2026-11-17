"""python -m mcp_firewall demo [--replay] [--html PATH]

Starts the real proxy (a subprocess, exactly as an MCP client would) in front
of the bundled fake MCP server, replays a short scripted session and prints
each decision plus the audit log. Needs no key: the regex lane needs no
model, and the classifier lane resolves GEMINI_API_KEY -> local Ollama ->
replay of verdicts recorded in demo_verdicts.jsonl. In replay mode it exits
1 if any step's decision is not the expected one, so CI can run it. With a
live model the classifier step shows what that model said (qwen3.5:9b, for
one, misses it) and is not held to the recorded answer.
"""
from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from .classifier import PROVIDERS

HERE = Path(__file__).parent
VERDICTS = HERE / "demo_verdicts.jsonl"

# (what it shows, tool, arguments, expected audit decision for the response or the denied request)
STEPS = [
    ("allowed call", "echo", {"msg": "hello"}, "forward"),
    ("path outside /workspace", "read_file", {"path": "/workspace/../etc/passwd"}, "deny"),
    ("denied tool", "delete_everything", {}, "deny"),
    ("secret in the arguments", "echo", {"api_key": "sk-" + "ant-" + "demo" * 8}, "redact"),
    ("secret in the result", "leaky", {}, "redact"),
    ("injection, regex lane", "web_fetch", {"url": "https://example.com"}, "annotate"),
    ("indirect injection, classifier lane", "read_page", {"url": "https://shop.example/aurora-x2"}, "annotate"),
]


def resolve_classifier(force_replay: bool) -> tuple[dict, str]:
    """Env key -> local Ollama -> replay. Returns (policy classifier block, mode line)."""
    if not force_replay and os.environ.get("GEMINI_API_KEY"):
        return {"provider": "gemini"}, f"mode: live (gemini {PROVIDERS['gemini'][2]}, key from GEMINI_API_KEY)"
    model = PROVIDERS["ollama"][2]
    if not force_replay:
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1) as r:
                if any(m.get("name") == model for m in json.load(r).get("models", [])):
                    return {"provider": "ollama"}, f"mode: local (ollama {model})"
        except (OSError, ValueError):
            pass
    rec = json.loads(VERDICTS.read_text().splitlines()[0])
    return ({"provider": "replay", "base_url": str(VERDICTS)},
            f"mode: replay (recorded {rec['model']}, {rec['date']})")


def run_session(clf: dict, tmp: Path) -> list[dict]:
    policy = {
        "tools": {"allow": ["echo", "read_*", "leaky", "web_fetch"], "deny": ["*delete*"]},
        "per_tool": {"read_file": {"args": {"path": {"path_prefix": ["/workspace"]}}}},
        "injection": {"action": "annotate", "classifier": clf},
    }
    (tmp / "policy.json").write_text(json.dumps(policy))
    audit = tmp / "audit.jsonl"
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_firewall", "--policy", str(tmp / "policy.json"), "--audit", str(audit),
         "--", sys.executable, str(HERE / "fake_server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def call(i: int, method: str, params: dict) -> dict:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n")
        proc.stdin.flush()
        while True:
            msg = json.loads(proc.stdout.readline())
            if msg.get("id") == i:
                return msg["result"]

    out = [{"label": "tools/list", "result": call(0, "tools/list", {})}]
    for i, (label, tool, args, expect) in enumerate(STEPS, 1):
        out.append({"label": label, "tool": tool, "args": args, "expect": expect,
                    "result": call(i, "tools/call", {"name": tool, "arguments": args})})
    proc.stdin.close()
    proc.wait(timeout=10)
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    for i, step in enumerate(out):
        mine = [e for e in events if e.get("id") == i]
        step["events"] = mine
        step["decision"] = next((e["decision"] for e in mine if e["decision"] == "deny"), mine[-1]["decision"])
    return out


def render(mode: str, steps: list[dict]) -> tuple[list[str], list[str], bool]:
    lines, ok, replay = [mode, ""], True, mode.startswith("mode: replay")
    names = [t["name"] for t in steps[0]["result"]["tools"]]
    lines.append(f"tools/list -> client sees {', '.join(names)} ({steps[0]['decision']}: denied tools hidden)")
    for s in steps[1:]:
        good = s["decision"] == s["expect"]
        model_step = "classifier" in s["label"]
        ok &= good or (model_step and not replay)
        text = " | ".join(c.get("text", "") for c in s["result"].get("content", []))
        tag = "ok " if good else ("MISS" if model_step and not replay else "BAD")
        lines.append(f"{tag} {s['label']}: {s['tool']}({json.dumps(s['args'])})")
        lines.append(f"    decision: {s['decision']}" + ("" if good else f" (the recorded Gemini run: {s['expect']})"
                                                         if model_step and not replay else f" (expected {s['expect']})"))
        lines.append(f"    client gets: {text[:220]}".replace("\n", " / "))
    audit = [json.dumps(e, ensure_ascii=False) for s in steps for e in s["events"]]
    return lines, audit, ok


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>mcp-firewall demo</title>
<style>:root{{--bg:#fbfbfa;--fg:#1d1d1b;--mute:#6b6b66;--ok:#1f7a3f;--bad:#b3261e;--box:#f0efeb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--fg:#e8e6e1;--mute:#9a978f;--ok:#6fcf8f;--bad:#ff8a80;--box:#20201e}}}}
body{{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;max-width:980px;margin:0 auto;padding:24px 16px}}
pre{{background:var(--box);padding:14px;border-radius:8px;overflow-x:auto;font-size:13px;line-height:1.45;white-space:pre-wrap;word-break:break-word}}
.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}p,.mute{{color:var(--mute)}}a{{color:inherit}}</style></head><body>
<h1>mcp-firewall demo</h1>
<p>A recorded run of <code>python -m mcp_firewall demo</code>: the real proxy in front of a fake MCP server,
with a scripted session. Source and measured detection numbers:
<a href="https://github.com/oguzhanozfe/mcp-firewall">github.com/oguzhanozfe/mcp-firewall</a>.</p>
<h2>Decisions</h2><pre>{session}</pre>
<h2>Audit log (JSONL, arguments always redacted)</h2><pre>{audit}</pre></body></html>
"""


def main(argv: list[str]) -> int:
    force_replay = "--replay" in argv
    html_path = argv[argv.index("--html") + 1] if "--html" in argv else None
    clf, mode = resolve_classifier(force_replay)
    with tempfile.TemporaryDirectory() as tmp:
        lines, audit, ok = render(mode, run_session(clf, Path(tmp)))
    print("\n".join(lines), "\naudit log:", *audit, sep="\n")
    if html_path:
        esc = [html.escape(x) for x in lines]
        esc = [f'<span class="{"ok" if x.startswith("ok ") else "bad"}">{x}</span>' if x[:3] in ("ok ", "BAD", "MIS") else x
               for x in esc]
        Path(html_path).write_text(PAGE.format(session="\n".join(esc), audit=html.escape("\n".join(audit))))
    if not ok:
        print("demo: a step did not get the expected decision", file=sys.stderr)
    return 0 if ok else 1
