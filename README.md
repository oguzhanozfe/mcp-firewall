# mcp-firewall

A stdio proxy that sits between an MCP client (Claude Code, for example) and one upstream MCP server and enforces a policy file:

- **Tool allowlist and denylist** (glob patterns). Denied tools are also removed from `tools/list`, so the model never sees them.
- **Per-tool argument rules**: regex (full match), path prefix (normalised, so `/work/../etc` does not pass as `/work`), maximum length.
- **Per-tool rate limits** (sliding window).
- **Secret redaction in both directions**: tool-call arguments on the way out, results on the way back. It covers private keys, AWS, GitHub, OpenAI/Anthropic, Google and Slack keys, JWTs, and `password=…`-style assignments.
- **Prompt-injection heuristics on tool results**, with one action per policy: `flag` (log only), `annotate` (prepend a warning block), `strip` (remove matched spans), or `block` (replace the result with an error).
- **A JSONL audit log** of every request, response and decision. Arguments in the log are always redacted, whatever the policy says.

Stdlib Python 3.10+, no dependencies.

## Why

An MCP server's tool results go straight into the model's context, and its tools act with your permissions. A web page, a README or an email that a tool returns can carry instructions aimed at the model. A tool can also be asked to touch paths or hosts it shouldn't. The proxy gives you one choke point to see every call, cap what a server can be asked to do, and stop credentials from leaking either way. It is a seatbelt, not a sandbox (see [Known limits](#known-limits)).

## How it works

The proxy does not speak MCP itself. It forwards every newline-delimited JSON-RPC message and steps in on three things only:

| Message | What happens |
|---|---|
| `tools/call` request | Policy check. A denied call never reaches the server; the client gets a `CallToolResult` with `isError: true` and the reason. An allowed call has its arguments redacted. |
| `tools/list` result | Denied tools are removed. |
| any result | Secrets are redacted. `tools/call` results with `resultType` `complete` (or no `resultType`) are scanned for injection. |

Because it never answers `initialize` or `server/discover` itself, the same proxy works with the stateless [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) protocol and with older handshake-based revisions. Message shapes were checked against the 2026-07-28 `schema.ts`. A line the proxy can't parse as JSON is dropped (and logged) rather than forwarded, so a peer with a looser parser never receives a message the proxy could not check.

## Run it

```bash
git clone https://github.com/oguzhanozfe/mcp-firewall && cd mcp-firewall
python -m unittest discover -s tests -t .      # 28 tests, offline
python -m mcp_firewall --policy examples/policy.json -- <upstream command> [args...]
```

Or install the `mcp-firewall` command:

```bash
pip install git+https://github.com/oguzhanozfe/mcp-firewall
```

### Wrapping a real server in Claude Code

Example: the reference filesystem server, restricted to read-only tools inside one folder. Use absolute paths, because Claude Code starts the proxy from the project directory.

```bash
claude mcp add fs-guarded -- mcp-firewall --policy /abs/path/policy.json --audit /abs/path/audit.jsonl -- npx -y @modelcontextprotocol/server-filesystem /abs/path/workspace
```

Everything after the first `--` is the command Claude Code runs. Everything after the second `--` is the upstream server the firewall starts.

[`examples/smoke_filesystem.sh`](examples/smoke_filesystem.sh) does the same without Claude Code: it wraps `@modelcontextprotocol/server-filesystem` (version 2.3.0 in the recorded run, [`examples/smoke_run.txt`](examples/smoke_run.txt)) and sends a handshake, `tools/list`, a read of a file containing an injection, a `../` traversal and a call to a tool outside the allowlist. On that run the server's 16 tools were filtered to the 3 allowed ones (13 hidden, per the audit log), the injected file came back with a warning block, and the traversal and the write were denied before reaching the server.

## Policy file

JSON, or TOML on Python 3.11+ (`tomllib`). An unknown key, a bad regex or an invalid action stops the proxy at start rather than running with a policy you didn't mean.

```json
{
  "tools": {"allow": ["read_*", "list_*", "search_*", "get_*"], "deny": ["*delete*", "*write*"]},
  "per_tool": {
    "read_*":   {"args": {"path": {"path_prefix": ["/workspace"], "max_length": 1024}},
                 "rate_limit": {"calls": 30, "per_seconds": 60}},
    "search_*": {"args": {"query": {"max_length": 500}}},
    "get_url":  {"args": {"url": {"regex": "https://[A-Za-z0-9.-]+(/[^\\s]*)?"}}}
  },
  "redact": {"enabled": true, "extra_patterns": []},
  "injection": {"action": "annotate"},
  "audit_log": "mcp-firewall-audit.jsonl"
}
```

- `tools.deny` wins over `tools.allow`. With no `allow`, every tool that isn't denied is allowed.
- `per_tool` keys are globs. Argument rules from every matching key apply, and a later key overrides an earlier one for the same argument. A rule only checks arguments that are present; whether an argument is required is the tool schema's job.
- A rate limit on a glob is one shared bucket for all tools that match it.
- `audit_log` can be overridden with `--audit PATH`; `--audit -` writes to stderr. With neither set, the log goes to stderr.

An audit line looks like this:

```json
{"ts": 1763370000.123, "dir": "request", "id": 4, "method": "tools/call", "tool": "read_text_file", "decision": "deny", "reason": "argument 'path' path '/etc/hosts' is outside ['/workspace']", "arguments": {"path": "/workspace/../../etc/hosts"}}
```

## Measured results

### Injection detection

The heuristics are regexes. They were measured on two labelled sets of tool outputs. The full run, including every miss, is in [`eval/results.md`](eval/results.md). Reproduce it with `python eval/measure.py --errors`.

| set | n | TP | FP | FN | TN | precision | recall |
|---|---|---|---|---|---|---|---|
| dev (written by the rule author, rules tuned on it) | 39 | 17 | 0 | 1 | 21 | 1.00 | 0.94 |
| held-out (generated by a different model, measured once) | 72 | 5 | 0 | 23 | 44 | 1.00 | 0.18 |

How to read this:

- **The held-out number is the honest one: the rules catch about 1 injection in 5 they weren't written for.** The dev score comes from the same author who wrote the rules and the examples.
- **The held-out set** was generated by a local model (`qwen3.5:9b` via Ollama, [`eval/generate_heldout.py`](eval/generate_heldout.py)), so its wording was not shaped by the rule author. A human reviewed every label. One fragment was dropped and 7 items with no instruction in them were relabelled benign, with the reason recorded per row. The raw output is committed next to it.
- **What gets caught**: blunt overrides ("ignore all previous instructions"), fake system or role markers, hidden Unicode, text addressed to "the AI", requests to hide things from the user, markdown-image exfiltration beacons.
- **What gets missed**: polite indirect requests ("could you please make sure your next answer…"), directives styled as code comments (`/* INSTRUCTION: … */`), requests to send files to a URL that don't name a credential, French that isn't the literal "ignore the previous instructions", and "run it silently" phrasings.
- **Zero false positives** on 44 + 21 benign items, which include security articles about prompt injection, changelogs that say "ignore previous versions", and READMEs full of imperatives. That is a small set. Expect false positives on real traffic, which is why `annotate` is the default rather than `block`.

Use the injection flag as a signal in the audit log and a warning to the model, not as a guarantee. The policy controls (allowlist, argument rules, rate limits) are the parts that actually constrain what a compromised model can do.

### Tests

28 unit and end-to-end tests run offline. They drive a real proxy process wrapping a fake MCP server ([`tests/fake_server.py`](tests/fake_server.py)) over stdio, using both handshake styles. They cover:

- tool filtering and denial;
- path traversal and prefix boundaries;
- rate limits;
- redaction both ways, including the audit log;
- annotate, strip, block and flag;
- JSON-RPC batches, `input_required` results and id types;
- dropped garbage lines and upstream exit-code propagation.

CI runs them on Python 3.10 to 3.13.

## Known limits

- **Injection heuristics miss most paraphrased attacks** (held-out recall 0.18, above). They only look at text: images, audio and PDFs inside results are not inspected.
- **Path rules are lexical.** The proxy can't resolve symlinks on the server's filesystem, so a symlink inside an allowed folder that points outside it will pass. Pair this with the server's own root restriction.
- **Regex and prefix rules only see the arguments you name.** A tool that takes a path under a different argument name, or inside a nested object, isn't checked unless you add a rule for it. An allowlist of tools is the stronger control.
- **Redaction is pattern-based.** It misses secrets that don't look like secrets (a random password in a plain `"value"` field, an unknown vendor's key format). Add `redact.extra_patterns` for your own formats.
- **Only one upstream server per proxy, and stdio only** (no Streamable HTTP).
- **Rate-limit state is in memory** and resets when the client restarts the proxy.
- **Only tool calls are policed.** Other results (`resources/read`, `prompts/get`) are redacted but not scanned for injection, and server-initiated requests (sampling, elicitation in older protocol revisions) pass through untouched.

## License

MIT. The redaction patterns are adapted from [`offload/credentials.py`](https://github.com/oguzhanozfe/llm-offload/blob/main/offload/credentials.py) in llm-offload (MIT).
