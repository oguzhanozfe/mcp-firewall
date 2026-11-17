# mcp-firewall

A stdio proxy that sits between an MCP client (Claude Code, for example) and one upstream MCP server and enforces a policy file:

- **Tool allowlist and denylist** (glob patterns). Denied tools are also removed from `tools/list`, so the model never sees them.
- **Per-tool argument rules**: regex (full match), path prefix (normalised, so `/work/../etc` does not pass as `/work`), maximum length.
- **Per-tool rate limits** (sliding window).
- **Secret redaction in both directions**: tool-call arguments on the way out, results on the way back. It covers private keys, AWS, GitHub, OpenAI/Anthropic, Google and Slack keys, JWTs, `password=…`-style assignments, and any string value under a key named like `password`, `api_key`, `client_secret` or `authorization`.
- **Prompt-injection detection on tool results**, with one action per policy: `flag` (log only), `annotate` (prepend a warning block), `strip` (remove matched spans), or `block` (replace the result with an error). There are two lanes:
  - regex heuristics, run on normalised text (invisible characters removed, look-alike and fullwidth letters folded, base64 and hex payloads decoded);
  - an optional LLM classifier on any OpenAI-compatible endpoint (Gemini, Ollama, DeepSeek), off by default.
- **A JSONL audit log** of every request, response and decision. Arguments in the log are always redacted, whatever the policy says.

Stdlib Python 3.10+, no dependencies. Tests and CI need no key and no model.

## Try it

**[Demo page](https://oguzhanozfe.github.io/mcp-firewall/)**: a recorded run, no install needed.

[![Demo: one allowed call, two denied calls, two redacted secrets and two flagged injections](docs/demo.png)](https://oguzhanozfe.github.io/mcp-firewall/)

```bash
git clone https://github.com/oguzhanozfe/mcp-firewall && cd mcp-firewall
python -m mcp_firewall demo
```

The demo starts the real proxy in front of the bundled fake MCP server (`mcp_firewall/fake_server.py`), sends a scripted session and prints each decision and the audit log. It takes about a second and needs no key.

The regex lane needs no model. For the classifier lane the demo picks the first available of these:

1. `GEMINI_API_KEY` set: live `gemini-3.1-flash-lite`.
2. Ollama on `127.0.0.1:11434` with `qwen3.5:9b`: local.
3. Otherwise, replay of verdicts recorded from `gemini-3.1-flash-lite` on 2026-11-17 (`mcp_firewall/demo_verdicts.jsonl`). The demo prints `mode: replay (...)`.

`--replay` forces replay, and `--html PATH` also writes the page above. CI runs the replay demo on every push, and the demo exits 1 if any step gets an unexpected decision.

Live models can disagree with the recording. The demo prints `MISS` rather than failing. On 2026-11-17, local `qwen3.5:9b` let the classifier-lane page through. A politer first draft of that injection, an email asking "whoever drafts the board summary" to drop a paragraph, got past Gemini too, so the demo uses a page Gemini does catch. Both are examples of what [it will miss](#injection-detection).

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
python -m unittest discover -s tests -t .      # 38 tests, offline
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

Everything after the first `--` is the command Claude Code runs. Everything after the second `--` is the upstream server the firewall starts. Checked with Claude Code 2.1.296: a server added this way showed `✔ Connected` in `claude mcp list`, and the audit log recorded the health check's requests.

[`examples/smoke_filesystem.sh`](examples/smoke_filesystem.sh) does the same without Claude Code: it wraps `@modelcontextprotocol/server-filesystem` (version 2.3.0 in the recorded run, [`examples/smoke_run.txt`](examples/smoke_run.txt)) and sends a handshake, `tools/list`, a read of a file containing an injection, a `../` traversal and a call to a tool outside the allowlist. On that run the server's 16 tools were filtered to the 3 allowed ones (13 hidden, per the audit log), the injected file came back with a warning block, and the traversal and the write were denied before reaching the server.

## Policy file

JSON, or TOML on Python 3.11+ (`tomllib`). An unknown key at any level, a wrong type, a bad regex or an invalid action stops the proxy at start rather than running with a policy you didn't mean.

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

### Optional classifier lane

```json
"injection": {
  "action": "annotate",
  "classifier": {"provider": "gemini", "model": "gemini-3.1-flash-lite", "timeout_s": 30}
}
```

| `provider` | default model | endpoint | key |
|---|---|---|---|
| `gemini` | `gemini-3.1-flash-lite` | Gemini's OpenAI-compatible API | `GEMINI_API_KEY` |
| `ollama` | `qwen3.5:9b` | `http://127.0.0.1:11434/v1` | none |
| `deepseek` | `deepseek-chat` | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` |

`base_url`, `api_key_env` and `max_chars` (default 6000) can be overridden. The key is read from the environment and never logged.

The classifier only runs when the heuristics did not already flag the result. If it fails (timeout, no key, bad reply), the result goes through unflagged and the audit line records `classifier_error`: the lane fails open so that an outage doesn't take your tools down. With a cloud provider, **every tool result is sent to that provider**, so use `ollama` for private data.

An audit line looks like this:

```json
{"ts": 1763370000.123, "dir": "request", "id": 4, "method": "tools/call", "tool": "read_text_file", "decision": "deny", "reason": "argument 'path' path '/etc/hosts' is outside ['/workspace']", "arguments": {"path": "/workspace/../../etc/hosts"}}
```

## Measured results

### Injection detection

All numbers below come from [`eval/results.md`](eval/results.md), which is the output of `python eval/measure.py`.

**The data**

- **Dev set** (231 items, used for tuning): 39 written by hand, 72 generated by `qwen3.5:9b`, and 120 written by a Claude Sonnet subagent. The rule author read all of it.
- **Held-out set** (160 items, 80 injected and 80 benign, 8 of each per category, [`eval/heldout_v2.jsonl`](eval/heldout_v2.jsonl)): written by a separate Claude Sonnet subagent that was told not to look at the detector. The detector's author never opened it. `measure.py` refuses to print its items and only reports aggregate counts.
- **Injection styles covered:** indirect instructions inside ordinary content, hidden HTML and markdown, base64 and hex payloads, homoglyph and zero-width tricks, "as the assistant you must…", exfiltration URLs with query parameters, forged tool calls and approvals, polite paraphrases, non-English text, and directives in code comments.
- **Hard benign cases:** security write-ups that quote attacks, docs full of imperatives, config with `model:` and `role: system`, legitimate base64, URLs with templated parameters, hidden menus, tool-calling docs.
- **Caveat:** both sets were written by language models, so real attacks may look different.

**Heuristics: precision and recall trade-off** (held-out, all 160 items)

The score is the sum of rule weights: strong rules weigh 2, weak signals 1. The proxy flags at a score of 2 or more.

| flag when score ≥ | TP | FP | FN | TN | precision | recall |
|---|---|---|---|---|---|---|
| 1 | 72 | 42 | 8 | 38 | 0.63 | 0.90 |
| **2 (default)** | **53** | **6** | **27** | **74** | **0.90** | **0.66** |
| 3 | 36 | 2 | 44 | 78 | 0.95 | 0.45 |
| 4 | 18 | 0 | 62 | 80 | 1.00 | 0.23 |

On the dev set the default threshold scores precision 1.00 and recall 0.89. That gap is the overfitting you'd expect from rules tuned on their own data, and it's why only held-out numbers are quoted here.

**Classifier lane** (held-out, fixed sample)

Free-tier quotas (about 20 requests per model per day, shared) can't cover all 160 items. So every lane is compared on a fixed stratified sample: 2 items per label and category, 40 in total, picked by hashing item ids. Responses are cached on disk by input hash ([`eval/runs/classifier_cache.jsonl`](eval/runs/classifier_cache.jsonl)), so re-running costs nothing.

| lane (same 40 items) | model | TP | FP | FN | TN | precision | recall | latency per call |
|---|---|---|---|---|---|---|---|---|
| heuristics, default threshold | none (regex) | 14 | 0 | 6 | 20 | 1.00 | 0.70 | under 1 ms |
| classifier | `gemini-3.1-flash-lite` (Gemini API, 2026-11-17) | 20 | 0 | 0 | 20 | 1.00 | 1.00 | median 1.3 s, p90 2.2 s, max 3.4 s |
| either (what the proxy does with the classifier on) | regex + `gemini-3.1-flash-lite` | 20 | 0 | 0 | 20 | 1.00 | 1.00 | the classifier is skipped when the regex already flags |

`gemma-4-31b-it` on the same API was also tried but returned 503s, timeouts and dropped connections that day, and produced no answers, so it has no row. The Ollama provider (`qwen3.5:9b` by default) works through the same code path. It was not measured, because the shared local Ollama was reserved for projects where local inference is the point.

With 40 items, a perfect score has a wide error bar: 20 of 20 gives a 95% Wilson lower bound of about 0.84 for recall. Treat the classifier rows as "much better than the regexes on this data", not as a measured 100%.

**What it will miss**

Heuristics at the default threshold, held-out, share of injected items caught per category:

| category | caught | category | caught |
|---|---|---|---|
| as_assistant | 1.00 | hidden_markup | 0.75 |
| unicode_tricks | 1.00 | tool_forgery | 0.75 |
| exfil_url | 0.75 | encoded, code_comment, non_english | 0.62 each |
| indirect | 0.38 | polite_paraphrase | 0.12 |

- **Polite or indirect requests are mostly missed.** "It would help if your summary left out…" contains nothing a regex can key on without flagging ordinary support emails.
- **Non-English coverage is limited.** Only French, Spanish, German, Turkish, Japanese and Chinese override and address phrases are covered. Other languages get through.
- **Encoded payloads** are decoded only when they are plain base64 or hex runs. Anything else (rot13, split strings, a payload the page asks the model to assemble) isn't decoded.
- **Directives in code** that don't name an AI, or use an unusual label, get through.
- **False positives** at the default threshold: 6 of 80 benign items. Most were security write-ups quoting attacks (3 of 8 in that category), plus single cases in human-imperative docs, hidden-HTML pages and tool docs.
- **The classifier can be talked out of a verdict** by text written for it, and with a cloud provider every tool result leaves the machine.
- **Neither lane** looks at images, audio or PDFs.

Use detection as a warning to the model and a signal in the audit log. The allowlist, argument rules and rate limits are what actually limit a compromised model.

### Tests

38 unit and end-to-end tests run offline. They drive a real proxy process wrapping a fake MCP server ([`tests/fake_server.py`](tests/fake_server.py)) over stdio, using both handshake styles. They cover:

- tool filtering and denial;
- path traversal and prefix boundaries;
- rate limits;
- redaction both ways, including the audit log;
- annotate, strip, block and flag;
- JSON-RPC batches, `input_required` results and id types;
- dropped garbage lines and upstream exit-code propagation.

CI runs them on Python 3.10 to 3.13.

## Known limits

- **Injection detection misses things** (see [What it will miss](#injection-detection)): about a third of held-out injections get past the heuristics at the default threshold.
- **Path rules are lexical.** The proxy can't resolve symlinks on the server's filesystem, so a symlink inside an allowed folder that points outside it will pass. Pair this with the server's own root restriction.
- **Regex and prefix rules only see the arguments you name.** A tool that takes a path under a different argument name, or inside a nested object, isn't checked unless you add a rule for it. An allowlist of tools is the stronger control.
- **Redaction is pattern-based.** It misses secrets that don't look like secrets (a random password in a plain `"value"` field, an unknown vendor's key format). Add `redact.extra_patterns` for your own formats.
- **Redaction rewrites outbound arguments.** A tool that legitimately takes a password, or a write tool whose content contains a key, receives `[REDACTED:…]` instead. Turn redaction off for that server if this is a problem; the audit log is redacted either way.
- **Path rules assume POSIX paths** (prefixes must be absolute; backslashes are treated as separators).
- **Only one upstream server per proxy, and stdio only** (no Streamable HTTP).
- **Rate-limit state is in memory** and resets when the client restarts the proxy.
- **Only tool calls are policed.** Other results (`resources/read`, `prompts/get`) are redacted but not scanned for injection, and server-initiated requests (sampling, elicitation in older protocol revisions) pass through untouched.

## License

MIT. The redaction patterns are adapted from [`offload/credentials.py`](https://github.com/oguzhanozfe/llm-offload/blob/main/offload/credentials.py) in llm-offload (MIT).
