# Detection results

Produced by `python eval/measure.py` (tables below are its verbatim output). Model verdicts come from `eval/runs/classifier_cache.jsonl`, written by `python eval/measure.py --run-model heldout gemini <model>`.

## Data

| set | file(s) | items | written by | used for |
|---|---|---|---|---|
| dev | `dev_hand.jsonl` | 39 | the rule author (an AI coding agent) | tuning |
| dev | `dev_qwen.jsonl` (raw: `dev_qwen_raw.jsonl`) | 72 | `qwen3.5:9b` via Ollama (digest `56671c2ab938`), labels reviewed by the rule author | tuning (this was the round-1 held-out set; it moved to dev once its misses had been read) |
| dev | `dev_extra.jsonl` | 120 | a Claude Sonnet subagent | tuning |
| held-out | `heldout_v2.jsonl` | 160 | a separate Claude Sonnet subagent, told not to read the detector | measurement only; never opened by the rule author, `measure.py` refuses to print its items |

## History

- Round 1 (rules tuned on `dev_hand` only): on the `qwen3.5:9b` set, precision 1.00 / recall 0.18.
- Round 2: text normalisation (invisible characters removed, NFKC, Cyrillic/Greek look-alikes folded, base64/hex decoded) and new rule families, tuned on the 231-item dev set. First held-out run at the default threshold: precision 0.90 / recall 0.68.
- After that run, one change: `suspicious_url` no longer double-counts templated query parameters already scored by `url_placeholder` (found by a unit test with an API-docs URL, not by a held-out miss). Held-out recall at the default threshold went 0.68 → 0.66; the tables below are after the change. No rule was changed in response to held-out results.
- Classifier lane: `gemini-3.1-flash-lite` answered all 40 sample items (2026-11-17). `gemma-4-31b-it` was attempted the same day and produced no answers (HTTP 503, timeouts, dropped connections).

## Current run

### dev: heuristics, all 231 items

| lane | n | TP | FP | FN | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| heuristics (score >= 1) | 231 | 101 | 46 | 5 | 79 | 0.69 | 0.95 | 0.80 |
| heuristics (score >= 2) [default] | 231 | 94 | 0 | 12 | 125 | 1.00 | 0.89 | 0.94 |
| heuristics (score >= 3) | 231 | 64 | 0 | 42 | 125 | 1.00 | 0.60 | 0.75 |
| heuristics (score >= 4) | 231 | 39 | 0 | 67 | 125 | 1.00 | 0.37 | 0.54 |

### heldout: heuristics, all 160 items

| lane | n | TP | FP | FN | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| heuristics (score >= 1) | 160 | 72 | 42 | 8 | 38 | 0.63 | 0.90 | 0.74 |
| heuristics (score >= 2) [default] | 160 | 53 | 6 | 27 | 74 | 0.90 | 0.66 | 0.76 |
| heuristics (score >= 3) | 160 | 36 | 2 | 44 | 78 | 0.95 | 0.45 | 0.61 |
| heuristics (score >= 4) | 160 | 18 | 0 | 62 | 80 | 1.00 | 0.23 | 0.37 |

### heldout: all lanes on the fixed sample (40 items, 2 per label x category); a model row with n < 40 has unanswered items

| lane | n | TP | FP | FN | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| heuristics (score >= 1) | 40 | 17 | 8 | 3 | 12 | 0.68 | 0.85 | 0.76 |
| heuristics (score >= 2) [default] | 40 | 14 | 0 | 6 | 20 | 1.00 | 0.70 | 0.82 |
| heuristics (score >= 3) | 40 | 9 | 0 | 11 | 20 | 1.00 | 0.45 | 0.62 |
| heuristics (score >= 4) | 40 | 6 | 0 | 14 | 20 | 1.00 | 0.30 | 0.46 |
| model gemini-3.1-flash-lite | 40 | 20 | 0 | 0 | 20 | 1.00 | 1.00 | 1.00 |
| either (heuristics OR gemini-3.1-flash-lite) | 40 | 20 | 0 | 0 | 20 | 1.00 | 1.00 | 1.00 |

- `gemini-3.1-flash-lite`: 40 cached calls, latency median 1304 ms, p90 2165 ms, max 3435 ms

Heuristics per category, all 160 items (injected: share caught; benign: share wrongly flagged):

| label | category | n | flagged |
|---|---|---|---|
| benign | base64_legit | 8 | 0.00 |
| benign | code_config | 8 | 0.00 |
| benign | hidden_html_legit | 8 | 0.12 |
| benign | human_imperatives | 8 | 0.12 |
| benign | misc_data | 8 | 0.00 |
| benign | non_english_benign | 8 | 0.00 |
| benign | security_writeup | 8 | 0.38 |
| benign | support_email | 8 | 0.00 |
| benign | tool_docs | 8 | 0.12 |
| benign | urls_with_params | 8 | 0.00 |
| injected | as_assistant | 8 | 1.00 |
| injected | code_comment | 8 | 0.62 |
| injected | encoded | 8 | 0.62 |
| injected | exfil_url | 8 | 0.75 |
| injected | hidden_markup | 8 | 0.75 |
| injected | indirect | 8 | 0.38 |
| injected | non_english | 8 | 0.62 |
| injected | polite_paraphrase | 8 | 0.12 |
| injected | tool_forgery | 8 | 0.75 |
| injected | unicode_tricks | 8 | 1.00 |
