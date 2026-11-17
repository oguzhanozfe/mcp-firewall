"""Measure injection detection per lane.

  python eval/measure.py                      # tables for dev and heldout (from committed runs)
  python eval/measure.py --errors dev         # list dev misses (refused for heldout: it is blind)
  python eval/measure.py --run-model heldout gemini gemini-3.1-flash-lite
                                              # classify the held-out sample, cache in eval/runs/

Lanes: heuristics at score thresholds 1-4 (2 is the shipped default), each
model classifier, and "either" (heuristics at 2 OR model), which is what the
proxy does when the classifier is enabled. Free-tier quotas (~20 requests per
model per day) cannot cover the full set, so model lanes run on a fixed
stratified sample (SAMPLE_PER_CELL items per label x category, chosen by
hashing the item id) and the heuristics are also reported on that sample.
Every model response is cached on disk by a hash of (model, prompt, text), so
re-running costs nothing. The README's numbers are this
script's output, saved in eval/results.md.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_firewall.classifier import Classifier, cache_key  # noqa: E402
from mcp_firewall.injection import THRESHOLD, scan  # noqa: E402

HERE = Path(__file__).parent
SETS = {"dev": ["dev_hand", "dev_qwen", "dev_extra"], "heldout": ["heldout_v2"]}
BLIND = {"heldout"}
SAMPLE_PER_CELL = 2
CACHE = HERE / "runs" / "classifier_cache.jsonl"


def load_cache() -> dict[str, dict]:
    if not CACHE.exists():
        return {}
    return {r["key"]: r for r in map(json.loads, CACHE.read_text().splitlines()) if r.get("verdict") is not None}


def sample(name: str) -> list[dict]:
    cells: dict[tuple, list] = defaultdict(list)
    for r in rows(name):
        cells[(r["label"], r.get("category", ""))].append(r)
    out = []
    for cell in sorted(cells):
        out += sorted(cells[cell], key=lambda r: hashlib.sha256(r["id"].encode()).hexdigest())[:SAMPLE_PER_CELL]
    return out


def rows(name: str) -> list[dict]:
    out = []
    for f in SETS[name]:
        path = HERE / f"{f}.jsonl"
        if path.exists():
            out += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return out


def score(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(p and t for p, t in pairs)
    fp = sum(p and not t for p, t in pairs)
    fn = sum(t and not p for p, t in pairs)
    tn = len(pairs) - tp - fp - fn
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    return {"n": len(pairs), "TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if tp else 0.0}


def lanes(name: str, data: list[dict]) -> dict[str, list[tuple[bool, bool, dict]]]:
    cache = load_cache()
    models = sorted({c["model"] for c in cache.values()})
    out: dict[str, list] = defaultdict(list)
    for r in data:
        truth = r["label"] == "injected"
        f = scan(r["text"])
        for t in (1, 2, 3, 4):
            out[f"heuristics (score >= {t})" + (" [default]" if t == THRESHOLD else "")].append((f.score >= t, truth, r))
        for m in models:
            c = cache.get(cache_key(m, r["text"]))
            if c:
                out[f"model {m}"].append((c["verdict"], truth, r))
                out[f"either (heuristics OR {m})"].append((f.score >= THRESHOLD or c["verdict"], truth, r))
    return out


def print_lanes(out: dict, title: str, only_complete: bool = False) -> None:
    print(f"\n{title}\n")
    print("| lane | n | TP | FP | FN | TN | precision | recall | F1 |")
    print("|---|---|---|---|---|---|---|---|---|")
    n_max = max(len(v) for v in out.values())
    for lane, items in out.items():
        if only_complete and len(items) < n_max:
            continue
        s = score([(p, t) for p, t, _ in items])
        print(f"| {lane} | {s['n']} | {s['TP']} | {s['FP']} | {s['FN']} | {s['TN']} | {s['precision']:.2f} | {s['recall']:.2f} | {s['f1']:.2f} |")


def table(name: str) -> None:
    data = rows(name)
    out = lanes(name, data)
    print_lanes({k: v for k, v in out.items() if k.startswith("heuristics")}, f"### {name}: heuristics, all {len(data)} items")
    if any(k.startswith("model") for k in out):
        smp = sample(name)
        print_lanes(lanes(name, smp), f"### {name}: all lanes on the fixed sample ({len(smp)} items, "
                    f"{SAMPLE_PER_CELL} per label x category); a model row with n < {len(smp)} has unanswered items")
        cache = load_cache()
        for m in sorted({c["model"] for c in cache.values()}):
            lat = sorted(c["latency_ms"] for c in cache.values() if c["model"] == m)
            print(f"\n- `{m}`: {len(lat)} cached calls, latency median {statistics.median(lat):.0f} ms, "
                  f"p90 {lat[int(0.9 * (len(lat) - 1))]:.0f} ms, max {lat[-1]:.0f} ms")
    if "category" in (data or [{}])[0]:
        default = next(k for k in out if "[default]" in k)
        cats: dict[tuple, list] = defaultdict(list)
        for p, t, r in out[default]:
            cats[(r["label"], r.get("category", "?"))].append(p)
        print(f"\nHeuristics per category, all {len(data)} items (injected: share caught; benign: share wrongly flagged):\n")
        print("| label | category | n | flagged |")
        print("|---|---|---|---|")
        for (label, cat), v in sorted(cats.items()):
            print(f"| {label} | {cat} | {len(v)} | {sum(v) / len(v):.2f} |")


def errors(name: str) -> None:
    if name in BLIND:
        sys.exit(f"refusing to print {name} items: it is the blind set. Use the aggregate table.")
    for r in rows(name):
        f = scan(r["text"])
        if f.flagged != (r["label"] == "injected"):
            kind = "FN" if r["label"] == "injected" else "FP"
            print(f"  {kind} {r['id']} {r.get('category', '')} {f.rules} {r['text'][:110]!r}")


def run_model(name: str, provider: str, model: str) -> None:
    """Classify the fixed sample, one call at a time, appending each answer to the cache.
    Stops at the first 429 (daily quota) instead of looping; retries a 503 twice."""
    clf = Classifier(provider=provider, model=model, timeout_s=90)
    cache = load_cache()
    CACHE.parent.mkdir(exist_ok=True)
    todo = [r for r in sample(name) if cache_key(clf.model, r["text"]) not in cache]
    print(f"{clf.model}: {len(todo)} items to classify", file=sys.stderr)
    for n, r in enumerate(todo):
        for attempt in range(3):
            try:
                verdict, ms = clf.classify(r["text"])
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    sys.exit(f"{clf.model}: quota exhausted (429) after {n} of {len(todo)}; cached answers kept")
                if e.code == 503 and attempt < 2:
                    time.sleep(20)
                    continue
                print(f"{r['id']}: HTTP {e.code}, skipped", file=sys.stderr)
                break
            except OSError as e:  # dropped connection or timeout: transient on the free tier
                if attempt < 2:
                    time.sleep(20)
                    continue
                print(f"{r['id']}: {type(e).__name__}, skipped", file=sys.stderr)
                break
            except (ValueError, KeyError) as e:
                print(f"{r['id']}: {type(e).__name__}, skipped", file=sys.stderr)
                break
            with CACHE.open("a") as f:
                f.write(json.dumps({"key": cache_key(clf.model, r["text"]), "model": clf.model, "provider": provider,
                                    "id": r["id"], "verdict": verdict, "latency_ms": round(ms, 1),
                                    "date": time.strftime("%Y-%m-%d")}) + "\n")
            break
        time.sleep(4)  # stay under per-minute limits


def main() -> None:
    a = sys.argv[1:]
    if a[:1] == ["--run-model"]:
        return run_model(a[1], a[2] if len(a) > 2 else "gemini", a[3] if len(a) > 3 else "gemini-3.1-flash-lite")
    if a[:1] == ["--errors"]:
        return errors(a[1] if len(a) > 1 else "dev")
    for name in a or ["dev", "heldout"]:
        table(name)


if __name__ == "__main__":
    main()
