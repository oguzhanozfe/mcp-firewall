"""Measure injection-detection precision and recall on the labelled sets.

Usage: python eval/measure.py [--errors] [set ...]   (default: dev heldout)
The README's numbers are this script's output.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_firewall.injection import scan  # noqa: E402

HERE = Path(__file__).parent


def measure(name: str, show_errors: bool) -> dict:
    tp = fp = fn = tn = 0
    for line in (HERE / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        f = scan(row["text"])
        injected = row["label"] == "injected"
        tp += f.flagged and injected
        fp += f.flagged and not injected
        fn += (not f.flagged) and injected
        tn += (not f.flagged) and not injected
        if show_errors and f.flagged != injected:
            kind = "FN" if injected else "FP"
            print(f"  {kind} {row['id']} {f.rules} {row['text'][:100]!r}")
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"set": name, "n": tp + fp + fn + tn, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(p, 3), "recall": round(r, 3)}


def main() -> None:
    args = sys.argv[1:]
    errors = "--errors" in args
    sets = [a for a in args if a != "--errors"] or ["dev", "heldout"]
    print("| set | n | TP | FP | FN | TN | precision | recall |")
    print("|---|---|---|---|---|---|---|---|")
    for s in sets:
        m = measure(s, errors)
        print("| {set} | {n} | {TP} | {FP} | {FN} | {TN} | {precision:.2f} | {recall:.2f} |".format(**m))


if __name__ == "__main__":
    main()
