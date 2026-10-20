"""Threshold calibration from YOUR audit log: how much friction would each step-up threshold create?"""
from __future__ import annotations
import json
from collections import defaultdict
from typing import Iterable

DEFAULT = (0.35, 0.45, 0.55, 0.65, 0.75)


def calibrate(log_path: str, thresholds: Iterable[float] = DEFAULT) -> dict:
    """Reads the per-request `risk` (behaviour) and `transport.score` values the gate wrote, and reports for each
    threshold the share of requests and number of accounts that would be stepped up. Use on a period of normal
    traffic to choose thresholds with an acceptable false-positive rate."""
    thresholds = list(thresholds)
    total = 0
    values = {"behavior": [], "transport": []}
    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict) or r.get("kind", "REQUEST") != "REQUEST":
                continue
            total += 1
            if "risk" in r:
                values["behavior"].append((r["operator"], r["risk"]))
            if isinstance(r.get("transport"), dict):
                values["transport"].append((r["operator"], r["transport"]["score"]))
    out = {"requests_total": total}
    for src, rows in values.items():
        table = {}
        for t in thresholds:
            hit = [op for op, s in rows if s >= t]
            table[t] = {"requests": len(hit), "share": round(len(hit) / len(rows), 4) if rows else 0.0,
                        "accounts": len(set(hit))}
        out[src] = {"observed": len(rows), "thresholds": table}
    return out


def format_table(result: dict) -> str:
    lines = [f"requests in log: {result['requests_total']}"]
    for src in ("behavior", "transport"):
        d = result[src]
        lines.append(f"\n{src} (observed on {d['observed']} requests)\n  threshold  requests  share   accounts")
        for t, v in d["thresholds"].items():
            lines.append(f"  {t:>9}  {v['requests']:>8}  {100 * v['share']:>5.1f}%  {v['accounts']:>8}")
    return "\n".join(lines)
