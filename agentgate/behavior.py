#!/usr/bin/env python3
"""Behaviour baselines for agent_gate: does this session look like the real account holder?

IMPORTANT LIMITS
  * Behaviour is not intent. A genuine customer can still ask for something harmful; this layer only
    detects account takeover, probing and coordinated abuse, and responds with STEP-UP verification
    (never an outright block), because anomalies often have innocent causes (new phone, travel).
  * New accounts have no baseline, attackers can mimic habits, and profiling raises privacy duties:
    keep retention short, store hashes, and document it.

Anti-poisoning (v1.2): the baseline learns ONLY from clean requests. A device or hour that triggered a flag is
not "known" just because it was seen once; a new device becomes trusted after repeated use over >= 24h
(slow trust) or when the owner re-verifies. Otherwise an attacker simply uses the stolen session twice.
"""
from __future__ import annotations
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from ._util import LRUDict, atomic_write_json, read_json

MAX_EVENTS = 500


@dataclass
class Assessment:
    score: float
    flags: List[str]
    recommend: str      # none | log | step_up


class BehaviorMonitor:
    def __init__(self, min_history=10, burst_limit=20, burst_window=600, probe_window=1800, probe_count=4,
                 shared_infra_limit=3, infra_window=86400, step_up_at=0.55, log_at=0.35,
                 trust_after=86400, trust_sightings=3, max_accounts=100_000):
        self.min_history, self.burst_limit, self.burst_window = min_history, burst_limit, burst_window
        self.probe_window, self.probe_count = probe_window, probe_count
        self.shared_infra_limit, self.infra_window = shared_infra_limit, infra_window
        self.step_up_at, self.log_at = step_up_at, log_at
        self.trust_after, self.trust_sightings = trust_after, trust_sightings
        self.events = LRUDict(list, max_accounts)        # op -> [[ts, device, flagged, clean], ...]
        self.trusted = LRUDict(dict, max_accounts)       # op -> {device: first_trusted_ts}
        self.hours = LRUDict(lambda: [0] * 24, max_accounts)
        self.pending = LRUDict(dict, max_accounts)       # op -> {device: [first_ts, sightings]}
        self.cleared = LRUDict(float, max_accounts)
        self.infra = LRUDict(list, max_accounts * 2)     # device/ip -> [[ts, operator], ...]

    # -- helpers
    def _known(self, operator):
        return {e[1] for e in self.events.get(operator, []) if e[3]} | set(self.trusted.get(operator, {}))

    @staticmethod
    def _clean(a) -> bool:
        return a is None or not [f for f in a.flags if f != "cold-start"]

    def assess(self, operator: str, ts: float, device: str = "", ip: str = "") -> Assessment:
        hist = [e for e in self.events.get(operator, []) if e[0] < ts]
        warm = len(hist) >= self.min_history
        flags, score = [], 0.0

        def add(w, name):
            nonlocal score
            score += w
            flags.append(name)

        if not warm:
            add(0.15, "cold-start")
        if warm and device and device not in self._known(operator):
            add(0.35, "new-device")
        if warm:
            hrs = self.hours.get(operator) or [0] * 24
            seen = [x for x in range(24) if hrs[x]]
            h = int(ts // 3600) % 24
            if seen and min(min((h - x) % 24, (x - h) % 24) for x in seen) > 1:
                add(0.2, "unusual-hour")
        since = self.cleared.get(operator, 0.0)
        live = [e for e in hist if e[0] >= since]
        if 1 + sum(1 for e in live if e[0] > ts - self.burst_window) >= self.burst_limit:
            add(0.25, "burst")
        if sum(1 for e in live if e[2] and e[0] > ts - self.probe_window) >= self.probe_count:
            add(0.45, "probing")
        if warm:
            recent, older = hist[-20:], hist[:-20]
            if older and sum(e[2] for e in recent) / len(recent) >= 0.3 and sum(e[2] for e in older) / len(older) <= 0.05:
                add(0.25, "topic-drift")
        if device and self._others(device, operator, ts) >= self.shared_infra_limit:
            add(0.45, "shared-device")
        if ip and self._others(ip, operator, ts) >= self.shared_infra_limit:
            add(0.2, "shared-ip")          # weak: NAT/offices share IPs legitimately
        score = round(min(score, 1.0), 2)
        rec = "step_up" if score >= self.step_up_at else "log" if score >= self.log_at else "none"
        return Assessment(score, flags, rec)

    def record(self, operator, ts, device="", ip="", flagged=False, assessment=None):
        a = assessment if assessment is not None else self.assess(operator, ts, device, ip)
        clean = (not flagged) and self._clean(a)
        ev = self.events[operator]
        ev.append([ts, device, bool(flagged), clean])
        if len(ev) > MAX_EVENTS:
            del ev[:len(ev) - MAX_EVENTS]
        if clean:
            self.hours[operator][int(ts // 3600) % 24] += 1
        elif not flagged and device and a.flags and set(a.flags) <= {"new-device", "cold-start"} and "new-device" in a.flags:
            p = self.pending[operator].setdefault(device, [ts, 0])     # slow trust: repeated use over time
            p[1] += 1
            if p[1] >= self.trust_sightings and ts - p[0] >= self.trust_after:
                self.trusted[operator][device] = ts
                self.pending[operator].pop(device, None)
        cutoff = ts - self.infra_window
        for k in (device, ip):
            if k:
                lst = self.infra[k]
                lst.append([ts, operator])
                if len(lst) > 200 or (lst and lst[0][0] < cutoff):
                    lst[:] = [x for x in lst if x[0] >= cutoff][-200:]

    def trust_device(self, operator, device, ts=None):
        if device:
            self.trusted[operator][device] = ts if ts is not None else time.time()

    def verify(self, operator, device="", ts=0.0):
        """Owner re-authenticated: trust the device, credit the hour, reset burst/probe windows."""
        if device:
            self.trusted[operator][device] = ts
        self.hours[operator][int(ts // 3600) % 24] += 1
        self.cleared[operator] = ts

    def _others(self, key, operator, ts):
        return len({o for t, o in self.infra.get(key, []) if t > ts - self.infra_window and o != operator})

    # -- persistence
    def snapshot(self) -> dict:
        return {"events": dict(self.events), "trusted": dict(self.trusted), "hours": dict(self.hours),
                "pending": dict(self.pending), "cleared": dict(self.cleared), "infra": dict(self.infra)}

    def restore(self, d: dict) -> None:
        for name in ("events", "trusted", "hours", "pending", "cleared", "infra"):
            tgt = getattr(self, name)
            tgt.clear()
            for k, v in (d.get(name) or {}).items():
                tgt[k] = v

    def save(self, path: str) -> None:
        atomic_write_json(path, self.snapshot())

    def load(self, path: str) -> None:
        d = read_json(path, None)
        if d:
            self.restore(d)


def backtest(log_path: str, monitor: BehaviorMonitor = None) -> dict:
    """Replay a historical audit log through the monitor to see what it WOULD have flagged."""
    m = monitor or BehaviorMonitor()
    tally = defaultdict(int)
    flagged_ops = defaultdict(int)
    with open(log_path) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict) or r.get("kind", "REQUEST") != "REQUEST":
                continue
            a = m.assess(r["operator"], r["ts"], r.get("device", ""), r.get("ip", ""))
            tally["requests"] += 1
            tally[a.recommend] += 1
            if a.recommend != "none":
                flagged_ops[r["operator"]] += 1
            for fl in a.flags:
                tally["flag:" + fl] += 1
            m.record(r["operator"], r["ts"], r.get("device", ""), r.get("ip", ""),
                     flagged=r["action"] in ("BLOCK", "ESCALATE") or "uncertain" in r.get("categories", []), assessment=a)
    return {"counts": dict(tally), "top_operators": sorted(flagged_ops.items(), key=lambda kv: -kv[1])[:5]}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "backtest":
        print(json.dumps(backtest(sys.argv[2]), indent=2))
    else:
        sys.exit("usage: behavior.py backtest gate_audit.jsonl")
