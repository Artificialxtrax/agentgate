"""Tripwires: signals that are traceable and almost never innocent.

1. HoneyTokens   - unique fake secrets planted where only an intruder (or a hijacked agent) would look.
                   Each token is unique per placement, so a hit tells you EXACTLY which store leaked.
                   The registry stores only hashes. A real owner has no reason to ever use one.
2. ReconDetector - attackers explore before they act: many resources the account has never touched.
3. TypingMonitor - keystroke timing: scripted/injected/pasted input is machine-regular; remote-control
                   or a different person shifts the rhythm. CLIENT-SUPPLIED and spoofable (an attacker
                   can replay recorded timings): a speed bump and a correlating signal, never proof.

Honest limit: a patient attacker who does only what the owner normally does, touches no decoys and
types like a human is not caught by this module. Layer it with device signing and the content policy.
"""
from __future__ import annotations
import hashlib, json, math, re, secrets, statistics, unicodedata, urllib.parse
from typing import Dict, List, Optional, Set

from ._util import LRUDict, atomic_write_json, read_json

TOKEN_RE = re.compile(r"hx-[a-z0-9]{3,12}-[a-f0-9]{24}", re.I)
_STRIP = {"Cf", "Cc", "Cs", "Co", "Mn"}


def _canon(t: str) -> str:
    t = unicodedata.normalize("NFKC", t)
    return "".join(c for c in t if unicodedata.category(c) not in _STRIP).lower()


class HoneyTokens:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.tokens = read_json(path, {}) if path else {}      # sha256(token) -> {"placement","kind"}

    def issue(self, placement: str, kind: str = "api-key") -> str:
        """Plant the returned string in a decoy file / env var / doc / DB row. Never reuse across places."""
        slug = re.sub(r"[^a-z0-9]", "", placement.lower())[:12]
        slug = (slug + "xxx")[:12] if len(slug) < 3 else slug
        tok = f"hx-{slug}-{secrets.token_hex(12)}"
        self.tokens[hashlib.sha256(tok.encode()).hexdigest()] = {"placement": placement, "kind": kind}
        self._save()
        return tok

    def scan(self, text: str) -> List[dict]:
        """Finds tokens even when upper-cased, split by zero-width characters, full-width, or URL-encoded."""
        if not isinstance(text, str):
            return []
        views = {_canon(text)}
        try:
            views.add(_canon(urllib.parse.unquote(text)))
        except Exception:
            pass
        hits, seen = [], set()
        for v in views:
            for m in TOKEN_RE.findall(v):
                m = m.lower()
                rec = self.tokens.get(hashlib.sha256(m.encode()).hexdigest())
                if rec and m not in seen:
                    seen.add(m)
                    hits.append(dict(rec, token_prefix=m[:10]))
        return hits

    def _save(self):
        if self.path:
            atomic_write_json(self.path, self.tokens)


class ReconDetector:
    """Flags a burst of first-time resource accesses by an account with an established history."""
    def __init__(self, min_history=15, window=1800, novel_min=8, novel_ratio=0.7, min_age=2 * 86400,
                 max_accounts=100_000, max_resources=5000):
        self.min_age, self.max_resources = min_age, max_resources
        self.first = LRUDict(None, max_accounts)
        self.min_history, self.window, self.novel_min, self.novel_ratio = min_history, window, novel_min, novel_ratio
        self.seen = LRUDict(dict, max_accounts)                  # op -> {resource: 1} (insertion-ordered, capped)
        self.recent = LRUDict(list, max_accounts)                # op -> [[ts, resource, novel]]

    def observe(self, operator: str, resource: str, ts: float) -> Optional[str]:
        if not isinstance(resource, str):
            return None
        resource = resource[:512]
        self.first.setdefault(operator, ts)
        seen = self.seen[operator]
        warm = len(seen) >= self.min_history and ts - self.first[operator] >= self.min_age
        novel = resource not in seen
        r = [e for e in self.recent[operator] if e[0] > ts - self.window] + [[ts, resource, novel]]
        self.recent[operator] = r[-200:]
        seen[resource] = 1
        while len(seen) > self.max_resources:
            seen.pop(next(iter(seen)))
        if not warm:
            return None
        nov = sum(1 for e in r if e[2])
        if nov >= self.novel_min and nov / len(r) >= self.novel_ratio:
            return f"recon: {nov} first-time resources in {len(r)} accesses"
        return None

    def save(self, path: str) -> None:
        atomic_write_json(path, {"first": dict(self.first), "seen": {k: list(v) for k, v in self.seen.items()},
                                 "recent": dict(self.recent)})

    def load(self, path: str) -> None:
        d = read_json(path, None)
        if d:
            for k, v in d.get("first", {}).items(): self.first[k] = v
            for k, v in d.get("seen", {}).items(): self.seen[k] = {x: 1 for x in v}
            for k, v in d.get("recent", {}).items(): self.recent[k] = v


class TypingMonitor:
    def __init__(self, min_keys=15, bot_cv=0.12, z_limit=4.0):
        self.min_keys, self.bot_cv, self.z_limit = min_keys, bot_cv, z_limit
        self.profiles: Dict[str, tuple] = {}

    MAX_KEYS = 500

    @classmethod
    def _valid(cls, iv):
        """Return a clean list of finite, non-negative numbers, or None if the data is malformed."""
        if not isinstance(iv, (list, tuple)):
            return None
        iv = list(iv)[-cls.MAX_KEYS:]
        if not all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and 0 <= x < 1e7 for x in iv):
            return None
        return [float(x) for x in iv]

    @staticmethod
    def _stats(iv):
        logs = [math.log(max(x, 1.0)) for x in iv]
        return statistics.mean(logs), (statistics.pstdev(logs) or 0.01)

    def enroll(self, operator: str, intervals_ms: List[float]):
        intervals_ms = self._valid(intervals_ms)
        if intervals_ms is None:
            raise ValueError("intervals must be a list of finite, non-negative numbers")
        if len(intervals_ms) >= self.min_keys:
            self.profiles[operator] = self._stats(intervals_ms)

    def check(self, operator: str, intervals_ms: List[float], pasted: bool = False):
        if pasted:
            return "automated", "paste/injected input"
        intervals_ms = self._valid(intervals_ms)
        if intervals_ms is None:
            return "automated", "malformed timing data"
        if len(intervals_ms) < self.min_keys:
            return "insufficient", ""
        mean = statistics.mean(intervals_ms)
        cv = statistics.pstdev(intervals_ms) / mean if mean else 0
        if mean < 20 or cv < self.bot_cv:
            return "automated", f"machine-regular timing (mean {mean:.0f}ms, cv {cv:.2f})"
        prof = self.profiles.get(operator)
        if prof:
            mu, sd = self._stats(intervals_ms)
            z = abs(mu - prof[0]) / prof[1] * math.sqrt(len(intervals_ms))
            if z > self.z_limit:
                return "mismatch", f"rhythm differs from enrolled profile (z={z:.1f})"
        return "human", ""
