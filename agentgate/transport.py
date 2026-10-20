"""Transport fingerprints: the 'oddball out' signal for a stolen session.

A copied token carries none of the machinery that sent it. Every request also has a client fingerprint
(TLS handshake pattern e.g. JA3/JA4 computed by your edge/proxy, HTTP header ORDER, user agent), a network
type, and a coarse location. For each (operator, device) we learn the real client's fingerprint, then flag:
  fp-new-for-device   same device id, but a client stack never seen with it
  automation-client   HTTP library / headless browser for an account that only ever used a real browser
  hosting-network     datacenter/VPN/Tor for an account that is normally residential/mobile
  impossible-travel   location change faster than a plane
  concurrent-clients  two different client stacks alternating on one device id within minutes
Responses are STEP-UP (re-verify), never block: browser updates and VPNs have innocent causes.

Anti-poisoning: the baseline only learns from CLEAN requests (score < log threshold) or after the user
re-verifies, so an attacker cannot teach the system their own fingerprint.

Honest limits: an attacker who fully impersonates the client (TLS impersonation libraries, same header
order, residential proxy in the owner's city) is NOT caught here, and neither is malware running inside the
owner's own browser. This raises attacker cost; it is not proof of identity. Needs an edge that supplies
the TLS fingerprint and geo/ASN data.
meta keys: asn (ISP/AS number from your edge), sensitive (bool: export, change destination, run privileged tool), device, tls, headers (list, in order), ua, geo=(lat, lon), net in {residential,mobile,hosting,vpn,tor}
"""
from __future__ import annotations
import hashlib, json, math, re
from dataclasses import dataclass
from typing import Dict, List

from ._util import AMBIGUOUS, LRUDict, atomic_write_json, is_raw_ip, normalise_host, read_json

AUTOMATION = re.compile(r"python-requests|python-urllib|aiohttp|httpx|curl/|wget|go-http-client|libwww|axios|"
                        r"node-fetch|headlesschrome|selenium|playwright|puppeteer|phantomjs|scrapy", re.I)
SUSPECT_NET = {"hosting", "vpn", "tor"}


@dataclass
class TAssessment:
    score: float
    flags: List[str]
    recommend: str


def _s(v) -> str:
    return v if isinstance(v, str) else ""


def _hdrs(meta) -> list:
    h = meta.get("headers")
    return [x for x in h if isinstance(x, str)] if isinstance(h, (list, tuple)) else []


def fingerprint(meta: dict) -> str:
    ua = re.sub(r"\d+", "#", _s(meta.get("ua")).lower())      # tolerate browser auto-updates
    hdr = ",".join(h.lower() for h in _hdrs(meta))
    return hashlib.sha256(f"{_s(meta.get('tls'))}|{hdr}|{ua}".encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _is_auto(meta) -> bool:
    return bool(AUTOMATION.search(f"{_s(meta.get('ua'))} {_s(meta.get('tls'))}"))


def _geo(meta):
    g = meta.get("geo")
    if (isinstance(g, (list, tuple)) and len(g) == 2
            and all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in g)):
        return (float(g[0]), float(g[1]))
    return None


def haversine_km(a, b) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


class TransportMonitor:
    def __init__(self, min_history=5, concurrent_window=300, max_kmh=900, step_up_at=0.55, learn_below=0.35,
                 sensitive_at=0.35, asn_trust_age=86400, asn_trust_count=3, max_accounts=100_000):
        self.sensitive_at, self.asn_trust_age, self.asn_trust_count = sensitive_at, asn_trust_age, asn_trust_count
        self.asns = LRUDict(set, max_accounts)
        self.asn_n = LRUDict(int, max_accounts)
        self.pending = LRUDict(dict, max_accounts)
        self.min_history, self.concurrent_window = min_history, concurrent_window
        self.max_kmh, self.step_up_at, self.learn_below = max_kmh, step_up_at, learn_below
        self.dev = LRUDict(dict, max_accounts * 2)                      # (op, device) -> {fp: count}
        self.kinds = LRUDict(lambda: {"auto": 0, "human": 0, "suspect_net": 0, "net": 0, "vpn": 0}, max_accounts)
        self.last = LRUDict(None, max_accounts)                         # op -> (ts, fp, device, geo)

    def assess(self, operator: str, ts: float, meta: dict) -> TAssessment:
        meta = meta or {}
        fp, device, flags, score = fingerprint(meta), _s(meta.get("device")), [], 0.0

        def add(w, n):
            nonlocal score
            score += w
            flags.append(n)

        seen = self.dev.get((operator, device)) or {}
        established = sum(seen.values()) >= self.min_history
        if established and fp not in seen:
            add(0.4, "fp-new-for-device")
        k = self.kinds.get(operator) or {"auto": 0, "human": 0, "suspect_net": 0, "net": 0, "vpn": 0}
        if _is_auto(meta) and k["human"] >= self.min_history and k["auto"] == 0:
            add(0.4, "automation-client")
        if meta.get("net") in SUSPECT_NET and k["net"] >= self.min_history and k["suspect_net"] / k["net"] < 0.2:
            add(0.2, "hosting-network")
        asn = _s(meta.get("asn"))
        if asn and self.asn_n.get(operator, 0) >= self.min_history and asn not in (self.asns.get(operator) or ()):
            add(0.35, "new-asn")
        last = self.last.get(operator)
        if last:
            lts, lfp, ldev, lgeo = last
            geo = _geo(meta)
            vpn_ok = meta.get("net") == "vpn" and k["vpn"] > 0       # owner is a known VPN user: exit-node jumps are normal
            if geo and lgeo and ts > lts and not vpn_ok:
                km = haversine_km(lgeo, geo)
                if km > 300 and km / max((ts - lts) / 3600, 1e-6) > self.max_kmh:
                    add(0.6, "impossible-travel")
            if lfp != fp and ldev == device and 0 <= ts - lts < self.concurrent_window and lfp in seen:
                add(0.45, "concurrent-clients")
        score = round(min(score, 1.0), 2)
        thr = self.sensitive_at if (meta.get("sensitive") or meta.get("sensitive_action")) else self.step_up_at   # weak signals matter more for risky actions
        return TAssessment(score, flags, "step_up" if score >= thr else "log" if score >= self.learn_below else "none")

    def record(self, operator: str, ts: float, meta: dict, a: TAssessment, force: bool = False) -> None:
        meta = meta or {}
        fp, device = fingerprint(meta), _s(meta.get("device"))
        if a.score < self.learn_below or force:            # never learn from suspicious requests
            seen = self.dev[(operator, device)]
            seen[fp] = seen.get(fp, 0) + 1
            k = self.kinds[operator]
            k["auto" if _is_auto(meta) else "human"] += 1
            if meta.get("net"):
                k["net"] += 1
                k["suspect_net"] += meta["net"] in SUSPECT_NET
                k["vpn"] += meta["net"] == "vpn"
            if _s(meta.get("asn")):
                self.asns[operator].add(meta["asn"])
                self.asn_n[operator] += 1
        elif _s(meta.get("asn")) and a.flags == ["new-asn"]:      # a new provider alone: trust only after sustained, repeated use
            p = self.pending[(operator, meta["asn"])]
            first = p.setdefault("first", ts)
            p["n"] = p.get("n", 0) + 1
            if p["n"] >= self.asn_trust_count and ts - first >= self.asn_trust_age:
                self.asns[operator].add(meta["asn"])
        self.last[operator] = (ts, fp, device, _geo(meta))

    def verify(self, operator: str, meta: dict, ts: float = 0.0) -> None:
        """Call after real re-authentication: trust this client from now on."""
        self.record(operator, ts, meta, TAssessment(0, [], "none"), force=True)

    def snapshot(self) -> dict:
        return {"asns": {k: sorted(v) for k, v in self.asns.items()}, "asn_n": dict(self.asn_n),
                "dev": {json.dumps(k): v for k, v in self.dev.items()}, "kinds": dict(self.kinds),
                "last": {k: list(v) for k, v in self.last.items()},
                "pending": {json.dumps(k): v for k, v in self.pending.items()}}

    def restore(self, d: dict) -> None:
        for name in ("asns", "asn_n", "dev", "kinds", "last", "pending"):
            getattr(self, name).clear()
        for k, v in d.get("asns", {}).items(): self.asns[k] = set(v)
        for k, v in d.get("asn_n", {}).items(): self.asn_n[k] = v
        for k, v in d.get("dev", {}).items(): self.dev[tuple(json.loads(k))] = v
        for k, v in d.get("kinds", {}).items(): self.kinds[k] = v
        for k, v in d.get("last", {}).items(): self.last[k] = (v[0], v[1], v[2], tuple(v[3]) if v[3] else None)
        for k, v in d.get("pending", {}).items(): self.pending[tuple(json.loads(k))] = v

    def save(self, path: str) -> None:
        atomic_write_json(path, self.snapshot())

    def load(self, path: str) -> None:
        d = read_json(path, None)
        if d:
            self.restore(d)


class DestinationMonitor:
    """Where do results go? A hijacker must send output to somewhere THEY control (new webhook, email,
    endpoint, raw IP). By default NO destination is trusted until the owner approves one (learn_first=False):
    learning the first destination ever seen would let an attacker who acts first (or after a restart wipes
    state) register their own. Ambiguous strings (parser differentials such as `https://evil.com\\@good.com`)
    never match anything and always force re-verification."""
    def __init__(self, learn_first: bool = False, path: str = None, max_accounts: int = 100_000):
        self.learn_first, self.path = learn_first, path
        self.known = LRUDict(set, max_accounts)
        if path:
            self.load(path)

    normalise = staticmethod(normalise_host)

    def check(self, operator: str, dest: str):
        host = normalise_host(dest)
        if not host:
            return None
        if host == AMBIGUOUS:
            return "destination:ambiguous"
        if host in (self.known.get(operator) or ()):
            return None
        if self.learn_first and not self.known.get(operator):
            self.known[operator].add(host)
            self._save()
            return None
        return "destination:raw-ip" if is_raw_ip(host) else "destination:new"

    def approve(self, operator: str, dest: str) -> None:
        host = normalise_host(dest)
        if host and host != AMBIGUOUS:
            self.known[operator].add(host)
            self._save()

    def snapshot(self) -> dict:
        return {k: sorted(v) for k, v in self.known.items()}

    def save(self, path: str) -> None:
        atomic_write_json(path, self.snapshot())

    def load(self, path: str) -> None:
        d = read_json(path, None)
        if d:
            self.known.clear()
            for k, v in d.items():
                self.known[k] = set(v)

    def _save(self):
        if self.path:
            self.save(self.path)
