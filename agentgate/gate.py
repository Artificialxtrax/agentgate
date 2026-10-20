#!/usr/bin/env python3
"""agent_gate - a policy gateway that screens operator requests BEFORE they reach an AI agent.

What it does
  * screens each request against a policy (pluggable classifier; rule-based default, run on raw AND
    Unicode-normalised text so zero-width characters, full-width letters and homoglyphs do not evade it)
  * applies tiered actions by operator identity tier (anonymous / verified / verified-security)
  * tracks strikes and suspends repeat offenders until a human reinstates them
  * routes the most serious cases to a HUMAN review queue
  * keeps a tamper-evident (hash-chained) audit log that stores hashes, not raw text; every trust-extending
    event (verification, key enrolment/revocation, reinstatement) is logged too
  * FAILS CLOSED: any internal error returns a BLOCK decision (never an exception a caller might swallow)

What it deliberately does NOT do
  * decide what is "legal": it enforces a policy your legal/trust team writes
  * contact law enforcement automatically: referrals are human + counsel decisions
  * replace a real classifier: regex rules are a weak baseline; plug in a model via `classifier=`

Deployment notes that matter for security
  * `meta` MUST be built server-side (see edge.build_meta). `sensitive_action` must come from your route/handler,
    never from client input, or an attacker simply omits it.
  * All monitor state is in-process (optionally checkpointed with state_dir=). Running several workers means each
    has its own view; use sticky routing or a shared store.
  * Operator IDs must be canonical identifiers from your auth system ("Mallory" and "mallory " are different keys).
"""
from __future__ import annotations
import hashlib, hmac, json, math, os, re, secrets, sys, threading, time, unicodedata, urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ._util import atomic_write_json, normalise_host, read_json

try:
    import fcntl
except ImportError:              # non-POSIX: in-process locking only
    fcntl = None

ALLOW, ALLOW_LOGGED, SUPPORT, BLOCK, ESCALATE, SUSPENDED, STEP_UP = (
    "ALLOW", "ALLOW_LOGGED", "SUPPORT", "BLOCK", "ESCALATE", "SUSPENDED", "STEP_UP")
RANK = {ALLOW: 0, ALLOW_LOGGED: 1, SUPPORT: 2, BLOCK: 3, ESCALATE: 4, SUSPENDED: 5, STEP_UP: 1}
TIER_ANON, TIER_VERIFIED, TIER_VERIFIED_SECURITY = 0, 1, 2
GENESIS = "0" * 64
MAX_TEXT_CHARS = 1_000_000          # hard limit: larger inputs are refused, not scanned
CLASSIFIER_CHARS = 20_000           # a custom/LLM classifier sees head+tail of longer inputs (rules scan everything)

# category -> (default action, {tier: action override})
POLICY: Dict[str, Tuple[str, Dict[int, str]]] = {
    "child_safety":      (ESCALATE, {}),
    "mass_harm_weapons": (ESCALATE, {}),
    "violence":          (ESCALATE, {}),
    "malware":           (BLOCK, {}),
    "intrusion":         (BLOCK, {TIER_VERIFIED_SECURITY: ALLOW_LOGGED}),
    "fraud":             (BLOCK, {}),
    "stalking":          (BLOCK, {}),
    "self_harm":         (SUPPORT, {}),   # a person in distress needs help, not a strike
    "tripwire":          (ESCALATE, {}),      # decoy credential used: near-certain compromise
    "uncertain":         (ALLOW_LOGGED, {}),  # ambiguous: allowed, logged, sampled for human review, no strike
}
STRIKE_WEIGHT = {BLOCK: 1, ESCALATE: 2}

_F = re.I | re.S
RULES = [
    ("malware", "build-malware", re.compile(
        r"\b(write|create|build|make|code|develop)\b[^.\n]{0,40}\b(ransomware|keylogger|botnet|computer worm|rootkit|infostealer|malware)\b", _F)),
    ("intrusion", "break-into-others", re.compile(
        r"\b(hack|break into|get into|gain access to)\b[^.\n]{0,30}\b(someone'?s|my ex'?s|her|his|their|a stranger'?s|neighbou?r'?s)\b[^.\n]{0,25}\b(account|phone|email|wi-?fi|computer|camera)\b", _F)),
    ("fraud", "phishing", re.compile(r"\b(create|make|build|set up)\b[^.\n]{0,25}\bphishing\b", _F)),
    ("fraud", "harvest-credentials", re.compile(
        r"\b(steal|harvest|collect)\b[^.\n]{0,30}\b(passwords|credit card numbers|logins)\b[^.\n]{0,40}\b(victims?|users|people|customers)\b", _F)),
    ("violence", "harm-person", re.compile(
        r"\b(how (?:do|can|to)|help me)\b[^.\n]{0,25}\b(kill|poison|hurt|stab|shoot)\b[^.\n]{0,25}\b(my (?:wife|husband|boss|neighbou?r|ex)|him|her|someone|a person)\b", _F)),
    ("mass_harm_weapons", "weapons", re.compile(
        r"\b(synthesi[sz]e|make|produce|build|weaponi[sz]e)\b[^.\n]{0,30}\b(nerve agent|sarin|vx gas|bioweapon|anthrax|dirty bomb|pipe bomb)\b", _F)),
    ("stalking", "covert-tracking", re.compile(
        r"\b(track|follow|monitor|locate)\b[^.\n]{0,30}\b(my ex|her|him|someone)\b[^.\n]{0,30}\b(secretly|without (?:her|his|their) (?:knowing|knowledge|consent)|without them knowing)\b", _F)),
    ("child_safety", "sexualised-minor", re.compile(
        r"\b(sexual|explicit|nude|erotic)\b[^.\n]{0,40}\b(child|children|minor|underage|(?:[1-9]|1[0-7])[- ]year[- ]old)\b", _F)),
    ("self_harm", "self-harm", re.compile(r"\b(kill myself|end my life|want to die)\b", _F)),
]

MESSAGES = {
    ALLOW: "",
    ALLOW_LOGGED: "Allowed under your verified account. This request is logged.",
    SUPPORT: ("It sounds like you may be going through something painful. You're not alone. "
              "In the US you can call or text 988 (Suicide & Crisis Lifeline) any time."),
    BLOCK: "Request declined: it conflicts with the usage policy ({cats}). Repeated violations lead to suspension.",
    ESCALATE: "Request declined and flagged for human review ({cats}).",
    SUSPENDED: "This account is suspended pending human review.",
    STEP_UP: "For your security, please re-verify your identity to continue.",
}
APPROVAL_MESSAGE = "This action needs approval with your physical security key."
THROTTLED_MESSAGE = "Too many approvals are pending for this device. Wait a minute and try again."
ERROR_MESSAGE = "We couldn't process this request right now. Please try again shortly."


# --------------------------------------------------------------------------- text normalisation
# Visually identical Cyrillic/Greek letters -> Latin (applied after case folding).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "ӏ": "l", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k",
    "ϲ": "c", "ѵ": "v", "ɑ": "a",
})
_DROP = {"Cf", "Cc", "Cs", "Co", "Mn"}          # format (zero-width, soft hyphen, bidi), control, surrogate, private, marks
_KEEP = {"\n", "\t"}


def normalize_text(s: str) -> str:
    """Canonical form for RULE MATCHING ONLY (the original text is what models and humans see)."""
    if not s.isascii():
        s = unicodedata.normalize("NFKC", s)
        s = "".join(c for c in s if c in _KEEP or unicodedata.category(c) not in _DROP)
        s = s.casefold().translate(_CONFUSABLES)
    else:
        s = s.casefold()
    return re.sub(r"[^\S\n]+", " ", s)


@dataclass
class Finding:
    category: str
    rule: str


@dataclass
class Decision:
    action: str
    categories: List[str] = field(default_factory=list)
    message: str = ""
    strikes: int = 0
    rules: List[str] = field(default_factory=list)
    challenge: Optional[dict] = None      # set when a physical-key approval is required

    @property
    def allowed(self) -> bool:
        return self.action in (ALLOW, ALLOW_LOGGED, SUPPORT)


def rule_classifier(text: str) -> List[Finding]:
    return [Finding(c, n) for c, n, rx in RULES if rx.search(text)]


# --------------------------------------------------------------------------- meta validation
_STR_LIMITS = {"device": 256, "tls": 512, "ua": 1024, "asn": 64, "net": 32, "ip": 64, "destination": 2048,
               "sensitive_action": 512, "resource": 1024}
_CRITICAL = ("device-invalid", "sensitive_action-invalid")


def clean_meta(meta) -> Tuple[dict, List[str]]:
    """Validate the request metadata. Invalid fields are dropped and reported; problems with security-critical
    fields (device, sensitive_action) make the gate demand re-verification instead of silently ignoring them."""
    problems: List[str] = []
    if meta is None:
        return {}, problems
    if not isinstance(meta, dict):
        return {}, ["meta-not-dict"]
    out: dict = {}
    for key, limit in _STR_LIMITS.items():
        v = meta.get(key)
        if v is None:
            continue
        if isinstance(v, str) and len(v) <= limit:
            out[key] = v
        else:
            problems.append(f"{key}-invalid")
    h = meta.get("headers")
    if h is not None:
        if isinstance(h, (list, tuple)) and len(h) <= 200 and all(isinstance(x, str) and len(x) <= 256 for x in h):
            out["headers"] = list(h)
        else:
            problems.append("headers-invalid")
    g = meta.get("geo")
    if g is not None:
        if (isinstance(g, (list, tuple)) and len(g) == 2
                and all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in g)
                and -90 <= g[0] <= 90 and -180 <= g[1] <= 180):
            out["geo"] = (float(g[0]), float(g[1]))
        else:
            problems.append("geo-invalid")
    ki = meta.get("key_intervals")
    if ki is not None:
        if isinstance(ki, (list, tuple)):
            out["key_intervals"] = list(ki)[-500:]            # TypingMonitor validates the individual values
        else:
            problems.append("key_intervals-invalid")
    for flag in ("pasted", "sensitive"):
        if meta.get(flag) is True:
            out[flag] = True
    return out, problems


def bind_action(action: str, text: str, destination: str = "") -> str:
    """What a key tap actually authorises: the action label AND the exact request text AND the destination host.
    A captured approval therefore cannot be replayed against a different request or re-aimed elsewhere."""
    th = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]
    return f"{action}|dest={normalise_host(destination)}|text={th}"


def _hash_rec(rec: dict) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()


def verify_chain(path: str) -> Tuple[bool, Optional[int]]:
    """Check an audit log's hash chain. Never raises on a corrupt file: returns (False, index of first bad line)."""
    prev = GENESIS
    if not os.path.exists(path):
        return True, None
    with open(path, "rb") as f:
        for i, raw in enumerate(f):
            try:
                rec = json.loads(raw)
            except ValueError:
                return False, i
            if not isinstance(rec, dict) or not isinstance(rec.get("hash"), str) or "prev" not in rec:
                return False, i
            h = rec.pop("hash")
            if rec["prev"] != prev or _hash_rec(rec) != h:
                return False, i
            prev = h
    return True, None


def _read_exact(fd: int, n: int) -> bytes:
    out = b""
    while len(out) < n:
        b = os.read(fd, n - len(out))
        if not b:
            break
        out += b
    return out


def _tail_hash_fd(fd: int) -> str:
    """Hash of the last valid record, found by reading backwards from the end of the file."""
    size = os.fstat(fd).st_size
    chunk = 65536
    while True:
        start = max(0, size - chunk)
        os.lseek(fd, start, os.SEEK_SET)
        lines = _read_exact(fd, size - start).split(b"\n")
        if start > 0:
            lines = lines[1:]                       # first line may be cut off
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("hash"), str):
                return rec["hash"]
        if start == 0:
            return GENESIS
        chunk *= 4


class Gate:
    def __init__(self, log_path="gate_audit.jsonl", review_path="gate_review.jsonl", state_path: Optional[str] = None,
                 classifier: Callable[[str], List[Finding]] = rule_classifier, strike_limit: int = 3,
                 window_days: int = 30, store_excerpt: bool = True, monitor=None,
                 registry=None, require_proof: bool = False, tripwires=None, typing=None, transport=None,
                 destinations=None, approvals=None, recon=None, require_edge_data: bool = True,
                 strict: bool = False, max_text_chars: int = MAX_TEXT_CHARS, classifier_chars: int = CLASSIFIER_CHARS,
                 state_dir: Optional[str] = None, checkpoint_every: int = 200, fsync: bool = False):
        self.monitor, self.registry, self.require_proof = monitor, registry, require_proof
        self.tripwires, self.typing, self.transport = tripwires, typing, transport
        self.destinations, self.approvals, self.recon = destinations, approvals, recon
        self.require_edge_data, self.strict, self.fsync = require_edge_data, strict, fsync
        self.max_text_chars, self.classifier_chars = max_text_chars, classifier_chars
        self.log_path, self.review_path, self.state_path = log_path, review_path, state_path
        self.classifier, self.strike_limit = classifier, strike_limit
        self.window, self.store_excerpt = window_days * 86400, store_excerpt
        self.errors = 0
        self._lock = threading.RLock()
        self._pii_cache: Optional[bytes] = None
        self._tail_cache: Tuple[int, int, str] = (-1, -1, GENESIS)         # (inode, size, hash)
        self._calls, self.checkpoint_every, self._targets = 0, checkpoint_every, []
        self.strikes: Dict[str, List[List[float]]] = read_json(state_path, {}) if state_path else {}
        # key enrolment / revocation are the most security-sensitive trust events: make them auditable
        seen = set()
        for reg in (registry, getattr(approvals, "registry", None)):
            if reg is not None and id(reg) not in seen:
                seen.add(id(reg))
                if getattr(reg, "on_event", None) is None:
                    reg.on_event = self._registry_event
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
            for name, obj in (("behavior", monitor), ("transport", transport), ("destinations", destinations),
                              ("recon", recon)):
                if obj is not None and hasattr(obj, "load"):
                    path = os.path.join(state_dir, name + ".json")
                    obj.load(path)
                    self._targets.append((obj, path))

    # ------------------------------------------------------------------ public API
    def screen(self, operator: str, text: str, tier: int = TIER_ANON, now: Optional[float] = None,
               meta: Optional[dict] = None, proof: Optional[dict] = None,
               approval: Optional[dict] = None) -> Decision:
        """Decide what to do with one request. Never raises (unless strict=True): on any internal error the
        decision is BLOCK, so a caller that forgets error handling still fails closed."""
        try:
            return self._screen(operator, text, tier, now, meta, proof, approval)
        except Exception as e:
            if self.strict:
                raise
            kind = type(e).__name__
            self.errors += 1
            try:
                self._log_event("ERROR", operator if isinstance(operator, str) else "", {"type": kind})
            except Exception:
                pass
            try:       # a person in crisis must still get help when the machinery is broken
                t = text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else (text if isinstance(text, str) else "")
                if any(f.category == "self_harm" for f in rule_classifier(normalize_text(t[:20000]))):
                    return Decision(SUPPORT, ["self_harm"], MESSAGES[SUPPORT], 0, [f"internal-error:{kind}"])
            except Exception:
                pass
            return Decision(BLOCK, [], ERROR_MESSAGE, 0, [f"internal-error:{kind}"])

    def reinstate(self, operator: str, by: str = "") -> None:
        """Human action: clear strikes after review. Logged."""
        with self._lock:
            self.strikes.pop(operator, None)
            self._save_state()
            self._log_event("REINSTATE", operator, {"by": by})

    def verify_identity(self, operator: str, meta: Optional[dict] = None, now: Optional[float] = None, by: str = "") -> None:
        """Call ONLY after the operator passed real re-authentication. Extends trust to the device, client,
        network and destination in `meta`. Logged."""
        now = now if now is not None else time.time()
        m, _ = clean_meta(meta)
        with self._lock:
            self._trust(operator, m, now)
            self._log_event("VERIFY", operator, {"device": self._pii(m.get("device", "")), "ip": self._pii(m.get("ip", "")),
                                                 "by": by}, ts=now)

    def verify_log(self) -> Tuple[bool, Optional[int]]:
        return verify_chain(self.log_path)

    def checkpoint(self) -> None:
        """Write monitor baselines to state_dir (called automatically every `checkpoint_every` requests)."""
        with self._lock:
            for obj, path in self._targets:
                obj.save(path)

    # ------------------------------------------------------------------ the decision path
    def _screen(self, operator, text, tier, now, meta, proof, approval) -> Decision:
        if not isinstance(operator, str) or not operator:
            raise TypeError("operator must be a non-empty string")
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        if not isinstance(text, str):
            raise TypeError("text must be str")
        now = now if now is not None else time.time()
        meta, problems = clean_meta(meta)
        if not meta.get("device") and isinstance(proof, dict) and isinstance(proof.get("device"), str):
            meta["device"] = proof["device"][:256]       # verified below; an invalid proof still steps up
        if len(text) > self.max_text_chars:
            with self._lock:
                d = Decision(BLOCK, [], "This request is too large to process. Please shorten it.",
                             self._score(operator, now), ["oversize-input"])
                return self._finish(operator, tier, text, d, now, {})
        norm = normalize_text(text)
        with self._lock:
            if self._score(operator, now) >= self.strike_limit:
                return self._suspended(operator, tier, text, norm, now)
        findings = self._classify(text, norm)                 # may be slow (model call): outside the lock
        with self._lock:
            return self._decide(operator, text, tier, now, meta, problems, proof, approval, findings)

    def _classify(self, text: str, norm: str) -> List[Finding]:
        findings: List[Finding] = []
        ctext = text
        if len(text) > self.classifier_chars:
            half = self.classifier_chars // 2
            ctext = text[:half] + "\n[...]\n" + text[-half:]
            findings.append(Finding("uncertain", "truncated-for-classifier"))
        findings += list(self.classifier(ctext))
        findings += rule_classifier(norm)                     # the rule floor always runs, on normalised text
        if text != norm:
            findings += rule_classifier(text)
        if self.tripwires is not None:
            findings += [Finding("tripwire", "decoy:" + h["placement"]) for h in self.tripwires.scan(text)]
        seen, out = set(), []
        for f in findings:
            if (f.category, f.rule) not in seen:
                seen.add((f.category, f.rule))
                out.append(f)
        return out

    def _suspended(self, operator, tier, text, norm, now) -> Decision:
        """A suspended account gets no service, but a person in crisis still gets help."""
        if any(f.category == "self_harm" for f in rule_classifier(norm)):
            d = Decision(SUPPORT, ["self_harm"], MESSAGES[SUPPORT], self._score(operator, now), ["suspended-account-support"])
        else:
            d = Decision(SUSPENDED, [], MESSAGES[SUSPENDED], self._score(operator, now))
        return self._finish(operator, tier, text, d, now, {})

    def _decide(self, operator, text, tier, now, meta, problems, proof, approval, findings) -> Decision:
        cats = sorted({f.category for f in findings})
        action = ALLOW
        for c in cats:
            default, overrides = POLICY.get(c, (BLOCK, {}))
            a = overrides.get(tier, default)
            if RANK[a] > RANK[action]:
                action = a
        w = STRIKE_WEIGHT.get(action, 0)
        if "tripwire" in cats:
            w = self.strike_limit          # decoy use suspends immediately; humans reinstate after review
        if w:
            kept = [s for s in self.strikes.get(operator, []) if now - s[0] <= self.window]
            self.strikes[operator] = kept + [[now, w]]
            self._save_state()
        d = Decision(action, cats, MESSAGES[action].format(cats=", ".join(cats)), self._score(operator, now),
                     [f.rule for f in findings])
        extra: dict = {}
        if problems:
            extra["meta_problems"] = problems
        approved = False

        def soft() -> bool:                # may still be downgraded to a step-up?
            return d.action in (ALLOW, ALLOW_LOGGED) and not approved

        def step(rule: str, challenge=None, message=None) -> None:
            nonlocal d
            d = Decision(STEP_UP, d.categories, message or MESSAGES[STEP_UP], d.strikes, d.rules + [rule],
                         challenge=challenge)

        crit = [p for p in problems if p in _CRITICAL]
        if crit and soft():
            step("meta-invalid:" + "+".join(crit))

        sa = meta.get("sensitive_action")
        if self.approvals is not None and sa and meta.get("device") and d.action in (ALLOW, ALLOW_LOGGED):
            bound = bind_action(sa, text, meta.get("destination", ""))
            ok, why = self.approvals.verify(operator, approval, bound, now)
            extra["approval"] = why
            if ok:
                approved = True              # strong, request-bound proof: also trusts this client/network/destination
                self._trust(operator, meta, now)
            else:
                ch = self.approvals.challenge(operator, meta["device"], bound, now)
                step(f"approval:{why}", challenge=ch, message=APPROVAL_MESSAGE if ch else THROTTLED_MESSAGE)

        if self.require_edge_data and soft():
            missing = []
            if (self.monitor is not None or self.transport is not None) and not meta.get("device"):
                missing.append("device")
            if self.transport is not None and not (meta.get("tls") or meta.get("ua")):
                missing.append("client")
            if missing:
                step("edge-data-missing:" + "+".join(missing))

        if self.typing is not None and ("key_intervals" in meta or "key_intervals-invalid" in problems):
            if "key_intervals" in meta:
                v, why = self.typing.check(operator, meta["key_intervals"], meta.get("pasted", False))
            else:
                v, why = "automated", "malformed timing data"
            extra["typing"] = v
            if v in ("automated", "mismatch") and soft():
                step(f"typing:{why}")

        if self.transport is not None and any(k in meta for k in ("tls", "headers", "ua", "geo", "net", "asn")):
            ta = self.transport.assess(operator, now, meta)
            extra["transport"] = {"score": ta.score, "flags": ta.flags}
            if ta.recommend == "step_up" and soft():
                step("transport:" + "+".join(ta.flags))
            self.transport.record(operator, now, meta, ta)

        if self.recon is not None and meta.get("resource"):
            why = self.recon.observe(operator, meta["resource"], now)
            if why:
                extra["recon"] = why
                if soft():
                    step("recon")

        if self.destinations is not None and meta.get("destination"):
            why = self.destinations.check(operator, meta["destination"])
            extra["destination"] = "new" if why else "known"
            if why and soft():
                step(why)

        if self.registry is not None and (self.require_proof or proof is not None):
            ok, why = self.registry.verify(operator, text, proof, now)
            extra["proof"] = why
            if ok and self.monitor is not None:
                self.monitor.trust_device(operator, proof["device"])
            if not ok and soft():            # SUPPORT (crisis help) is never gated
                step(f"proof:{why}")

        if self.monitor is not None:
            dev, ip = meta.get("device", ""), meta.get("ip", "")
            a = self.monitor.assess(operator, now, dev, ip)
            extra.update({"risk": a.score, "flags": a.flags, "device": self._pii(dev), "ip": self._pii(ip)})
            if a.recommend == "step_up" and soft():
                step("behavior:" + "+".join(a.flags))
            self.monitor.record(operator, now, dev, ip,
                                flagged=d.action in (BLOCK, ESCALATE) or "uncertain" in d.categories, assessment=a)
        return self._finish(operator, tier, text, d, now, extra)

    def _trust(self, operator: str, meta: dict, now: float) -> None:
        if self.destinations is not None and meta.get("destination"):
            self.destinations.approve(operator, meta["destination"])
        if self.transport is not None:
            self.transport.verify(operator, meta, now)
        if self.monitor is not None:
            self.monitor.verify(operator, meta.get("device", ""), now)

    # ------------------------------------------------------------------ audit log
    def _score(self, operator, now):
        return sum(w for ts, w in self.strikes.get(operator, []) if now - ts <= self.window)

    def _finish(self, operator, tier, text, d, now, extra=None) -> Decision:
        rec = {"ts": now, "kind": "REQUEST", "operator": operator, "tier": tier,
               "text_sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
               "categories": d.categories, "rules": d.rules, "action": d.action, **(extra or {})}
        self._append_log(rec)
        if d.action == ESCALATE or "uncertain" in d.categories:
            item = {"ts": now, "operator": operator, "tier": tier, "categories": d.categories, "rules": d.rules,
                    "excerpt": text[:300] if self.store_excerpt else None, "status": "pending"}
            with open(self.review_path, "a") as f:
                f.write(json.dumps(item) + "\n")
        self._calls += 1
        if self._targets and self._calls % self.checkpoint_every == 0:
            self.checkpoint()
        return d

    def _log_event(self, kind: str, operator: str, detail: dict, ts: Optional[float] = None) -> None:
        self._append_log({"ts": ts if ts is not None else time.time(), "kind": kind, "operator": operator,
                          "action": kind, "detail": detail})

    def _registry_event(self, kind: str, operator: str, device: str) -> None:
        self._log_event(kind, operator, {"device": self._pii(device)})

    def _append_log(self, rec: dict) -> None:
        """Append one record. Safe under threads (RLock) and processes (flock): the previous hash is always read
        from the end of the file under the lock, so concurrent writers cannot fork or break the chain."""
        with self._lock:
            fd = os.open(self.log_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
            try:
                if fcntl:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                recovered = self._recover_torn_tail(fd)
                if recovered:
                    self._write_locked(fd, {"ts": time.time(), "kind": "LOG_RECOVERED", "operator": "",
                                            "action": "LOG_RECOVERED", "detail": recovered})
                self._write_locked(fd, rec)
            finally:
                os.close(fd)                 # closing releases the flock

    def _write_locked(self, fd: int, rec: dict) -> None:
        st = os.fstat(fd)
        ino, size, cached = self._tail_cache
        rec["prev"] = cached if (ino, size) == (st.st_ino, st.st_size) and size >= 0 else _tail_hash_fd(fd)
        rec.pop("hash", None)
        rec["hash"] = _hash_rec(rec)
        line = (json.dumps(rec, sort_keys=True) + "\n").encode()
        written = 0
        while written < len(line):
            written += os.write(fd, line[written:])
        if self.fsync:
            os.fsync(fd)
        self._tail_cache = (st.st_ino, st.st_size + len(line), rec["hash"])

    def _recover_torn_tail(self, fd: int) -> Optional[dict]:
        """After a crash mid-write the log can end in a partial line. Preserve it as evidence in a side file,
        cut it off, and let the caller record a LOG_RECOVERED event. Complete-but-corrupt lines are never touched."""
        size = os.fstat(fd).st_size
        if size == 0:
            return None
        os.lseek(fd, size - 1, os.SEEK_SET)
        if _read_exact(fd, 1) == b"\n":
            return None
        pos, keep = size, 0
        while pos > 0:
            start = max(0, pos - 65536)
            os.lseek(fd, start, os.SEEK_SET)
            j = _read_exact(fd, pos - start).rfind(b"\n")
            if j >= 0:
                keep = start + j + 1
                break
            pos = start
        os.lseek(fd, keep, os.SEEK_SET)
        torn = _read_exact(fd, size - keep)
        side = f"{self.log_path}.torn.{time.time_ns()}"
        sfd = os.open(side, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(sfd, "wb") as f:
            f.write(torn)
        os.ftruncate(fd, keep)
        self._tail_cache = (-1, -1, GENESIS)
        return {"torn_bytes": len(torn), "torn_sha256": hashlib.sha256(torn).hexdigest(), "saved_as": os.path.basename(side)}

    _hash = staticmethod(_hash_rec)

    # ------------------------------------------------------------------ keyed hashing of IPs/devices
    @property
    def _pii_key(self) -> bytes:
        if self._pii_cache is None:
            self._pii_cache = self._load_pii_key()
        return self._pii_cache

    def _load_pii_key(self) -> bytes:
        env = os.environ.get("AGENT_GATE_PII_KEY")
        if env:
            return env.encode()
        kp = self.log_path + ".key"
        for _ in range(4):
            try:
                with open(kp, "rb") as f:
                    key = f.read()
                if len(key) >= 32:
                    return key
            except FileNotFoundError:
                pass
            tmp = f"{kp}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
            try:
                os.link(tmp, kp)                 # atomic create-if-absent: no reader ever sees a half-written key
            except FileExistsError:
                pass
            except OSError:                      # filesystem without hard links
                if not os.path.exists(kp):
                    os.replace(tmp, kp)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        raise RuntimeError(f"could not initialise the PII key at {kp}")

    def _pii(self, value: str) -> str:
        """Keyed hash for IPs/devices. Plain SHA-256 of an IPv4 address can be reversed by brute force in
        seconds (only ~4 billion values); a secret key makes the logged value useless without it, while the
        key holder can still match a known IP against the log during an investigation."""
        return hmac.new(self._pii_key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:16] if value else ""

    def _save_state(self):
        if self.state_path:
            atomic_write_json(self.state_path, self.strikes)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Screen a request against the policy.")
    ap.add_argument("text", nargs="?")
    ap.add_argument("--operator", default="demo")
    ap.add_argument("--tier", type=int, default=0, choices=[0, 1, 2])
    ap.add_argument("--verify", action="store_true", help="verify audit-log integrity")
    a = ap.parse_args(argv)
    g = Gate(state_path="gate_state.json")
    if a.verify:
        ok, bad = g.verify_log()
        print("audit log OK" if ok else f"audit log TAMPERED at entry {bad}")
        sys.exit(0 if ok else 1)
    if not a.text:
        ap.error("text required")
    d = g.screen(a.operator, a.text, a.tier)
    print(json.dumps({"action": d.action, "categories": d.categories, "message": d.message, "strikes": d.strikes}, indent=2))
    sys.exit(0 if d.allowed else 3)


if __name__ == "__main__":
    main()
