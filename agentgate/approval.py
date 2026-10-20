"""Physical-key approval for sensitive actions (the layer that stops malware inside the owner's browser).

Flow: the gateway issues a ONE-TIME challenge bound to the exact action ("export:hooks.acme.com"). A hardware
key signs it; stolen tokens, copied fingerprints and code in the owner's browser cannot. A signature for one
action cannot be reused for another, replayed, or used after the challenge expires.

Two modes:
  * WebAuthn (production): approval = {"type": "webauthn", "nonce", "device", "credential_id",
    "authenticator_data", "client_data_json", "signature"}. Pass the challenge's `webauthn_challenge` (base64url)
    to navigator.credentials.get(). Configure rp_id/origin, enroll with DeviceRegistry.enroll_webauthn(), and set
    allow_simple=False.
  * Simple (development/tests): Ed25519 signature over {operator, device, nonce, action, presence}. The "hardware"
    flag is SELF-ASSERTED, so never allow this mode in production.

Limits: WebAuthn does not show the action text on the key. Malware that can fake the on-page prompt can still
trick a person into approving its action; show the action in a trusted UI. With store_path set, pending
challenges survive restarts and are shared between processes on one host (POSIX file lock); across hosts use a
shared store (e.g. Redis) with the same single-use semantics.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
import secrets
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._util import atomic_write_json
from .webauthn import WebAuthnError, b64u, verify_assertion

try:
    import fcntl
except ImportError:                    # non-POSIX
    fcntl = None

MAX_PENDING = 10_000
MAX_PENDING_PER_DEVICE = 6
MAX_PENDING_PER_OPERATOR = 20     # a token thief spamming challenges must not evict the real owner's


def action_hash(action: str) -> str:
    return hashlib.sha256(action.encode()).hexdigest()


def webauthn_challenge(nonce: str, ahash: str) -> bytes:
    return hashlib.sha256(f"{nonce}|{ahash}".encode()).digest()


def _msg(operator, device, nonce, ahash, up) -> bytes:
    return f"approve|v1|{operator}|{device}|{nonce}|{ahash}|{int(bool(up))}".encode()


def make_approval(priv, operator: str, device: str, challenge: dict, up: bool = True) -> dict:
    """Simple-mode authenticator side."""
    return {"device": device, "nonce": challenge["nonce"], "up": bool(up),
            "sig": priv.sign(_msg(operator, device, challenge["nonce"], challenge["action_hash"], up)).hex()}


class ApprovalService:
    def __init__(self, registry, ttl: int = 60, require_hardware: bool = True, rp_id: Optional[str] = None,
                 origin: Optional[str] = None, allow_simple: bool = True, require_uv: bool = False,
                 store_path: Optional[str] = None):
        self.registry, self.ttl, self.require_hardware = registry, ttl, require_hardware
        self.rp_id, self.origin, self.allow_simple, self.require_uv = rp_id, origin, allow_simple, require_uv
        self.store_path = store_path
        self.pending: Dict[str, dict] = {}

    @contextlib.contextmanager
    def _state(self):
        if not self.store_path:
            yield
            return
        with open(self.store_path + ".lock", "a") as lock:
            if fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                try:
                    with open(self.store_path) as f:
                        self.pending = json.load(f)
                except (FileNotFoundError, ValueError):
                    self.pending = {}
                yield
                atomic_write_json(self.store_path, self.pending)
            finally:
                if fcntl:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def challenge(self, operator: str, device: str, action: str, now: float) -> Optional[dict]:
        """Issue a one-time challenge. The same pending request returns the same challenge (no churn); an
        account/device that already has MAX_PENDING_PER_DEVICE open challenges is refused (returns None) rather
        than evicting older ones, so a token thief spamming requests cannot push out the owner's challenge."""
        with self._state():
            self.pending = {n: p for n, p in self.pending.items() if p["expires"] >= now}
            ah = action_hash(action)
            for p in self.pending.values():
                if p["operator"] == operator and p["device"] == device and p["action_hash"] == ah:
                    return {k: p[k] for k in ("nonce", "action_hash", "expires", "webauthn_challenge")}
            mine = [p for p in self.pending.values() if p["operator"] == operator]
            if (len(mine) >= MAX_PENDING_PER_OPERATOR
                    or sum(1 for p in mine if p["device"] == device) >= MAX_PENDING_PER_DEVICE
                    or len(self.pending) >= MAX_PENDING):
                return None
            nonce = secrets.token_hex(16)
            ch = {"nonce": nonce, "action_hash": ah, "expires": now + self.ttl,
                  "webauthn_challenge": b64u(webauthn_challenge(nonce, ah))}
            self.pending[nonce] = dict(ch, operator=operator, device=device)
        return ch

    def verify(self, operator: str, approval: Optional[dict], action: str, now: float) -> Tuple[bool, str]:
        if not approval or not isinstance(approval, dict):
            return False, "missing"
        try:
            nonce, dev = approval["nonce"], approval["device"]
            if not isinstance(nonce, str) or not isinstance(dev, str):
                return False, "malformed"
            kind = approval.get("type", "simple")
            if kind == "simple":
                sig, up = bytes.fromhex(approval["sig"]), bool(approval.get("up"))
            elif kind != "webauthn":
                return False, "malformed"
        except (KeyError, TypeError, ValueError):
            return False, "malformed"
        if kind == "simple" and not self.allow_simple:
            return False, "simple-mode-disabled"
        if kind == "webauthn" and not (self.rp_id and self.origin):
            return False, "webauthn-not-configured"
        with self._state():
            p = self.pending.pop(nonce, None)         # single use: consumed even if verification fails
        if not p:
            return False, "unknown-challenge"
        if now > p["expires"]:
            return False, "expired"
        if p["operator"] != operator or p["device"] != dev:
            return False, "wrong-session"
        if p["action_hash"] != action_hash(action):
            return False, "action-mismatch"
        rec = self.registry.devices.get(operator, {}).get(dev)
        if not rec or rec.get("revoked"):
            return False, "unknown-device"
        if self.require_hardware and not rec.get("hardware"):
            return False, "not-hardware-key"
        if kind == "webauthn":
            cred = rec.get("webauthn")
            if not cred:
                return False, "not-a-webauthn-credential"
            try:
                new_count = verify_assertion(cred, approval, webauthn_challenge(nonce, p["action_hash"]),
                                             self.rp_id, self.origin, self.require_uv)
            except WebAuthnError as e:
                return False, f"webauthn:{e}"
            cred["sign_count"] = new_count
            self.registry._save()
            return True, "ok"
        if not rec.get("pub"):
            return False, "unknown-device"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(rec["pub"])).verify(
                sig, _msg(operator, dev, nonce, p["action_hash"], up))
        except (InvalidSignature, ValueError):
            return False, "bad-signature"
        if not up:
            return False, "no-presence"
        return True, "ok"
