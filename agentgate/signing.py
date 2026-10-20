"""Device-bound request signing (passkey / WebAuthn-style) for agent_gate.

A stolen session token, cookie or device ID is just data. Each request must also carry an Ed25519
signature made with a private key that lives in the user's device (secure enclave / TPM / hardware key)
and never leaves it. Replays are rejected via a strictly increasing counter.

Honest limit: malware running ON the victim's device (or a remote-control session) can ask the device to
sign. Mitigate with user-presence/biometric prompts and device attestation.
Requires: pip install cryptography
"""
from __future__ import annotations
import hashlib, json, os
from ._util import atomic_write_json, read_json
from typing import Dict, Optional, Tuple
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SKEW_SECONDS = 120


def _msg(operator, device, counter, ts, text) -> bytes:
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return f"v1|{operator}|{device}|{counter}|{int(ts)}|{digest}".encode()


def public_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def make_proof(priv, operator, device, counter, ts, text) -> dict:
    """Client side (runs inside the device's secure key store in a real deployment)."""
    return {"device": device, "counter": counter, "ts": int(ts),
            "sig": priv.sign(_msg(operator, device, counter, int(ts), text)).hex()}


class DeviceRegistry:
    def __init__(self, path: Optional[str] = None, skew: int = SKEW_SECONDS):
        self.path, self.skew = path, skew
        self.on_event = None            # callable(kind, operator, device): set by Gate so enrol/revoke are audited
        self.devices: Dict[str, Dict[str, dict]] = {}
        if path:
            self.devices = read_json(path, {})

    def enroll(self, operator, device, pub_hex, hardware: bool = False) -> None:
        """Call ONLY after the operator has passed strong re-authentication.
        Set hardware=True only after VERIFYING the authenticator attestation; it gates sensitive-action approval."""
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        self.devices.setdefault(operator, {})[device] = {"pub": pub_hex, "counter": 0, "revoked": False, "hardware": bool(hardware)}
        self._save()
        self._emit("ENROLL", operator, device)

    def enroll_webauthn(self, operator, device, registration: dict) -> None:
        """Store a credential returned by webauthn.verify_registration(). It counts as a hardware key only if the
        registration was `attested` by YOUR attestation verifier. Call after strong re-authentication."""
        self.devices.setdefault(operator, {})[device] = {
            "pub": None, "counter": 0, "revoked": False, "hardware": bool(registration["attested"]),
            "webauthn": {k: registration[k] for k in ("credential_id", "alg", "pub", "sign_count", "fmt", "aaguid")}}
        self._save()
        self._emit("ENROLL_WEBAUTHN", operator, device)

    def revoke(self, operator, device) -> None:
        if device in self.devices.get(operator, {}):
            self.devices[operator][device]["revoked"] = True
            self._save()
            self._emit("REVOKE", operator, device)

    def _emit(self, kind, operator, device):
        if self.on_event:
            try:
                self.on_event(kind, operator, device)
            except Exception:
                pass

    def verify(self, operator, text, proof, now) -> Tuple[bool, str]:
        if not proof or not isinstance(proof, dict):
            return False, "missing"
        try:
            dev, counter, ts = proof["device"], int(proof["counter"]), int(proof["ts"])
            sig = bytes.fromhex(proof["sig"])
            if not isinstance(dev, str):
                raise TypeError
        except (KeyError, TypeError, ValueError, OverflowError):
            return False, "malformed"
        rec = self.devices.get(operator, {}).get(dev)
        if not rec:
            return False, "unknown-device"
        if rec["revoked"]:
            return False, "revoked"
        if not rec.get("pub"):
            return False, "not-a-signing-key"
        if abs(now - ts) > self.skew:
            return False, "stale"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(rec["pub"])).verify(sig, _msg(operator, dev, counter, ts, text))
        except (InvalidSignature, ValueError):
            return False, "bad-signature"
        if counter <= rec["counter"]:
            return False, "replay"
        rec["counter"] = counter
        self._save()
        return True, "ok"

    def _save(self):
        if self.path:
            atomic_write_json(self.path, self.devices)
