"""Software WebAuthn authenticator for tests, demos and local development ONLY.

It produces spec-shaped registration and assertion data so the server-side verifier can be exercised without
hardware. It is not a security device: its key sits in memory, so it can never prove a hardware key.
"""
from __future__ import annotations
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .webauthn import ALG_EDDSA, ALG_ES256, FLAG_AT, FLAG_UP, FLAG_UV, b64u


def cbor_encode(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError("too large")
    if isinstance(v, bool) or v is None:
        raise ValueError("unsupported")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor_encode(k) + cbor_encode(x) for k, x in v.items())
    raise ValueError("unsupported")


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str, alg: int = ALG_ES256, uv: bool = True):
        self.rp_id, self.origin, self.alg, self.uv = rp_id, origin, alg, uv
        self.credential_id = os.urandom(16)
        self.counter = 0
        self._priv = ec.generate_private_key(ec.SECP256R1()) if alg == ALG_ES256 else Ed25519PrivateKey.generate()

    def _cose(self) -> bytes:
        pub = self._priv.public_key()
        if self.alg == ALG_ES256:
            n = pub.public_numbers()
            return cbor_encode({1: 2, 3: ALG_ES256, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return cbor_encode({1: 1, 3: ALG_EDDSA, -1: 6, -2: raw})

    def _sign(self, data: bytes) -> bytes:
        return self._priv.sign(data, ec.ECDSA(hashes.SHA256())) if self.alg == ALG_ES256 else self._priv.sign(data)

    def _client_data(self, typ, challenge, origin=None) -> bytes:
        return json.dumps({"type": typ, "challenge": b64u(challenge), "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def make_registration(self, challenge: bytes, fmt: str = "none", rp_id: str = None, origin: str = None,
                          up: bool = True) -> dict:
        flags = (FLAG_UP if up else 0) | FLAG_AT | (FLAG_UV if self.uv else 0)
        ad = (hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
              + bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + self._cose())
        cdj = self._client_data("webauthn.create", challenge, origin)
        stmt = {}
        if fmt == "packed":
            stmt = {"alg": self.alg, "sig": self._sign(ad + hashlib.sha256(cdj).digest())}
        elif fmt == "fido-u2f-fake":
            stmt = {"x5c": [b"fake-cert"], "sig": b"x"}
        return {"attestation_object": cbor_encode({"fmt": fmt, "attStmt": stmt, "authData": ad}),
                "client_data_json": cdj}

    def get_assertion(self, challenge: bytes, up: bool = True, uv: bool = None, rp_id: str = None,
                      origin: str = None, bump_counter: bool = True) -> dict:
        if bump_counter:
            self.counter += 1
        uv = self.uv if uv is None else uv
        flags = (FLAG_UP if up else 0) | (FLAG_UV if uv else 0)
        ad = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + self.counter.to_bytes(4, "big")
        cdj = self._client_data("webauthn.get", challenge, origin)
        return {"type": "webauthn", "credential_id": b64u(self.credential_id), "authenticator_data": b64u(ad),
                "client_data_json": b64u(cdj), "signature": b64u(self._sign(ad + hashlib.sha256(cdj).digest()))}
