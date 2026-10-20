"""WebAuthn (FIDO2) registration and assertion verification, using only `cryptography`.

Implements the server-side checks from the W3C WebAuthn spec that matter for approving sensitive actions:
clientDataJSON type / challenge / origin, authenticator data rpIdHash, user-presence (UP) and optional
user-verification (UV) flags, signature over authData || SHA-256(clientDataJSON) for ES256 (-7) and EdDSA (-8),
and the signature counter (clone detection).

Attestation: this module does NOT ship vendor root certificates. A credential is only marked `attested` if you
pass an `attestation_verifier(fmt, att_stmt, auth_data, client_data_hash) -> bool` that validates the statement
against roots you trust (FIDO MDS). Without it every credential is `attested=False`, and ApprovalService will
not treat it as a hardware key. That is the point: a flag you set blindly proves nothing.

Status: tested against a software authenticator that follows the spec (agentgate.softauth), NOT against real
authenticators or the official conformance suite. Have a security reviewer check it, or use a maintained
library (e.g. py_webauthn) and map its result onto DeviceRegistry.enroll_webauthn().
"""
from __future__ import annotations
import base64
import hashlib
import json
from typing import Any, Callable, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80
ALG_ES256, ALG_EDDSA = -7, -8


class WebAuthnError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- minimal CBOR (decode only)
def cbor_decode(data: bytes, offset: int = 0, depth: int = 0) -> Tuple[Any, int]:
    if depth > 16:
        raise WebAuthnError("cbor-too-deep")
    try:
        head = data[offset]
    except IndexError:
        raise WebAuthnError("cbor-truncated")
    major, info, offset = head >> 5, head & 0x1F, offset + 1

    def need(n):
        if offset + n > len(data):
            raise WebAuthnError("cbor-truncated")

    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        need(size)
        n, offset = int.from_bytes(data[offset:offset + size], "big"), offset + size
    else:
        raise WebAuthnError("cbor-unsupported")
    if major == 0:
        return n, offset
    if major == 1:
        return -1 - n, offset
    if major in (2, 3):
        need(n)
        raw = data[offset:offset + n]
        if major == 2:
            return raw, offset + n
        try:
            return raw.decode("utf-8"), offset + n
        except UnicodeDecodeError:
            raise WebAuthnError("cbor-bad-utf8")
    if major == 4:
        if n > 1024:
            raise WebAuthnError("cbor-too-large")
        out = []
        for _ in range(n):
            v, offset = cbor_decode(data, offset, depth + 1)
            out.append(v)
        return out, offset
    if major == 5:
        if n > 1024:
            raise WebAuthnError("cbor-too-large")
        out = {}
        for _ in range(n):
            k, offset = cbor_decode(data, offset, depth + 1)
            v, offset = cbor_decode(data, offset, depth + 1)
            out[k] = v
        return out, offset
    raise WebAuthnError("cbor-unsupported")


# ---------------------------------------------------------------- authenticator data
def parse_auth_data(ad: bytes, attested: bool) -> dict:
    if len(ad) < 37:
        raise WebAuthnError("authdata-short")
    out = {"rp_id_hash": ad[:32], "flags": ad[32], "sign_count": int.from_bytes(ad[33:37], "big")}
    if attested:
        if not out["flags"] & FLAG_AT or len(ad) < 55:
            raise WebAuthnError("no-attested-credential-data")
        cred_len = int.from_bytes(ad[53:55], "big")
        if len(ad) < 55 + cred_len:
            raise WebAuthnError("authdata-short")
        out["aaguid"] = ad[37:53]
        out["credential_id"] = ad[55:55 + cred_len]
        out["cose_key"], _ = cbor_decode(ad, 55 + cred_len)
    return out


def cose_to_public_key(cose: dict):
    if not isinstance(cose, dict):
        raise WebAuthnError("bad-cose-key")
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == ALG_ES256 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise WebAuthnError("bad-cose-key")
        try:
            return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                 ec.SECP256R1()).public_key(), ALG_ES256
        except ValueError:
            raise WebAuthnError("bad-cose-key")
    if kty == 1 and alg == ALG_EDDSA and cose.get(-1) == 6:
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise WebAuthnError("bad-cose-key")
        return Ed25519PublicKey.from_public_bytes(x), ALG_EDDSA
    raise WebAuthnError("unsupported-key-type")


def _spki(pub) -> str:
    return b64u(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def _check_client_data(client_data_json: bytes, expect_type: str, challenge: bytes, origin: str) -> None:
    try:
        cd = json.loads(client_data_json)
    except (ValueError, UnicodeDecodeError):
        raise WebAuthnError("bad-client-data")
    if not isinstance(cd, dict):
        raise WebAuthnError("bad-client-data")
    if cd.get("type") != expect_type:
        raise WebAuthnError("wrong-type")
    if cd.get("challenge") != b64u(challenge):
        raise WebAuthnError("challenge-mismatch")
    if cd.get("origin") != origin:
        raise WebAuthnError("origin-mismatch")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin")


def _check_flags(ad: dict, rp_id: str, require_uv: bool) -> None:
    if ad["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("rpid-mismatch")
    if not ad["flags"] & FLAG_UP:
        raise WebAuthnError("no-user-presence")
    if require_uv and not ad["flags"] & FLAG_UV:
        raise WebAuthnError("no-user-verification")


def _verify_sig(pub, alg: int, sig: bytes, data: bytes) -> None:
    try:
        if alg == ALG_ES256:
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_EDDSA:
            pub.verify(sig, data)
        else:
            raise WebAuthnError("unsupported-alg")
    except InvalidSignature:
        raise WebAuthnError("bad-signature")


# ---------------------------------------------------------------- registration
def _guard(fn):
    """Only WebAuthnError may escape: hostile input must never surface as TypeError/UnicodeError/etc."""
    import functools

    @functools.wraps(fn)
    def inner(*a, **k):
        try:
            return fn(*a, **k)
        except WebAuthnError:
            raise
        except Exception as e:
            raise WebAuthnError(f"malformed:{type(e).__name__}")
    return inner


@_guard
def verify_registration(attestation_object: bytes, client_data_json: bytes, expected_challenge: bytes,
                        rp_id: str, origin: str, require_uv: bool = False,
                        attestation_verifier: Optional[Callable[..., bool]] = None) -> dict:
    """Returns a credential record to store: credential_id, alg, pub (SPKI b64url), sign_count, attested, fmt, aaguid."""
    _check_client_data(client_data_json, "webauthn.create", expected_challenge, origin)
    att, _ = cbor_decode(attestation_object)
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes) or "fmt" not in att:
        raise WebAuthnError("bad-attestation-object")
    auth_data, fmt, stmt = att["authData"], att["fmt"], att.get("attStmt") or {}
    ad = parse_auth_data(auth_data, attested=True)
    _check_flags(ad, rp_id, require_uv)
    pub, alg = cose_to_public_key(ad["cose_key"])
    cdh = hashlib.sha256(client_data_json).digest()
    attested = False
    if fmt == "none":
        pass
    elif fmt == "packed" and "x5c" not in stmt and "ecdaaKeyId" not in stmt:      # self attestation
        if stmt.get("alg") != alg or not isinstance(stmt.get("sig"), bytes):
            raise WebAuthnError("bad-self-attestation")
        _verify_sig(pub, alg, stmt["sig"], auth_data + cdh)                       # proves key possession only
    elif attestation_verifier is not None:
        attested = bool(attestation_verifier(fmt, stmt, auth_data, cdh))
    return {"credential_id": b64u(ad["credential_id"]), "alg": alg, "pub": _spki(pub),
            "sign_count": ad["sign_count"], "attested": attested, "fmt": fmt, "aaguid": ad["aaguid"].hex()}


# ---------------------------------------------------------------- assertion
@_guard
def verify_assertion(cred: dict, assertion: dict, expected_challenge: bytes, rp_id: str, origin: str,
                     require_uv: bool = False) -> int:
    """Raises WebAuthnError on any failure; returns the new signature counter to persist."""
    if not isinstance(assertion, dict) or not isinstance(cred, dict):
        raise WebAuthnError("malformed")
    if any(isinstance(assertion.get(k), str) and len(assertion[k]) > 16384 for k in assertion):
        raise WebAuthnError("too-large")
    try:
        if assertion.get("credential_id") != cred["credential_id"]:
            raise WebAuthnError("credential-mismatch")
        auth_data = b64u_dec(assertion["authenticator_data"])
        cdj = b64u_dec(assertion["client_data_json"])
        sig = b64u_dec(assertion["signature"])
    except (KeyError, TypeError, ValueError):
        raise WebAuthnError("malformed")
    _check_client_data(cdj, "webauthn.get", expected_challenge, origin)
    ad = parse_auth_data(auth_data, attested=False)
    _check_flags(ad, rp_id, require_uv)
    pub = serialization.load_der_public_key(b64u_dec(cred["pub"]))
    _verify_sig(pub, cred["alg"], sig, auth_data + hashlib.sha256(cdj).digest())
    stored, new = int(cred.get("sign_count", 0)), ad["sign_count"]
    if (stored or new) and new <= stored:
        raise WebAuthnError("counter-rollback")          # possible cloned authenticator
    return new
