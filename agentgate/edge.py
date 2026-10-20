"""Edge helpers: turn a raw request into the `meta` dict that Gate.screen() expects.

  * ja3(client_hello)  - JA3 TLS fingerprint from raw ClientHello bytes (GREASE values removed).
  * build_meta(...)    - device, TLS fingerprint, header ORDER, user agent, plus ASN/geo/network type from a
                         lookup callable you provide.
  * classify_net(org)  - rough datacenter-vs-residential heuristic from an ASN organisation name (weak).
  * maxmind_lookup(...) - lookup backed by MaxMind GeoLite2 databases (needs `geoip2`; UNTESTED here).

Your reverse proxy usually has the raw ClientHello (e.g. nginx/Envoy/HAProxy JA3 modules): pass its JA3 hash
as `tls=` if you do not hand over raw bytes. JA3 is spoofable by TLS-impersonation libraries; it is one signal.
"""
from __future__ import annotations
import hashlib
from typing import Callable, Iterable, Optional, Tuple


def _is_grease(v: int) -> bool:
    return (v >> 8) == (v & 0xFF) and (v & 0x0F) == 0x0A


class _R:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise ValueError("truncated ClientHello")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def ja3(client_hello: bytes) -> Tuple[str, str]:
    """Returns (ja3_string, md5_hex). Accepts a TLS record or a bare handshake message."""
    data = client_hello
    if data[:1] == b"\x16":
        data = data[5:]
    r = _R(data)
    if r.u(1) != 1:
        raise ValueError("not a ClientHello")
    r.take(3)
    version = r.u(2)
    r.take(32)
    r.take(r.u(1))
    ciphers = [v for v in (r.u(2) for _ in range(r.u(2) // 2)) if not _is_grease(v)]
    r.take(r.u(1))
    ext_types, groups, formats = [], [], []
    if r.i < len(r.b):
        ext_total = r.u(2)
        end = r.i + ext_total
        while r.i < end:
            etype, elen = r.u(2), r.u(2)
            body = _R(r.take(elen))
            if _is_grease(etype):
                continue
            ext_types.append(etype)
            if etype == 10 and elen >= 2:
                groups = [g for g in (body.u(2) for _ in range(body.u(2) // 2)) if not _is_grease(g)]
            elif etype == 11 and elen >= 1:
                formats = [body.u(1) for _ in range(body.u(1))]
    s = ",".join([str(version), "-".join(map(str, ciphers)), "-".join(map(str, ext_types)),
                  "-".join(map(str, groups)), "-".join(map(str, formats))])
    return s, hashlib.md5(s.encode()).hexdigest()


HOSTING_HINTS = ("amazon", "aws", "google cloud", "google llc", "microsoft corporation", "azure", "digitalocean",
                 "ovh", "hetzner", "linode", "akamai connected", "vultr", "choopa", "leaseweb", "cloudflare",
                 "oracle", "alibaba", "tencent", "m247", "datacamp", "colocrossing", "contabo", "scaleway")


def classify_net(org: str, tor_exit: bool = False, vpn: bool = False) -> str:
    if tor_exit:
        return "tor"
    if vpn:
        return "vpn"
    o = (org or "").lower()
    return "hosting" if any(h in o for h in HOSTING_HINTS) else "residential"


def build_meta(headers: Iterable[Tuple[str, str]], *, device: str = "", client_hello: Optional[bytes] = None,
               tls: str = "", ip: str = "", lookup: Optional[Callable[[str], dict]] = None,
               sensitive_action: str = "", destination: str = "") -> dict:
    """`lookup(ip)` should return any of {"geo": (lat, lon), "asn": "AS123", "net": "residential|mobile|hosting|vpn|tor"}."""
    hdrs = list(headers)
    meta = {"device": device, "headers": [n for n, _ in hdrs],
            "ua": next((v for n, v in hdrs if n.lower() == "user-agent"), ""),
            "tls": ja3(client_hello)[1] if client_hello else tls}
    if ip:
        meta["ip"] = ip
        if lookup:
            meta.update({k: v for k, v in (lookup(ip) or {}).items() if k in ("geo", "asn", "net") and v})
    if sensitive_action:
        meta["sensitive_action"] = sensitive_action
    if destination:
        meta["destination"] = destination
    return meta


def maxmind_lookup(city_db: str, asn_db: str) -> Callable[[str], dict]:
    """UNTESTED: requires `pip install geoip2` and MaxMind GeoLite2 City + ASN databases."""
    import geoip2.database
    city, asn = geoip2.database.Reader(city_db), geoip2.database.Reader(asn_db)

    def look(ip: str) -> dict:
        out = {}
        try:
            c = city.city(ip)
            if c.location.latitude is not None:
                out["geo"] = (c.location.latitude, c.location.longitude)
        except Exception:
            pass
        try:
            a = asn.asn(ip)
            out["asn"] = f"AS{a.autonomous_system_number}"
            out["net"] = classify_net(a.autonomous_system_organization or "")
        except Exception:
            pass
        return out
    return look
