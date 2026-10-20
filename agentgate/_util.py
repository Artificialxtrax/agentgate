"""Shared helpers: bounded caches, atomic JSON state files, strict destination parsing."""
from __future__ import annotations
import ipaddress
import json
import os
import re
import tempfile
import unicodedata
from collections import OrderedDict
from typing import Any, Callable, Optional


class LRUDict(OrderedDict):
    """A dict with a size cap that evicts the least recently used key.

    Without a cap, an attacker who invents device IDs, IPs or accounts can grow monitor state until the process
    runs out of memory. With `factory`, `d[key]` creates a missing entry (like defaultdict); `get()` never creates.
    Eviction forgets old baselines: size the cap well above your real number of active accounts.
    """

    def __init__(self, factory: Optional[Callable[[], Any]] = None, maxsize: int = 100_000):
        super().__init__()
        self.factory, self.maxsize = factory, maxsize

    def __getitem__(self, key):
        try:
            value = OrderedDict.__getitem__(self, key)
        except KeyError:
            if self.factory is None:
                raise
            value = self.factory()
            self[key] = value
            return value
        self.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self.move_to_end(key)
        while len(self) > self.maxsize:
            # not popitem(): on some Python versions it re-enters our __getitem__ and fails
            OrderedDict.__delitem__(self, next(iter(self)))

    def get(self, key, default=None):
        return self[key] if key in self else default

    def setdefault(self, key, default=None):
        if key in self:
            return self[key]
        self[key] = default
        return default


def atomic_write_json(path: str, obj: Any) -> None:
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")      # mkstemp => mode 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except ValueError as e:
        raise ValueError(f"state file is corrupt: {path} ({e}). Inspect or move it aside; it was NOT reset.") from e


# --------------------------------------------------------------------------- destination parsing
_NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*")
AMBIGUOUS = "ambiguous-destination"


def _host_of(s: str) -> str:
    """Host part of a URL/e-mail/host string, lower-cased, without port, userinfo, brackets or trailing dot."""
    if "@" in s and "://" not in s:                       # e-mail style, or "mailto:x@y"
        return s.rsplit("@", 1)[1].split("/")[0].strip().rstrip(".")
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    authority = re.split(r"[/?#]", s, maxsplit=1)[0]
    authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("["):                         # IPv6 literal
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.split(":", 1)[0]
    return host.strip().rstrip(".")


def normalise_host(dest: Any) -> str:
    """Normalise a destination to a host key, or return AMBIGUOUS when different parsers could disagree.

    Parser differentials are a classic bypass: `https://evil.com\\@good.com/` is host good.com to RFC 3986
    parsers but host evil.com to browsers and WHATWG-style clients. If two reasonable readings of the string
    give different hosts (or the string hides control characters, percent-escapes in the host, or non-IDNA
    characters) we refuse to guess, so it can never match an approved destination.
    """
    if not isinstance(dest, str):
        return ""
    s = unicodedata.normalize("NFKC", dest).strip().lower()
    if not s:
        return ""
    if any(ord(c) < 33 or ord(c) == 127 for c in s):
        return AMBIGUOUS
    a, b = _host_of(s), _host_of(s.replace("\\", "/"))
    if a != b or not a or "%" in a:
        return AMBIGUOUS
    if not a.isascii():
        try:
            a = a.encode("idna").decode("ascii")
        except UnicodeError:
            return AMBIGUOUS
    return a


def is_raw_ip(host: str) -> bool:
    if not host or host == AMBIGUOUS:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST.fullmatch(host))        # 2130706433, 0x7f000001, 127.1 ...
