#!/usr/bin/env python3
"""Anchor the audit log to an external timestamp (e.g. Bitcoin via OpenTimestamps).

Gives proof the log looked a certain way at a certain time, so even someone controlling your server (who
can rewrite the log AND recompute its hash chain) cannot quietly change anchored history. It does NOT
authenticate users or stop hijacks in real time (Bitcoin confirmation takes hours). Only a Merkle root
(a hash) is published: no user data goes on-chain.

Backends:
  file            - local anchors; only meaningful if you ALSO publish the roots somewhere you don't control.
  opentimestamps  - stamps the root with the `ots` CLI (pip install opentimestamps-client). NOT TESTED here.
"""
from __future__ import annotations
import hashlib, json, os, shutil, subprocess, sys, time
from typing import List, Optional, Tuple

GENESIS = "0" * 64
from .gate import verify_chain


def merkle_root(hashes: List[str], v: int = 2) -> str:
    """Merkle root. v2 (default) uses leaf/node domain separation, promotes an odd node instead of duplicating it
    (v1 duplicated, so [a,b,c] and [a,b,c,c] shared a root) and binds the leaf count into the root."""
    if not hashes:
        return GENESIS
    if v == 1:
        level = [bytes.fromhex(h) for h in hashes]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
        return level[0].hex()
    level = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in hashes]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return hashlib.sha256(b"agentgate-merkle-v2" + len(hashes).to_bytes(8, "big") + level[0]).hexdigest()


def _log_hashes(path):
    ok, bad = verify_chain(path)
    if not ok:
        raise ValueError(f"audit log hash chain is broken at entry {bad}; refusing to anchor/verify a tampered log")
    with open(path) as f:
        return [json.loads(l)["hash"] for l in f if l.strip()]


def _load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def _ahash(rec):
    return hashlib.sha256(json.dumps({k: v for k, v in rec.items() if k != "anchor_hash"}, sort_keys=True).encode()).hexdigest()


def _ots_stamp(root, anchors_path, n, ots_cmd="ots"):
    if not shutil.which(ots_cmd):
        raise RuntimeError("opentimestamps client not found: pip install opentimestamps-client")
    root_file = f"{anchors_path}.{n}.root"
    with open(root_file, "w") as f:
        f.write(root)
    subprocess.run([ots_cmd, "stamp", root_file], check=True)
    return root_file + ".ots"


def anchor_log(log_path, anchors_path, backend="file", ots_cmd="ots") -> Optional[dict]:
    if backend not in ("file", "opentimestamps"):
        raise ValueError("backend must be file or opentimestamps")
    hashes, anchors = _log_hashes(log_path), _load(anchors_path)
    start = anchors[-1]["to"] if anchors else 0
    if len(hashes) <= start:
        return None
    root = merkle_root(hashes[start:], 2)
    rec = {"v": 2, "from": start, "to": len(hashes), "root": root, "ts": time.time(), "backend": backend,
           "receipt": None, "prev": anchors[-1]["anchor_hash"] if anchors else GENESIS}
    if backend == "opentimestamps":
        rec["receipt"] = _ots_stamp(root, anchors_path, len(anchors), ots_cmd)
    rec["anchor_hash"] = _ahash(rec)
    with open(anchors_path, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def verify_anchors(log_path, anchors_path, external_roots: Optional[List[str]] = None) -> Tuple[bool, List[str]]:
    """Re-derive each anchored range from the CURRENT log. Pass `external_roots` (roots published elsewhere)
    to also catch an attacker who rewrote the anchors file."""
    anchors, problems, prev = _load(anchors_path), [], GENESIS
    try:
        hashes = _log_hashes(log_path)
    except ValueError as e:
        return False, [str(e)]
    for i, a in enumerate(anchors):
        if a["prev"] != prev or _ahash(a) != a["anchor_hash"]:
            problems.append(f"anchor {i}: anchors file altered")
        if a["to"] > len(hashes):
            problems.append(f"anchor {i}: log truncated")
        elif merkle_root(hashes[a["from"]:a["to"]], a.get("v", 1)) != a["root"]:
            problems.append(f"anchor {i}: log entries {a['from']}-{a['to']} no longer match anchored root")
        if external_roots is not None and (i >= len(external_roots) or external_roots[i] != a["root"]):
            problems.append(f"anchor {i}: root differs from externally published root")
        prev = a["anchor_hash"]
    return (not problems), problems


def ots_upgrade(receipt: str, ots_cmd: str = "ots") -> Tuple[bool, str]:
    """Fetch the Bitcoin attestation for a pending receipt (run again hours after stamping)."""
    if not shutil.which(ots_cmd):
        raise RuntimeError("opentimestamps client not found: pip install opentimestamps-client")
    r = subprocess.run([ots_cmd, "upgrade", receipt], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def ots_verify(receipt: str, ots_cmd: str = "ots") -> Tuple[bool, str]:
    """Ask the OpenTimestamps client to verify a receipt against its root file (needs network / a Bitcoin node)."""
    if not shutil.which(ots_cmd):
        raise RuntimeError("opentimestamps client not found: pip install opentimestamps-client")
    r = subprocess.run([ots_cmd, "verify", receipt], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) >= 3 and a[0] == "anchor":
        print(json.dumps(anchor_log(a[1], a[2], a[3] if len(a) > 3 else "file"), indent=2))
    elif len(a) == 3 and a[0] == "verify":
        ok, p = verify_anchors(a[1], a[2])
        print("anchors OK" if ok else "PROBLEMS:\n" + "\n".join(p))
        sys.exit(0 if ok else 1)
    else:
        sys.exit("usage: anchor.py anchor LOG ANCHORS [file|opentimestamps] | anchor.py verify LOG ANCHORS")
