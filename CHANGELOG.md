# Changelog

## 1.2.1
- Fixed two Python 3.9 incompatibilities found by running the suite on 3.9 for the first time: an f-string that
  reused its own quote character (valid only on 3.12+) in `signing.py`, and the LRU eviction in `_util.py` crashing
  on 3.9 (affected every bounded monitor once its cap was reached).
- First real-authenticator test (Apple passkey, Chrome/macOS) via `examples/webauthn_demo.py`; see `docs/TESTED.md`.
- Added `REVIEW.md`, the browser demo, and demo-server test.

## 1.2.0 - adversarial audit
26 probes were run against 1.1.0; 24 confirmed defects, all fixed and covered by `tests/test_hardening.py`.
- **Fail closed**: `screen()` never raises; an internal error (including a crashing classifier) returns BLOCK and is
  logged (crisis text still gets SUPPORT). `strict=True` re-raises for tests.
- **Evasion**: rules run on Unicode-normalised text (NFKC, zero-width/combining/bidi stripped, case-folded,
  Cyrillic/Greek homoglyphs mapped). Honey tokens are found when upper-cased, split, full-width or URL-encoded.
  Suspended accounts still get crisis support. Oversize input refused; long input: rules scan all of it.
- **Hostile input**: `meta` is validated (types, lengths, finite numbers); invalid `device`/`sensitive_action`
  steps up. Malformed typing data is treated as automated. WebAuthn parsers raise only `WebAuthnError`.
- **Anti-poisoning**: a flagged device or hour is no longer learned from one sighting (slow trust after 3 uses over
  24h, or owner re-verification). Missing edge data (device/TLS/UA) steps up (`require_edge_data`).
- **Approvals** are bound to action + exact request text + destination host; ambiguous destination strings
  (backslash/percent/control-character parser tricks) never match and always step up; IPv6 hosts are distinct.
  The first destination is no longer auto-trusted (`DestinationMonitor(learn_first=True)` restores it).
  A token thief can no longer flood out the owner's pending challenge; identical requests reuse their challenge.
- **Audit log**: single-chain under threads and multiple processes; torn tail recovered and recorded
  (`LOG_RECOVERED`, bytes kept in `<log>.torn.*`); verify never crashes on garbage. Enrol/revoke/verify/reinstate
  events are logged. PII key created atomically and lazily.
- **Anchors**: Merkle v2 (domain separation, no duplicate-leaf ambiguity, count bound); anchoring a broken chain is refused.
- **Ops**: every in-memory structure is LRU-bounded; `state_dir=` persists baselines; recon detector wired via
  `meta["resource"]`; LLM reply parsing takes the first object with `findings`; user text is angle-bracket escaped;
  `kb-approve` requires `--path`.
- Known limits unchanged: a perfect impersonator on the owner's ISP and malware inside the owner's browser are
  stopped only by hardware-key approval; nothing was tested against real authenticators, a live model or Bitcoin.

## 1.1.0
- Real WebAuthn (FIDO2) verification: registration, assertion, UP/UV flags, signature counter, attestation hook.
  `ApprovalService` supports it (`allow_simple=False` for production) and can persist challenges (`store_path`).
- `SoftAuthenticator` for tests and demos; `edge.py` (JA3 from raw ClientHello, `build_meta`, ASN/geo lookup hook).
- Anthropic adapter now takes `base_url`/`timeout` and is tested against a local mock server; OpenTimestamps
  stamp/upgrade/verify tested against a fake client.
- `agent-gate calibrate`, `review`, `reinstate`, `kb-status`, `kb-approve`.
- VPN users no longer trigger impossible-travel on exit-node changes once VPN use is in their history.
- IP and device values in the audit log use a keyed hash (plain SHA-256 of an IPv4 address is reversible).

## 1.0.0
- First packaged release: content policy, behaviour baselines, device signing, decoys, transport fingerprint,
  ISP and destination checks, simplified hardware-key approval, hash-chained and anchored audit log.
