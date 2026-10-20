# agentgate (alpha)

Layered screening and **session-hijack resistance** for platforms that let operators run AI agents.
Python 3.9+, one dependency (`cryptography`). It raises the cost of misuse and of account takeover.
It does not make either impossible, and it is not legal advice.

> **Status: alpha (v1.2.1).** Tested with synthetic data, simulated attackers, a software WebAuthn authenticator,
> local mocks of the model API and OpenTimestamps, and one real-authenticator run (an Apple passkey on Chrome for
> Mac, see `docs/TESTED.md`). Not yet run against real traffic, a standalone hardware security key, a live model,
> or the Bitcoin network. It has had a self-audit (24 defects found and fixed) but **no independent review yet**.
> Read "What is NOT verified" first, then `REVIEW.md` if you want to help.

## The idea

No single check stops a determined attacker, so each layer targets a different kind of one:

| Layer | Module | Catches | Does NOT catch |
|---|---|---|---|
| Content policy (rules + optional model grounded in a human-vetted law KB) | `gate`, `llm_classifier` | Clearly harmful requests; ambiguous ones go to human review | Rewording; rules are a weak floor, use a model |
| Behaviour baselines | `behavior` | New device + odd hour, bursts, probing, topic drift, many accounts on one device | A patient attacker acting like the owner |
| Device-bound signatures | `signing` | Stolen tokens / cookies / device IDs | Malware on the owner's own device |
| Decoys, recon, typing rhythm | `tripwire` | Intruders who explore; scripted or injected input | Attackers who touch nothing and type like a human |
| Transport fingerprint, ISP (ASN), geo, output destination | `transport`, `edge` | Scripts, headless browsers, foreign proxies, redirected output | Perfect client impersonation on the owner's own ISP |
| **WebAuthn key approval** of sensitive actions | `approval`, `webauthn` | Token thieves **and malware inside the owner's browser** (cannot make the signature) | A user tricked into approving a faked prompt |
| Hash-chained audit log + external anchoring | `gate`, `anchor` | Silent rewriting of history, even by whoever runs the server | Anything in real time |

Responses are graded: **block**, **escalate to a human**, **step-up** (re-verify), **allow-and-log**, **support**
(crisis resources, never gated or struck). Behavioural signals never block outright, because innocent causes
(new phone, VPN, travel) are common.

## Install and try it

```bash
pip install cryptography             # the only dependency
python -m unittest discover -s tests -t .             # 145 tests
PYTHONPATH=. python examples/quickstart.py            # every layer, including a WebAuthn registration and key tap
PYTHONPATH=. python examples/webauthn_demo.py         # browser demo: open http://localhost:8765 and use your own key
PYTHONPATH=. python -m agentgate redteam              # synthetic owners vs attackers
```

(`pip install -e .` also works and gives you the `agent-gate` command; the `PYTHONPATH=.` prefix is for running
straight from a checkout.)

CLI: `screen` · `verify-log` · `anchor` / `verify-anchors` · `backtest` · `calibrate` · `review` · `reinstate` ·
`kb-status` / `kb-approve` · `redteam`.

```python
from agentgate import Gate, BehaviorMonitor, TransportMonitor, DestinationMonitor, HoneyTokens, \
                      DeviceRegistry, ApprovalService, build_meta

gate = Gate("audit.jsonl", "review.jsonl", monitor=BehaviorMonitor(), transport=TransportMonitor(),
            destinations=DestinationMonitor(), tripwires=HoneyTokens(),
            approvals=ApprovalService(registry, rp_id="example.com", origin="https://example.com", allow_simple=False))
meta = build_meta(request_headers, device=device_id, client_hello=raw_hello, ip=ip, lookup=geoip_lookup,
                  sensitive_action="export:hooks.acme.com", destination=webhook_url)
d = gate.screen(operator_id, text, meta=meta, approval=client_approval)
if d.action == "STEP_UP" and d.challenge:
    ...  # pass d.challenge["webauthn_challenge"] to navigator.credentials.get(), then call screen() again
```

See `docs/DEPLOYMENT.md` for the production checklist.

## Measured results (synthetic, 40-50 simulated accounts; a regression baseline, not proof)

- Owners on a normal day: 0% friction. Browser auto-update: 0%.
- Token thief using a script or headless browser from a datacenter: stepped up 40/40.
- Perfect impersonator on another ISP: stepped up 40/40 **for sensitive actions only**; 0/40 for ordinary requests.
- Perfect impersonator on the owner's own ISP, and malware inside the owner's browser: 0/40 on every layer
  except the key tap. Sensitive actions need the physical key, which they cannot produce (a property of the
  protocol, covered by tests, not a measured detection rate).
- Owner on a new network doing a sensitive action: re-verification (one key tap). Owner whose VPN exits abroad:
  re-verification unless VPN use is already in their history.
- Output redirected to a new endpoint: held 40/40; the owner's usual endpoint allowed 40/40.
- Decoys at 5% of resources: a hijacker touching 40 resources is caught about 88% of the time; touching 3, about 14%.

## What is NOT verified

- **Almost no real authenticators.** `webauthn.py` is tested against a spec-following software authenticator and
  one real run (an Apple passkey, Chrome on macOS; registration, approval, replay refusal). Not tested with
  standalone hardware keys, other browsers or platforms, or the FIDO conformance suite. No vendor attestation roots are bundled: `attested` is true only if *your*
  `attestation_verifier` says so. Get it reviewed, or map a maintained library's result onto `enroll_webauthn`.
- **No live model or network.** The Anthropic adapter ran only against a local mock; OpenTimestamps only against a
  fake client. Real Bitcoin confirmation takes hours and was never exercised.
- **Law knowledge base is unreviewed sample text**, excluded by default until a qualified human approves entries.
- **Thresholds are guesses.** Run shadow mode and `agent-gate calibrate` on your own traffic.
- **JA3 and GeoIP** are tested on a hand-built ClientHello and stubbed lookups; `maxmind_lookup` is untested.
- `pip install .` could not be run end to end in the sandbox (broken system setuptools). `pyproject.toml` was
  validated with setuptools' parser and an equivalent wheel installed and ran. CI (`.github/workflows/ci.yml`) is
  provided but has not run yet. Developed on Python 3.13; the full suite has passed on Python 3.9 (macOS) and 3.13 (Linux).
- "What you see is what you sign": WebAuthn does not show the action on the key; use a trusted UI.

## OWASP Top 10 for LLM Applications (2025) mapping

agentgate sits **in front of** an agent (who is asking, and should this request run?). It does not inspect model
internals, training data or model output. This is a self-assessment against the
[2025 list](https://genai.owasp.org/llm-top-10/), not an OWASP endorsement or an independent review.

| ID | Risk | Coverage | Where | Notes |
|---|---|---|---|---|
| LLM01 | Prompt Injection | Partial | `gate`, `llm_classifier` | Rules run on raw and Unicode-normalised text; the optional model classifier treats the request as data inside stripped `<request>` tags, and rules always run too. Only screens the operator's request, not indirect injection via documents/tools the agent reads later. |
| LLM02 | Sensitive Information Disclosure | Partial | `transport` (`DestinationMonitor`), `tripwire`, `gate` | Holds output sent to a new destination, honey tokens flag leaked/used fake secrets, audit log stores keyed hashes not raw text. Does not scan model output for secrets or PII. |
| LLM03 | Supply Chain | Out of scope | - | One dependency (`cryptography`); no model/package provenance checks. |
| LLM04 | Data and Model Poisoning | Out of scope | - | No training or embedding data handled. (Behaviour baselines resist poisoning of *their own* state, which is a different thing.) |
| LLM05 | Improper Output Handling | Out of scope | - | Model output is not validated or sanitised. |
| LLM06 | Excessive Agency | Partial | `approval`, `webauthn`, `signing`, `gate` | Sensitive actions need a one-time, action-bound WebAuthn key approval; graded block/escalate/step-up; device-bound request signing. You must mark which actions are sensitive server-side; it does not limit tool permissions itself. |
| LLM07 | System Prompt Leakage | Out of scope | - | |
| LLM08 | Vector and Embedding Weaknesses | Out of scope | - | No RAG/vector store. |
| LLM09 | Misinformation | Out of scope | - | The law KB grounding limits what the *classifier* may cite; it does not check agent answers. |
| LLM10 | Unbounded Consumption | Partial | `behavior`, `_util` | Burst detection steps up rapid requesters; bounded LRU caches stop attackers growing monitor state. Not a rate limiter or token/cost budget. |

Abuse via **stolen sessions** (the main thing agentgate targets) is not its own Top 10 entry; it overlaps
LLM06 and general access control. Corrections welcome, see `REVIEW.md`.

## Privacy and legal notes

- The audit log stores hashes, not raw text. IPs and devices use a **keyed** hash (key in `<log>.key`, mode 600,
  or `AGENT_GATE_PII_KEY`); plain hashes of IPv4 addresses can be reversed in seconds. Back the key up and
  restrict access; whoever holds it can match a known IP against the log.
- Behaviour profiling and fingerprinting are personal-data processing in many jurisdictions: set retention
  limits, document the purpose, and give users a route to contest decisions.
- The gateway never contacts law enforcement. Referrals are human decisions made with counsel.
- Code cannot determine legality. It enforces the policy your legal/trust team writes.

MIT licensed. See `SECURITY.md` to report vulnerabilities and `CHANGELOG.md` for history.
