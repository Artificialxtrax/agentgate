# Review guide

Thanks for looking. agentgate is a pre-1.0-quality (v1.2.0) gateway that screens requests to AI agents and makes
stolen-session abuse harder. **It has had no independent review yet; that is what this document asks for.**

## 15-minute path
1. `python -m unittest discover -s tests -t .` (145 tests, no network).
2. `python examples/quickstart.py` shows the layers working together.
3. `python examples/webauthn_demo.py`, open http://localhost:8765, register a real security key or passkey and run the
   four buttons. **Please report the browser, OS, authenticator and whether each step behaved as the page describes.**
4. `python -m agentgate redteam` runs synthetic owners vs attackers (a protocol check, not a measured detection rate).

## Test status
Full list in `docs/TESTED.md`. In short: 145 tests on Python 3.9 and 3.13, plus one real-authenticator run (Apple
passkey on Chrome for macOS) of registration, approval, replay refusal and thief handling. No other authenticator yet.

## What to review, in priority order
| Area | File | Question |
|---|---|---|
| WebAuthn verification | `webauthn.py`, `approval.py` | Does it match the W3C spec checks (origin, rpIdHash, UP/UV, counter, challenge binding)? Any parser or CBOR edge case? |
| Action binding | `gate.py: bind_action`, `_util.normalise_host` | Can an approval be replayed, re-aimed or confused with another request? Parser differentials? |
| Fail-closed behaviour | `gate.py: screen` | Any path that returns an allowing decision after an error? |
| Audit log | `gate.py: _append_log`, `anchor.py` | Chain integrity under crashes and concurrent writers; Merkle construction. |
| Anti-poisoning | `behavior.py`, `transport.py` | Can an attacker teach the baseline their own device, hours, network or destination? |
| Policy / legal | `data/laws_sample.json`, `gate.py: RULES` | Counsel: are the entries accurate? Is the escalation/referral wording appropriate? (Entries are marked UNREVIEWED.) |

## Threat model in one paragraph
Attacker holds a valid session token (or can influence the agent's input) but not the owner's security key.
Goals: run a sensitive action, redirect output to their own endpoint, or make the gate learn their device.
Out of scope / not stopped: malware inside the owner's browser that can trick them into tapping; an attacker who
is indistinguishable from the owner on the owner's network and device, doing only low-risk actions; compromise of
the gateway host itself.

## Known limits
See README and CHANGELOG. In short: thresholds are untuned guesses; vendor attestation verification is a hook, not
shipped; nothing tested against a live model or Bitcoin; WebAuthn does not display the action on the key; state is
per-process unless you use `state_dir` / a shared store.

## Reporting
Security issues: see `SECURITY.md` (private first). Everything else: issues or pull requests.
