# Deployment checklist

1. **Decide the policy.** Have legal/trust review `POLICY` and replace `laws_sample.json` with entries a lawyer
   has checked (`agent-gate kb-approve ID --reviewer "Name"`). Unreviewed entries are ignored by default.
2. **Plug in a model classifier.** `LLMClassifier(anthropic_llm(), LawKB(path))`. Measure its accuracy on your own
   labelled requests; the rules alone are only a floor.
3. **Supply edge data.** Use `edge.build_meta(...)` with JA3 from your reverse proxy and a GeoIP/ASN lookup.
4. **Enrol keys properly.** Use a WebAuthn flow in the browser, `verify_registration(..., attestation_verifier=...)`
   against FIDO MDS roots, then `DeviceRegistry.enroll_webauthn`. Set `ApprovalService(allow_simple=False,
   rp_id=..., origin=..., store_path=...)`. Mark which actions are sensitive via `meta["sensitive_action"]`.
5. **Run in shadow mode first.** Log decisions without enforcing, then `agent-gate calibrate audit.jsonl` and pick
   thresholds with an acceptable false-positive rate.
6. **Protect the keys and logs.** Back up `<log>.key` / `AGENT_GATE_PII_KEY`; restrict the review queue; set
   retention limits; publish anchor roots somewhere you cannot rewrite (git remote, Bitcoin via OpenTimestamps):
   `agent-gate anchor` on a schedule, `verify-anchors --external-roots` in audits.
7. **Staff the review queue.** `agent-gate review` lists escalations; `reinstate` clears strikes after a human
   decides. The gateway never contacts law enforcement.
8. **Plan the false positives.** Owners on new networks or VPNs will be asked to re-verify before sensitive
   actions. Give them a clear path and a human fallback.
9. **Multiple workers.** Challenge storage with `store_path` is shared only on one host; use a shared store for more.
10. **Build `meta` on the server.** `sensitive_action`, `destination` and `resource` must come from your route
    handler, never from client input. Missing device/TLS/UA data steps the request up (`require_edge_data=True`).
11. **Seed trust deliberately.** No destination is trusted until the owner approves it (`verify_identity`), and new
    devices become trusted only after repeated use over 24h or re-verification. Expect a few extra step-ups in week one.
12. **Persist state.** Pass `state_dir=` so baselines survive restarts, and canonical operator IDs from your auth system.
13. **Catch nothing.** `Gate.screen` never raises; treat any non-allowed action as final. Watch `gate.errors` and
    `ERROR` log records.
