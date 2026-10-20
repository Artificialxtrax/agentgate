# What has actually been tested

| Date | What | Where | Result |
|---|---|---|---|
| 2026-10-18 | Unit and integration suite (145 tests) | Python 3.13, Linux | pass |
| 2026-10-18 | Unit and integration suite (145 tests) | Python 3.9, macOS (Apple silicon) | pass (after two 3.9 fixes in 1.2.1) |
| 2026-10-18 | `examples/quickstart.py` | Python 3.9, macOS | all eight lines as expected |
| 2026-10-18 | `examples/webauthn_demo.py` with a **real authenticator**: Apple passkey (iCloud Keychain), Chrome on macOS | localhost | register OK; request held without tap; request allowed with tap; replayed approval refused (`unknown-challenge`); session-only thief held at `STEP_UP`; audit chain verified |

## Not yet tested
- Standalone hardware security keys (YubiKey etc.), Safari, Firefox, Windows Hello, Android.
- Vendor attestation verification (only a hook is provided).
- Real traffic, a live LLM classifier, Bitcoin anchoring via OpenTimestamps.
- Independent security review; legal review of the law knowledge base.

If you test another combination, please open an issue with: browser and version, OS, authenticator type, and what
each of the four demo buttons returned.
