# Security policy

agentgate is alpha software that defends other systems, so its own flaws matter.

- **Report vulnerabilities privately** using GitHub's "Report a vulnerability" (private security advisory) on the
  repository, not a public issue. Include steps to reproduce and the version.
  If you cannot use GitHub advisories, email: **Artificialxtrax@outlook.com**.
- Highest priority: anything that lets a request skip a block, forges or replays an approval, weakens the audit
  log, or leaks personal data.
- The WebAuthn verifier (`webauthn.py`) and approval logic (`approval.py`, `signing.py`) were written for this
  project. They are tested against a software authenticator and one real Apple passkey run (see `docs/TESTED.md`),
  and have had no independent review. Independent review is welcome and recommended before production use.
- Known, documented limits (see README "What is NOT verified") are not vulnerabilities by themselves.
- This is a volunteer project: expect an acknowledgement within a few days, not a guaranteed fix time.
