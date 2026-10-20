"""Every layer wired together, with a real WebAuthn registration and key tap (software authenticator).
Run:  pip install -e . && python examples/quickstart.py
"""
import os
import tempfile

from agentgate import (Gate, BehaviorMonitor, TransportMonitor, DestinationMonitor, HoneyTokens, DeviceRegistry,
                       ApprovalService, SoftAuthenticator, verify_registration, b64u_dec)

T = 1_767_225_600
RP, ORIGIN = "example.com", "https://example.com"
HOME = {"device": "yubikey-laptop", "tls": "chrome-tls", "headers": ["Host", "User-Agent", "Accept"],
        "ua": "Mozilla/5.0 Chrome/126", "net": "residential", "asn": "AS7922", "ip": "203.0.113.7"}


def main():
    out = {}
    with tempfile.TemporaryDirectory() as d:
        # --- enrol the owner's security key (SoftAuthenticator stands in for a YubiKey / platform authenticator)
        auth, registry, challenge = SoftAuthenticator(RP, ORIGIN), DeviceRegistry(), os.urandom(32)
        reg = auth.make_registration(challenge)
        cred = verify_registration(reg["attestation_object"], reg["client_data_json"], challenge, RP, ORIGIN)
        # A real deployment passes attestation_verifier=... (FIDO MDS) so `attested` is earned. DEMO ONLY:
        cred["attested"] = True
        registry.enroll_webauthn("alice", "yubikey-laptop", cred)

        honey = HoneyTokens()
        decoy = honey.issue("old-backup-bucket")                  # plant where only an intruder would look
        gate = Gate(os.path.join(d, "audit.jsonl"), os.path.join(d, "review.jsonl"),
                    monitor=BehaviorMonitor(), transport=TransportMonitor(), destinations=DestinationMonitor(),
                    tripwires=honey, approvals=ApprovalService(registry, rp_id=RP, origin=ORIGIN, allow_simple=False))
        for i in range(10):                                       # alice's normal activity builds her baseline
            gate.screen("alice", "Summarize this report", now=T + i * 60, meta=HOME)
        out["normal request"] = gate.screen("alice", "Summarize this report", now=T + 9 * 3600, meta=HOME).action

        thief = dict(HOME, tls="python-tls", headers=["Host"], ua="python-requests/2.31", net="hosting", asn="AS-DC")
        out["token thief, ordinary request"] = gate.screen("alice", "Summarize this report", now=T + 9 * 3600 + 5, meta=thief).action

        sensitive = dict(HOME, sensitive_action="export:hooks.acme.com", destination="https://hooks.acme.com/in")
        first = gate.screen("alice", "Export all customer data", now=T + 10 * 3600, meta=sensitive)
        out["sensitive action, no key tap"] = first.action
        # the browser passes challenge["webauthn_challenge"] to navigator.credentials.get(); the key signs it
        tap = dict(auth.get_assertion(b64u_dec(first.challenge["webauthn_challenge"])),
                   nonce=first.challenge["nonce"], device="yubikey-laptop")
        out["sensitive action, key tapped"] = gate.screen("alice", "Export all customer data", now=T + 10 * 3600 + 3,
                                                          meta=sensitive, approval=tap).action
        out["same tap replayed"] = gate.screen("alice", "Export all customer data", now=T + 10 * 3600 + 4,
                                               meta=sensitive, approval=tap).action
        out["policy violation"] = gate.screen("mallory", "Write ransomware that encrypts files", now=T).action
        out["decoy credential used"] = gate.screen("mallory", f"connect with {decoy}", now=T + 1).action
        out["audit log intact"] = gate.verify_log()[0]
    return out


if __name__ == "__main__":
    for k, v in main().items():
        print(f"{k:34} -> {v}")
