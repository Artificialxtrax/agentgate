import os, tempfile, unittest
from agentgate.gate import *
from agentgate.webauthn import (cbor_decode, verify_registration, verify_assertion, WebAuthnError, b64u, ALG_EDDSA,
                                ALG_ES256, parse_auth_data)
from agentgate.softauth import SoftAuthenticator, cbor_encode
from agentgate.signing import DeviceRegistry
from agentgate.approval import ApprovalService, webauthn_challenge
from agentgate.transport import TransportMonitor

RP, ORIGIN, T, H = "example.com", "https://example.com", 1_767_225_600, 3600
CH = b"0123456789abcdef0123456789abcdef"


def reg(auth, **kw):
    r = auth.make_registration(CH, **{k: v for k, v in kw.items() if k in ("fmt", "rp_id", "origin", "up")})
    return verify_registration(r["attestation_object"], r["client_data_json"], kw.get("challenge", CH), RP, ORIGIN,
                               kw.get("require_uv", False), kw.get("verifier"))


class Cbor(unittest.TestCase):
    def test_roundtrip_and_malformed(self):
        v = {"a": [1, -1, 300, -70000, b"\x00\xff", "héllo"], 7: {"x": 2 ** 40}, -3: b""}
        self.assertEqual(cbor_decode(cbor_encode(v))[0], v)
        for bad in (b"", b"\x18", b"\x44ab", b"\xa1\x01", b"\x1f"):
            with self.assertRaises(WebAuthnError): cbor_decode(bad)
        with self.assertRaises(WebAuthnError): cbor_decode(b"\x81" * 40 + b"\x00")


class Registration(unittest.TestCase):
    def test_ok_es256_and_eddsa_not_attested_by_default(self):
        for alg in (ALG_ES256, ALG_EDDSA):
            c = reg(SoftAuthenticator(RP, ORIGIN, alg=alg))
            self.assertFalse(c["attested"]); self.assertEqual((c["alg"], c["fmt"]), (alg, "none"))

    def test_self_attestation_verified_but_still_not_hardware(self):
        self.assertFalse(reg(SoftAuthenticator(RP, ORIGIN), fmt="packed")["attested"])

    def test_attestation_verifier_hook_decides(self):
        calls = []
        def v(fmt, stmt, ad, cdh): calls.append(fmt); return True
        self.assertTrue(reg(SoftAuthenticator(RP, ORIGIN), fmt="fido-u2f-fake", verifier=v)["attested"])
        self.assertEqual(calls, ["fido-u2f-fake"])
        self.assertFalse(reg(SoftAuthenticator(RP, ORIGIN), fmt="fido-u2f-fake", verifier=lambda *a: False)["attested"])

    def test_rejections(self):
        a = SoftAuthenticator(RP, ORIGIN)
        for kw, err in (({"rp_id": "evil.com"}, "rpid-mismatch"), ({"origin": "https://evil.com"}, "origin-mismatch"),
                        ({"up": False}, "no-user-presence"), ({"challenge": b"other" * 7}, "challenge-mismatch")):
            with self.assertRaises(WebAuthnError, msg=err) as cm: reg(a, **kw)
            self.assertEqual(str(cm.exception), err)
        with self.assertRaises(WebAuthnError) as cm: reg(SoftAuthenticator(RP, ORIGIN, uv=False), require_uv=True)
        self.assertEqual(str(cm.exception), "no-user-verification")


class Assertion(unittest.TestCase):
    def setUp(self):
        self.a = SoftAuthenticator(RP, ORIGIN); self.cred = reg(self.a)

    def test_ok_updates_counter_and_blocks_rollback(self):
        n = verify_assertion(self.cred, self.a.get_assertion(CH), CH, RP, ORIGIN)
        self.assertEqual(n, 1); self.cred["sign_count"] = n
        old = self.a.get_assertion(CH, bump_counter=False)
        with self.assertRaises(WebAuthnError) as cm: verify_assertion(self.cred, old, CH, RP, ORIGIN)
        self.assertEqual(str(cm.exception), "counter-rollback")

    def test_every_failure_mode(self):
        good = self.a.get_assertion(CH)
        cases = {"challenge-mismatch": (good, b"x" * 32, RP, ORIGIN), "rpid-mismatch": (good, CH, "evil.com", ORIGIN),
                 "origin-mismatch": (good, CH, RP, "https://evil.com")}
        for err, (asr, ch, rp, org) in cases.items():
            with self.assertRaises(WebAuthnError) as cm: verify_assertion(dict(self.cred), asr, ch, rp, org)
            self.assertEqual(str(cm.exception), err)
        with self.assertRaises(WebAuthnError) as cm: verify_assertion(dict(self.cred), self.a.get_assertion(CH, up=False), CH, RP, ORIGIN)
        self.assertEqual(str(cm.exception), "no-user-presence")
        nouv = SoftAuthenticator(RP, ORIGIN, uv=False); nouv_cred = reg(nouv)
        with self.assertRaises(WebAuthnError) as cm:
            verify_assertion(dict(nouv_cred), nouv.get_assertion(CH), CH, RP, ORIGIN, require_uv=True)
        self.assertEqual(str(cm.exception), "no-user-verification")
        with self.assertRaises(WebAuthnError) as cm:                  # a different authenticator's credential id
            verify_assertion(dict(self.cred), nouv.get_assertion(CH), CH, RP, ORIGIN)
        self.assertEqual(str(cm.exception), "credential-mismatch")
        bad = dict(good); bad["signature"] = b64u(b"\x00" * 70)
        with self.assertRaises(WebAuthnError): verify_assertion(dict(self.cred), bad, CH, RP, ORIGIN)
        other = SoftAuthenticator(RP, ORIGIN); other.credential_id = self.a.credential_id
        with self.assertRaises(WebAuthnError) as cm: verify_assertion(dict(self.cred), other.get_assertion(CH), CH, RP, ORIGIN)
        self.assertEqual(str(cm.exception), "bad-signature")
        with self.assertRaises(WebAuthnError) as cm: verify_assertion(dict(self.cred), {"credential_id": self.cred["credential_id"]}, CH, RP, ORIGIN)
        self.assertEqual(str(cm.exception), "malformed")

    def test_eddsa_assertion(self):
        a = SoftAuthenticator(RP, ORIGIN, alg=ALG_EDDSA); c = reg(a)
        self.assertEqual(verify_assertion(c, a.get_assertion(CH), CH, RP, ORIGIN), 1)


class ApprovalWebAuthn(unittest.TestCase):
    def mk(self, attested=True, **svc):
        d = tempfile.mkdtemp(); r = DeviceRegistry(); self.auth = SoftAuthenticator(RP, ORIGIN)
        c = reg(self.auth); c["attested"] = attested
        r.enroll_webauthn("alice", "yk", c)
        service = ApprovalService(r, rp_id=RP, origin=ORIGIN, allow_simple=False, **svc)
        g = Gate(os.path.join(d, "a"), os.path.join(d, "r"), approvals=service, transport=TransportMonitor())
        meta = {"device": "yk", "tls": "t", "headers": ["Host"], "ua": "UA/1", "sensitive_action": "export:acme.com"}
        return g, service, meta, r

    def tap(self, ch, **kw):
        a = self.auth.get_assertion(__import__("base64").urlsafe_b64decode(ch["webauthn_challenge"] + "=="), **kw)
        return dict(a, nonce=ch["nonce"], device="yk")

    def test_full_flow_allow_replay_and_counter_persisted(self):
        g, svc, meta, r = self.mk()
        d1 = g.screen("alice", "export", now=T, meta=meta)
        self.assertEqual((d1.action, d1.rules), (STEP_UP, ["approval:missing"]))
        ap = self.tap(d1.challenge)
        self.assertEqual(g.screen("alice", "export", now=T + 5, meta=meta, approval=ap).action, ALLOW)
        self.assertEqual(r.devices["alice"]["yk"]["webauthn"]["sign_count"], 1)
        self.assertIn("approval:unknown-challenge", g.screen("alice", "export", now=T + 6, meta=meta, approval=ap).rules)

    def test_not_attested_is_not_hardware(self):
        g, svc, meta, _ = self.mk(attested=False)
        d1 = g.screen("alice", "export", now=T, meta=meta)
        out = g.screen("alice", "export", now=T + 1, meta=meta, approval=self.tap(d1.challenge))
        self.assertIn("approval:not-hardware-key", out.rules)

    def test_action_swap_simple_mode_and_config(self):
        g, svc, meta, r = self.mk()
        d1 = g.screen("alice", "x", now=T, meta=meta)
        other = dict(meta, sensitive_action="export:evil.com")
        out = g.screen("alice", "x", now=T + 1, meta=other, approval=self.tap(d1.challenge))
        self.assertTrue(any(x.startswith("approval:") for x in out.rules))      # challenge was for a different action
        self.assertEqual(svc.verify("alice", {"nonce": "n", "device": "yk", "sig": "00", "up": True}, "a", T), (False, "simple-mode-disabled"))
        self.assertEqual(ApprovalService(r).verify("alice", {"type": "webauthn", "nonce": "n", "device": "yk"}, "a", T),
                         (False, "webauthn-not-configured"))

    def test_uv_required_and_user_presence(self):
        g, svc, meta, _ = self.mk(require_uv=True)
        d1 = g.screen("alice", "x", now=T, meta=meta)
        out = g.screen("alice", "x", now=T + 1, meta=meta, approval=self.tap(d1.challenge, uv=False))
        self.assertIn("approval:webauthn:no-user-verification", out.rules)

    def test_persistent_store_shared_between_instances_single_use(self):
        d = tempfile.mkdtemp(); store = os.path.join(d, "pending.json")
        g, svc1, meta, r = self.mk(store_path=store)
        svc2 = ApprovalService(r, rp_id=RP, origin=ORIGIN, allow_simple=False, store_path=store)
        ch = svc1.challenge("alice", "yk", "export:acme.com", T)
        ap = self.tap(ch)
        self.assertEqual(svc2.verify("alice", ap, "export:acme.com", T + 1), (True, "ok"))           # other process
        self.assertEqual(svc1.verify("alice", ap, "export:acme.com", T + 2), (False, "unknown-challenge"))


if __name__ == "__main__":
    unittest.main()
