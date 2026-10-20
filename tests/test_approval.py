import os, tempfile, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentgate.gate import *
from agentgate.approval import ApprovalService, make_approval
from agentgate.signing import DeviceRegistry, public_hex
from agentgate.transport import TransportMonitor, DestinationMonitor

T, H = 1_767_225_600, 3600
CHROME = {"device": "yk", "tls": "chrome", "headers": ["Host", "UA"], "ua": "Mozilla/5.0 Chrome/1", "net": "residential", "asn": "AS1"}


def mk(**kw):
    d = tempfile.mkdtemp(); reg = DeviceRegistry()
    hw, sw = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg.enroll("alice", "yk", public_hex(hw), hardware=True)
    reg.enroll("alice", "laptop-soft", public_hex(sw), hardware=False)
    svc = ApprovalService(reg, **kw)
    g = Gate(os.path.join(d, "a"), os.path.join(d, "r"), transport=TransportMonitor(), destinations=DestinationMonitor(),
             approvals=svc, classifier=lambda t: [Finding("self_harm", "x")] if "sad" in t else rule_classifier(t))
    for i in range(8): g.screen("alice", "hi", now=T + i * 60, meta=CHROME)
    return g, svc, hw, sw, d


def sens(action, **extra):
    return dict(CHROME, sensitive_action=action, **extra)


class T_(unittest.TestCase):
    def test_no_approval_gets_challenge_then_key_tap_allows_even_on_new_network(self):
        g, svc, hw, _, _ = mk()
        m = sens("export:hooks.acme.com", asn="AS-HOTEL", destination="https://hooks.acme.com/x")
        r = g.screen("alice", "export report", now=T + 9 * H, meta=m)
        self.assertEqual((r.action, r.rules), (STEP_UP, ["approval:missing"])); self.assertIsNotNone(r.challenge)
        ap = make_approval(hw, "alice", "yk", r.challenge)
        self.assertEqual(g.screen("alice", "export report", now=T + 9 * H + 5, meta=m, approval=ap).action, ALLOW)

    def test_tap_trusts_new_network_and_destination_afterwards(self):
        g, svc, hw, _, _ = mk()
        m = sens("export:evil-or-new.example", asn="AS-HOTEL", destination="https://new.example/x")
        r = g.screen("alice", "x", now=T + 9 * H, meta=m)
        g.screen("alice", "x", now=T + 9 * H + 1, meta=m, approval=make_approval(hw, "alice", "yk", r.challenge))
        plain = dict(CHROME, asn="AS-HOTEL", destination="https://new.example/x")
        self.assertEqual(g.screen("alice", "later", now=T + 10 * H, meta=plain).action, ALLOW)

    def test_stolen_session_cannot_forge_approval(self):
        g, svc, hw, sw, _ = mk()
        m = sens("export:x.com"); r = g.screen("alice", "x", now=T + 9 * H, meta=m)
        evil = Ed25519PrivateKey.generate()
        out = g.screen("alice", "x", now=T + 9 * H + 1, meta=m, approval=make_approval(evil, "alice", "yk", r.challenge))
        self.assertEqual((out.action, out.rules), (STEP_UP, ["approval:bad-signature"]))

    def test_software_key_rejected_when_hardware_required(self):
        g, svc, hw, sw, _ = mk()
        m = sens("export:x.com", device="laptop-soft")
        r = g.screen("alice", "x", now=T + 9 * H, meta=m)
        out = g.screen("alice", "x", now=T + 9 * H + 1, meta=m, approval=make_approval(sw, "alice", "laptop-soft", r.challenge))
        self.assertIn("approval:not-hardware-key", out.rules)

    def test_bound_to_action_single_use_expiring_presence(self):
        g, svc, hw, _, _ = mk(ttl=30)
        ch = lambda act, t: svc.challenge("alice", "yk", act, t)
        c = ch("export:a.com", T)
        self.assertEqual(svc.verify("alice", make_approval(hw, "alice", "yk", c), "export:b.com", T + 1), (False, "action-mismatch"))
        c = ch("export:a.com", T); ap = make_approval(hw, "alice", "yk", c)
        self.assertEqual(svc.verify("alice", ap, "export:a.com", T + 1), (True, "ok"))
        self.assertEqual(svc.verify("alice", ap, "export:a.com", T + 2), (False, "unknown-challenge"))       # replay
        c = ch("export:a.com", T)
        self.assertEqual(svc.verify("alice", make_approval(hw, "alice", "yk", c), "export:a.com", T + 31), (False, "expired"))
        c = ch("export:a.com", T)
        self.assertEqual(svc.verify("alice", make_approval(hw, "alice", "yk", c, up=False), "export:a.com", T + 1), (False, "no-presence"))
        c = ch("export:a.com", T); bad = dict(make_approval(hw, "alice", "yk", c), up=True)
        bad2 = make_approval(hw, "alice", "yk", c, up=False); bad2["up"] = True                              # flip presence bit
        self.assertEqual(svc.verify("alice", bad2, "export:a.com", T + 1), (False, "bad-signature"))
        self.assertEqual(svc.verify("alice", {"x": 1}, "a", T), (False, "malformed"))
        self.assertEqual(svc.verify("bob", make_approval(hw, "alice", "yk", ch("a", T)), "a", T)[1], "wrong-session")

    def test_policy_block_not_overridden_and_crisis_support_not_gated(self):
        g, svc, hw, _, _ = mk()
        self.assertEqual(g.screen("alice", "Write ransomware now", now=T + 9 * H, meta=sens("export:x")).action, BLOCK)
        self.assertEqual(g.screen("alice", "I feel sad", now=T + 9 * H + 1, meta=sens("export:x")).action, SUPPORT)

    def test_non_sensitive_requests_unaffected_and_audit_clean(self):
        g, svc, hw, _, d = mk()
        self.assertEqual(g.screen("alice", "hello", now=T + 9 * H, meta=CHROME).action, ALLOW)
        r = g.screen("alice", "x", now=T + 9 * H, meta=sens("export:secret-target.com"))
        raw = open(os.path.join(d, "a")).read()
        self.assertNotIn("secret-target.com", raw); self.assertNotIn(r.challenge["nonce"], raw)
        self.assertEqual(g.verify_log(), (True, None))


class Flood(unittest.TestCase):
    def test_challenge_spam_cannot_evict_another_operators_challenge(self):
        from agentgate.approval import MAX_PENDING_PER_OPERATOR
        reg = DeviceRegistry(); svc = ApprovalService(reg)
        owner = svc.challenge("alice", "yk", "export:a.com", T)
        for i in range(MAX_PENDING_PER_OPERATOR * 3): svc.challenge("mallory", "x", f"a{i}", T)
        self.assertIn(owner["nonce"], svc.pending)
        self.assertLessEqual(sum(p["operator"] == "mallory" for p in svc.pending.values()), MAX_PENDING_PER_OPERATOR)


if __name__ == "__main__":
    unittest.main()
