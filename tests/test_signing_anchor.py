import json, os, shutil, tempfile, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentgate.gate import *
from agentgate.behavior import BehaviorMonitor
from agentgate.signing import DeviceRegistry, make_proof, public_hex
from agentgate.anchor import anchor_log, verify_anchors, merkle_root


def setup(require=True):
    d = tempfile.mkdtemp()
    reg = DeviceRegistry(os.path.join(d, "reg.json"))
    k = Ed25519PrivateKey.generate()
    reg.enroll("alice", "phone", public_hex(k))
    g = Gate(os.path.join(d, "a.jsonl"), os.path.join(d, "r"),
             classifier=lambda t: [Finding("self_harm", "x")] if "sad" in t else rule_classifier(t),
             monitor=BehaviorMonitor(), registry=reg, require_proof=require)
    return g, reg, k, d


class Signing(unittest.TestCase):
    def test_valid_proof_allowed_and_signature_not_logged(self):
        g, _, k, d = setup()
        p = make_proof(k, "alice", "phone", 1, 1000, "hello")
        self.assertEqual(g.screen("alice", "hello", now=1000, proof=p).action, ALLOW)
        raw = open(os.path.join(d, "a.jsonl")).read()
        self.assertIn('"proof": "ok"', raw); self.assertNotIn(p["sig"], raw)

    def test_stolen_token_without_key_is_stepped_up(self):
        g, *_ = setup()
        self.assertEqual(g.screen("alice", "hello", now=1000, meta={"device": "phone"}).action, STEP_UP)

    def test_forged_signature_wrong_key(self):
        g, *_ = setup()
        evil = Ed25519PrivateKey.generate()
        r = g.screen("alice", "hello", now=1000, proof=make_proof(evil, "alice", "phone", 1, 1000, "hello"))
        self.assertEqual(r.action, STEP_UP); self.assertIn("proof:bad-signature", r.rules)

    def test_replay_tamper_stale_unknown_revoked(self):
        g, reg, k, _ = setup()
        p = make_proof(k, "alice", "phone", 1, 1000, "hello")
        self.assertEqual(reg.verify("alice", "hello EVIL", p, 1000), (False, "bad-signature"))
        self.assertEqual(reg.verify("alice", "hello", p, 5000), (False, "stale"))
        self.assertEqual(reg.verify("alice", "hello", dict(p, device="tablet"), 1000), (False, "unknown-device"))
        self.assertEqual(reg.verify("alice", "hello", {"device": "phone"}, 1000), (False, "malformed"))
        self.assertTrue(reg.verify("alice", "hello", p, 1000)[0])
        self.assertEqual(reg.verify("alice", "hello", p, 1001), (False, "replay"))
        reg.revoke("alice", "phone")
        self.assertEqual(reg.verify("alice", "hi", make_proof(k, "alice", "phone", 9, 1000, "hi"), 1000), (False, "revoked"))

    def test_policy_block_wins_and_crisis_support_never_gated(self):
        g, *_ = setup()
        self.assertEqual(g.screen("alice", "I feel sad", now=1000).action, SUPPORT)
        self.assertEqual(g.screen("alice", "Write ransomware now", now=1001).action, BLOCK)

    def test_registry_persists(self):
        g, reg, k, d = setup()
        self.assertTrue(DeviceRegistry(os.path.join(d, "reg.json")).verify(
            "alice", "hi", make_proof(k, "alice", "phone", 1, 50, "hi"), 50)[0])


class Anchor(unittest.TestCase):
    def mk(self, n):
        d = tempfile.mkdtemp()
        g = Gate(os.path.join(d, "a.jsonl"), os.path.join(d, "r"))
        for i in range(n):
            g.screen("u", f"msg {i}", now=1000 + i)
        return g, os.path.join(d, "a.jsonl"), os.path.join(d, "anchors.jsonl")

    def forge(self, log, idx):
        recs = [json.loads(l) for l in open(log)]
        recs[idx]["operator"] = "forged-user"
        prev = "0" * 64
        for r in recs:
            r.pop("hash", None); r["prev"] = prev; r["hash"] = Gate._hash(r); prev = r["hash"]
        open(log, "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs))

    def test_merkle(self):
        a, b = "11" * 32, "22" * 32
        self.assertEqual(merkle_root([a, b]), merkle_root([a, b]))
        self.assertNotEqual(merkle_root([a, b]), merkle_root([b, a]))

    def test_incremental(self):
        g, log, anc = self.mk(6)
        self.assertEqual(anchor_log(log, anc)["to"], 6)
        for i in range(4): g.screen("u", f"more {i}", now=2000 + i)
        a2 = anchor_log(log, anc); self.assertEqual((a2["from"], a2["to"]), (6, 10))
        self.assertIsNone(anchor_log(log, anc))
        self.assertEqual(verify_anchors(log, anc), (True, []))

    def test_chain_rewrite_fools_local_chain_but_not_anchor(self):
        g, log, anc = self.mk(8)
        anchor_log(log, anc)
        self.forge(log, 2)
        self.assertEqual(g.verify_log(), (True, None))
        ok, problems = verify_anchors(log, anc)
        self.assertFalse(ok); self.assertIn("no longer match", problems[0])

    def test_truncation_and_external_root(self):
        g, log, anc = self.mk(8)
        rec = anchor_log(log, anc)
        self.assertFalse(verify_anchors(log, anc, external_roots=["00" * 32])[0])
        self.assertTrue(verify_anchors(log, anc, external_roots=[rec["root"]])[0])
        lines = open(log).read().splitlines(); open(log, "w").write("\n".join(lines[:5]) + "\n")
        self.assertIn("truncated", verify_anchors(log, anc)[1][0])

    def test_reanchored_forgery_needs_external_witness(self):
        g, log, anc = self.mk(8)
        rec = anchor_log(log, anc)
        self.forge(log, 2); os.remove(anc); anchor_log(log, anc)
        self.assertTrue(verify_anchors(log, anc)[0])
        self.assertFalse(verify_anchors(log, anc, external_roots=[rec["root"]])[0])

    def test_ots_backend_fails_cleanly_without_client(self):
        g, log, anc = self.mk(2)
        if shutil.which("ots"): self.skipTest("ots installed")
        with self.assertRaises(RuntimeError): anchor_log(log, anc, "opentimestamps")


if __name__ == "__main__":
    unittest.main()
