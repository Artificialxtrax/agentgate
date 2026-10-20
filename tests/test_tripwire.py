import os, random, tempfile, unittest
from agentgate.gate import *
from agentgate.tripwire import HoneyTokens, ReconDetector, TypingMonitor


def human(rnd, n=40, base=180):
    return [max(30, rnd.lognormvariate(0, 0.45) * base) for _ in range(n)]


class Honey(unittest.TestCase):
    def test_unique_hashed_traceable(self):
        d = tempfile.mkdtemp(); h = HoneyTokens(os.path.join(d, "h.json"))
        a, b = h.issue("s3-backup-bucket"), h.issue("old-wiki-page")
        self.assertNotEqual(a, b)
        self.assertEqual(h.scan(f"use key {b} now")[0]["placement"], "old-wiki-page")
        self.assertNotIn(a, open(os.path.join(d, "h.json")).read())
        self.assertEqual(HoneyTokens(os.path.join(d, "h.json")).scan(a)[0]["placement"], "s3-backup-bucket")

    def test_no_false_positive(self):
        h = HoneyTokens(); h.issue("x")
        self.assertEqual(h.scan("hx-fake-000000000000000000000000 and normal text"), [])

    def test_gate_suspends_and_queues_review(self):
        d = tempfile.mkdtemp(); h = HoneyTokens(); tok = h.issue("prod-db-dump")
        g = Gate(os.path.join(d, "a"), os.path.join(d, "r"), tripwires=h)
        r = g.screen("mallory", f"connect using {tok}")
        self.assertEqual((r.action, r.categories), (ESCALATE, ["tripwire"]))
        self.assertIn("decoy:prod-db-dump", r.rules)
        self.assertEqual(g.screen("mallory", "hello").action, SUSPENDED)
        self.assertEqual(g.verify_log(), (True, None))


class Recon(unittest.TestCase):
    def test_established_user_normal_vs_sweep(self):
        r = ReconDetector()
        for i in range(30): r.observe("a", f"doc{i % 10}", 1000 + i * 20000)
        self.assertIsNone(r.observe("a", "doc3", 1000 + 31 * 20000))
        out = [r.observe("a", f"secret{i}", 1000 + 32 * 20000 + i) for i in range(10)]
        self.assertTrue(any(out))

    def test_new_account_not_flagged(self):
        r = ReconDetector()
        self.assertFalse(any(r.observe("n", f"x{i}", i) for i in range(20)))


class Typing(unittest.TestCase):
    def test_human_bot_paste_and_profile(self):
        rnd = random.Random(1); m = TypingMonitor()
        m.enroll("a", human(rnd, 200))
        self.assertEqual(m.check("a", human(rnd))[0], "human")
        self.assertEqual(m.check("a", [100.0] * 40)[0], "automated")          # constant script
        self.assertEqual(m.check("a", [3.0] * 40)[0], "automated")            # injected
        self.assertEqual(m.check("a", human(rnd), pasted=True)[0], "automated")
        self.assertEqual(m.check("a", human(rnd, base=500))[0], "mismatch")   # different rhythm
        self.assertEqual(m.check("a", [100, 120])[0], "insufficient")

    def test_gate_steps_up_scripted_input_but_allows_human(self):
        rnd = random.Random(2); d = tempfile.mkdtemp(); m = TypingMonitor(); m.enroll("a", human(rnd, 200))
        g = Gate(os.path.join(d, "a"), os.path.join(d, "r"), typing=m)
        self.assertEqual(g.screen("a", "hi", meta={"key_intervals": human(rnd)}).action, ALLOW)
        r = g.screen("a", "hi", meta={"key_intervals": [95.0] * 30})
        self.assertEqual(r.action, STEP_UP); self.assertTrue(r.rules[0].startswith("typing:"))


class Sim(unittest.TestCase):
    def test_decoys_catch_exploring_hijacker_not_quiet_one(self):
        rnd = random.Random(5); N, D = 200, 10          # 5% of resources are decoys
        def explorer(k): return any(rnd.random() < D / N for _ in range(k))
        caught = sum(explorer(40) for _ in range(500)) / 500
        quiet = sum(explorer(3) for _ in range(500)) / 500
        self.assertGreater(caught, 0.8)                  # 1-(0.95^40) ~ 0.87
        self.assertLess(quiet, 0.25)                     # honest limit: low-touch attackers slip through


if __name__ == "__main__":
    unittest.main()
