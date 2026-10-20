import json, os, tempfile, unittest
from agentgate.gate import *
from agentgate.behavior import BehaviorMonitor, backtest

H = 3600
def warm(m, op="a", dev="d1", n=15, base=9 * H):
    for i in range(n):
        m.record(op, base + i * 60, dev, "ip1", False)


class T(unittest.TestCase):
    def test_cold_start_lenient(self):
        a = BehaviorMonitor().assess("new", 9 * H, "d9")
        self.assertEqual((a.flags, a.recommend), (["cold-start"], "none"))

    def test_new_device_plus_odd_hour_steps_up(self):
        m = BehaviorMonitor(); warm(m)
        a = m.assess("a", 3 * H + 86400, "d2")
        self.assertTrue({"new-device", "unusual-hour"} <= set(a.flags))
        self.assertEqual(a.recommend, "step_up")

    def test_new_device_alone_only_logged(self):
        m = BehaviorMonitor(); warm(m)
        a = m.assess("a", 9 * H + 86400, "d2")
        self.assertEqual((a.flags, a.recommend), (["new-device"], "log"))

    def test_known_device_hour_clean(self):
        m = BehaviorMonitor(); warm(m)
        self.assertEqual(m.assess("a", 9 * H + 86400, "d1").recommend, "none")

    def test_burst(self):
        m = BehaviorMonitor(); warm(m)
        for i in range(19): m.record("a", 86400 + 9 * H + i, "d1")
        self.assertIn("burst", m.assess("a", 86400 + 9 * H + 30, "d1").flags)

    def test_probing_and_cold_start_steps_up(self):
        m = BehaviorMonitor()
        for i in range(4): m.record("p", 1000 + i * 60, "d", flagged=True)
        a = m.assess("p", 1300, "d")
        self.assertIn("probing", a.flags); self.assertEqual(a.recommend, "step_up")

    def test_established_user_probing_only_logged(self):
        m = BehaviorMonitor(); warm(m)
        for i in range(4): m.record("a", 86400 + 9 * H + i * 60, "d1", flagged=True)
        self.assertEqual(m.assess("a", 86400 + 9 * H + 400, "d1").recommend, "log")

    def test_topic_drift(self):
        m = BehaviorMonitor(); warm(m, n=40)
        for i in range(8): m.record("a", 86400 + 9 * H + i * 3000, "d1", flagged=True)
        self.assertIn("topic-drift", m.assess("a", 86400 + 9 * H + 30000, "d1").flags)

    def test_shared_device_across_accounts(self):
        m = BehaviorMonitor()
        for i in range(3): m.record(f"s{i}", 100 + i, "dev-x")
        a = m.assess("s9", 500, "dev-x")
        self.assertIn("shared-device", a.flags); self.assertEqual(a.recommend, "step_up")

    def test_verify_trusts_device_and_clears_burst(self):
        m = BehaviorMonitor(); warm(m)
        m.verify("a", "d2", ts=86400)
        self.assertNotIn("new-device", m.assess("a", 86400 + 9 * H, "d2").flags)


class GateIntegration(unittest.TestCase):
    def mk(self):
        d = tempfile.mkdtemp()
        return Gate(os.path.join(d, "a"), os.path.join(d, "r"), classifier=lambda t: [Finding("self_harm", "x")] if "sad" in t else [],
                    monitor=BehaviorMonitor()), d

    def test_step_up_blocks_clean_request_and_verify_clears(self):
        g, _ = self.mk()
        for i in range(3): g.monitor.record(f"s{i}", 100 + i, "devx", "ip")
        d = g.screen("victim", "hello", now=500, meta={"device": "devx", "ip": "ip"})
        self.assertEqual(d.action, STEP_UP); self.assertFalse(d.allowed)

    def test_crisis_support_never_gated(self):
        g, _ = self.mk()
        for i in range(3): g.monitor.record(f"s{i}", 100 + i, "devx", "ip")
        self.assertEqual(g.screen("victim", "I feel sad", now=500, meta={"device": "devx", "ip": "ip"}).action, SUPPORT)

    def test_audit_has_risk_and_hashed_device_and_chain_ok(self):
        g, d = self.mk()
        g.screen("a", "hello", now=1, meta={"device": "my-phone", "ip": "1.2.3.4"})
        raw = open(os.path.join(d, "a")).read()
        self.assertIn('"risk"', raw); self.assertNotIn("my-phone", raw); self.assertNotIn("1.2.3.4", raw)
        self.assertEqual(g.verify_log(), (True, None))

    def test_backtest_replays_log(self):
        g, d = self.mk()
        for i in range(3): g.screen(f"s{i}", "hi", now=100 + i, meta={"device": "devx"})
        g.screen("v", "hi", now=500, meta={"device": "devx"})
        r = backtest(os.path.join(d, "a"))
        self.assertEqual(r["counts"]["requests"], 4); self.assertEqual(r["counts"]["step_up"], 1)


if __name__ == "__main__":
    unittest.main()
