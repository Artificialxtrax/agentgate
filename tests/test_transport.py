import os, tempfile, unittest
from agentgate.gate import *
from agentgate.transport import TransportMonitor, fingerprint, haversine_km

NYC, LA = (40.71, -74.0), (34.05, -118.24)
CHROME = {"device": "d1", "tls": "t13d1516h2_chrome", "headers": ["Host", "User-Agent", "Accept", "Accept-Language"],
          "ua": "Mozilla/5.0 Chrome/126.0.1", "geo": NYC, "net": "residential"}
H = 3600


def warm(m, op="a", meta=CHROME, n=8, t0=0):
    for i in range(n):
        a = m.assess(op, t0 + i * 60, meta); m.record(op, t0 + i * 60, meta, a)


class T(unittest.TestCase):
    def test_owner_clean_and_browser_update_tolerated(self):
        m = TransportMonitor(); warm(m)
        self.assertEqual(m.assess("a", 9 * H, CHROME).flags, [])
        self.assertEqual(m.assess("a", 9 * H, dict(CHROME, ua="Mozilla/5.0 Chrome/131.0.9")).flags, [])

    def test_script_with_stolen_token_flagged_and_steps_up(self):
        m = TransportMonitor(); warm(m)
        bot = dict(CHROME, tls="t13d1812h2_pyreq", headers=["Host", "Accept"], ua="python-requests/2.31")
        a = m.assess("a", 9 * H, bot)
        self.assertTrue({"fp-new-for-device", "automation-client"} <= set(a.flags)); self.assertEqual(a.recommend, "step_up")

    def test_api_customer_using_python_is_not_flagged(self):
        m = TransportMonitor(); api = dict(CHROME, tls="py", ua="python-requests/2", headers=["Host"], net="hosting")
        warm(m, meta=api)
        self.assertEqual(m.assess("a", 9 * H, api).flags, [])

    def test_impossible_travel_and_ok_travel(self):
        m = TransportMonitor(); warm(m)
        self.assertIn("impossible-travel", m.assess("a", 600 + 8 * 60, dict(CHROME, geo=LA)).flags)
        self.assertNotIn("impossible-travel", m.assess("a", 600 + 8 * 60 + 8 * H, dict(CHROME, geo=LA)).flags)

    def test_concurrent_clients_same_device(self):
        m = TransportMonitor(); warm(m)
        other = dict(CHROME, tls="impersonator", headers=["Host", "Accept"])
        self.assertIn("concurrent-clients", m.assess("a", 8 * 60 + 30, other).flags)

    def test_attacker_cannot_poison_baseline(self):
        m = TransportMonitor(); warm(m)
        bot = dict(CHROME, tls="evil", headers=["Host"], ua="curl/8")
        for i in range(10):
            a = m.assess("a", 9 * H + i * 3 * H, bot); m.record("a", 9 * H + i * 3 * H, bot, a)
        self.assertIn("fp-new-for-device", m.assess("a", 99 * H, bot).flags)

    def test_verify_trusts_new_client(self):
        m = TransportMonitor(); warm(m)
        newc = dict(CHROME, tls="firefox", headers=["Host", "Accept"], ua="Mozilla/5.0 Firefox/130")
        m.verify("a", newc, ts=9 * H)
        self.assertEqual(m.assess("a", 20 * H, newc).flags, [])

    def test_haversine_and_cold_start(self):
        self.assertTrue(3900 < haversine_km(NYC, LA) < 4000)
        self.assertEqual(TransportMonitor().assess("new", 0, CHROME).flags, [])

    def test_gate_integration_hashed_audit_and_crisis_not_gated(self):
        d = tempfile.mkdtemp(); m = TransportMonitor()
        g = Gate(os.path.join(d, "a"), os.path.join(d, "r"), transport=m,
                 classifier=lambda t: [Finding("self_harm", "x")] if "sad" in t else [])
        for i in range(8): g.screen("a", "hi", now=i * 60, meta=CHROME)
        bot = dict(CHROME, tls="evil", headers=["Host"], ua="curl/8")
        r = g.screen("a", "hello", now=9 * H, meta=bot)
        self.assertEqual(r.action, STEP_UP); self.assertTrue(r.rules[-1].startswith("transport:"))
        self.assertEqual(g.screen("a", "I feel sad", now=9 * H + 5, meta=bot).action, SUPPORT)
        raw = open(os.path.join(d, "a")).read()
        self.assertNotIn("curl/8", raw); self.assertNotIn("t13d1516h2_chrome", raw)
        self.assertEqual(g.verify_log(), (True, None))
        g.verify_identity("a", bot, now=9 * H + 10)


if __name__ == "__main__":
    unittest.main()


class PiiHash(unittest.TestCase):
    def test_ip_hash_is_keyed_not_bruteforceable_and_stable(self):
        import hashlib, json
        from agentgate.behavior import BehaviorMonitor
        d = tempfile.mkdtemp(); path = os.path.join(d, "a")
        g = Gate(path, os.path.join(d, "r"), monitor=BehaviorMonitor())
        g.screen("a", "hi", now=1, meta={"device": "phone", "ip": "203.0.113.7"})
        rec = json.loads(open(path).readline())
        plain = hashlib.sha256(b"203.0.113.7").hexdigest()[:16]
        self.assertNotEqual(rec["ip"], plain)                       # an attacker cannot just hash all IPv4s
        self.assertEqual(rec["ip"], g._pii("203.0.113.7"))          # key holder can match a known IP
        g2 = Gate(path, os.path.join(d, "r"), monitor=BehaviorMonitor())
        self.assertEqual(g2._pii("203.0.113.7"), rec["ip"])         # key persists across restarts
        self.assertEqual(oct(os.stat(path + ".key").st_mode & 0o777), "0o600")
