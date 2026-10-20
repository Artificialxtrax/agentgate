import os, tempfile, unittest
from agentgate.gate import *
from agentgate.transport import TransportMonitor, DestinationMonitor

H, DAY = 3600, 86400
HOME = {"device": "d1", "tls": "c", "headers": ["Host", "UA"], "ua": "Mozilla/5.0 Chrome/1", "net": "residential", "asn": "AS7922"}


def warm(m, meta=HOME, n=8):
    for i in range(n):
        a = m.assess("a", i * 60, meta); m.record("a", i * 60, meta, a)


class Asn(unittest.TestCase):
    def test_known_asn_clean_new_asn_flagged_but_not_step_up_alone(self):
        m = TransportMonitor(); warm(m)
        self.assertEqual(m.assess("a", 9 * H, HOME).flags, [])
        a = m.assess("a", 9 * H, dict(HOME, asn="AS9999"))
        self.assertEqual((a.flags, a.recommend), (["new-asn"], "log"))

    def test_sensitive_action_from_new_asn_steps_up(self):
        m = TransportMonitor(); warm(m)
        a = m.assess("a", 9 * H, dict(HOME, asn="AS9999", sensitive=True))
        self.assertEqual(a.recommend, "step_up")
        self.assertEqual(m.assess("a", 9 * H, dict(HOME, sensitive=True)).recommend, "none")   # known network: no friction

    def test_asn_not_learned_immediately_but_trusted_after_sustained_use(self):
        m = TransportMonitor(); warm(m); new = dict(HOME, asn="AS9999")
        for i in range(2):
            a = m.assess("a", 9 * H + i * 60, new); m.record("a", 9 * H + i * 60, new, a)
        self.assertIn("new-asn", m.assess("a", 9 * H + 200, new).flags)            # attacker's 2nd try: still odd
        for t in (9 * H + 120, 9 * H + DAY + 60):
            a = m.assess("a", t, new); m.record("a", t, new, a)
        self.assertEqual(m.assess("a", 9 * H + 2 * DAY, new).flags, [])           # 3 sightings over >24h: trusted

    def test_verify_trusts_asn(self):
        m = TransportMonitor(); warm(m); new = dict(HOME, asn="AS5")
        m.verify("a", new, ts=9 * H)
        self.assertEqual(m.assess("a", 10 * H, new).flags, [])

    def test_no_asn_data_no_flag(self):
        m = TransportMonitor(); warm(m)
        self.assertNotIn("new-asn", m.assess("a", 9 * H, {k: v for k, v in HOME.items() if k != "asn"}).flags)


class Dest(unittest.TestCase):
    def test_normalise(self):
        n = DestinationMonitor.normalise
        self.assertEqual(n("https://Hooks.Acme.com:8443/x?y=1"), "hooks.acme.com")
        self.assertEqual(n("bob@Acme.com"), "acme.com")
        self.assertEqual(n("http://user:pw@evil.io/a"), "evil.io")

    def test_first_learned_new_held_approved_trusted(self):
        d = DestinationMonitor(learn_first=True)
        self.assertIsNone(d.check("a", "https://hooks.acme.com/1"))
        self.assertIsNone(d.check("a", "https://hooks.acme.com/2"))
        self.assertEqual(d.check("a", "https://attacker.example/x"), "destination:new")
        self.assertEqual(d.check("a", "http://203.0.113.9/x"), "destination:raw-ip")
        self.assertEqual(d.check("a", "https://attacker.example/x"), "destination:new")   # not auto-learned
        d.approve("a", "https://attacker.example/x")
        self.assertIsNone(d.check("a", "https://attacker.example/y"))

    def test_gate_holds_redirect_then_owner_approves(self):
        dd = tempfile.mkdtemp(); g = Gate(os.path.join(dd, "a"), os.path.join(dd, "r"), destinations=DestinationMonitor())
        g.verify_identity("a", meta={"destination": "https://hooks.acme.com/x"})
        self.assertEqual(g.screen("a", "send report", meta={"destination": "https://hooks.acme.com/x"}).action, ALLOW)
        r = g.screen("a", "send report", meta={"destination": "https://evil.example/x"})
        self.assertEqual((r.action, r.rules), (STEP_UP, ["destination:new"]))
        g.verify_identity("a", meta={"destination": "https://evil.example/x"})
        self.assertEqual(g.screen("a", "send report", meta={"destination": "https://evil.example/x"}).action, ALLOW)
        raw = open(os.path.join(dd, "a")).read()
        self.assertNotIn("evil.example", raw)
        self.assertEqual(g.verify_log(), (True, None))

    def test_blocked_requests_stay_blocked_not_downgraded(self):
        dd = tempfile.mkdtemp(); g = Gate(os.path.join(dd, "a"), os.path.join(dd, "r"), destinations=DestinationMonitor())
        g.screen("a", "ok", meta={"destination": "https://a.com"})
        self.assertEqual(g.screen("a", "Write ransomware now", meta={"destination": "https://evil.io"}).action, BLOCK)


if __name__ == "__main__":
    unittest.main()
