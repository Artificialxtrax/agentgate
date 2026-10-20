import unittest
from agentgate.redteam import run


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, _ = run()

    def test_legit_users_not_annoyed(self):
        _, f, n = self.r["legit users (normal day)"]
        self.assertLessEqual(f / n, 0.02)

    def test_takeover_detected(self):
        _, det, cnt, leak, total = self.r["account takeover (new device, 3am, burst)"]
        self.assertGreaterEqual(det / cnt, 0.9)
        self.assertLess(leak / total, 0.35)

    def test_prober_and_sybil_mostly_detected(self):
        self.assertGreaterEqual(self.r["boundary prober (rewording, fresh account)"][1] / 20, 0.8)
        self.assertGreaterEqual(self.r["sybil farm (60 fresh accounts, 6 devices)"][1] / 60, 0.6)

    def test_claims_in_text_never_raise_trust(self):
        self.assertEqual(self.r["fake authority claim in text"][1], 20)

    def test_KNOWN_GAP_session_hijack_on_victims_own_device_is_not_detected(self):
        # documents an honest limit: identical device + hours + deniable requests look like the owner.
        # If this ever starts failing because detection IMPROVED, update the test and the README.
        self.assertEqual(self.r["session hijack (victim's device+hours, slow)"][1], 0)


if __name__ == "__main__":
    unittest.main()
