import unittest
from examples.quickstart import main


class T(unittest.TestCase):
    def test_quickstart_behaves_as_documented(self):
        r = main()
        self.assertEqual(r["normal request"], "ALLOW")
        self.assertEqual(r["token thief, ordinary request"], "STEP_UP")
        self.assertEqual(r["sensitive action, no key tap"], "STEP_UP")
        self.assertEqual(r["sensitive action, key tapped"], "ALLOW")
        self.assertEqual(r["same tap replayed"], "STEP_UP")
        self.assertEqual(r["policy violation"], "BLOCK")
        self.assertEqual(r["decoy credential used"], "ESCALATE")
        self.assertTrue(r["audit log intact"])
