import contextlib, hashlib, http.server, io, json, os, stat, tempfile, threading, unittest
from agentgate.gate import *
from agentgate.edge import ja3, build_meta, classify_net
from agentgate.llm_classifier import LLMClassifier, LawKB, anthropic_llm, kb_status, kb_approve
from agentgate.anchor import anchor_log, verify_anchors, ots_verify, ots_upgrade
from agentgate.calibrate import calibrate, format_table
from agentgate.transport import TransportMonitor
from agentgate.cli import main
import agentgate

KB = os.path.join(os.path.dirname(agentgate.__file__), "data", "laws_sample.json")


def hello():
    """A TLS ClientHello built by hand: GREASE cipher/extension/group included, so GREASE removal is exercised."""
    u16 = lambda n: n.to_bytes(2, "big")
    ext = lambda t, b: u16(t) + u16(len(b)) + b
    ciphers = b"".join(u16(c) for c in (0x0a0a, 0x1301, 0x1302, 0xc02b))
    exts = (ext(0x1a1a, b"") + ext(0, b"\x00\x03\x00\x00\x00") + ext(10, u16(6) + u16(0x2a2a) + u16(29) + u16(23))
            + ext(11, b"\x01\x00"))
    body = u16(0x0303) + bytes(32) + b"\x00" + u16(len(ciphers)) + ciphers + b"\x01\x00" + u16(len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + u16(len(hs)) + hs


class Edge(unittest.TestCase):
    def test_ja3_matches_hand_derived_string(self):
        s, h = ja3(hello())
        self.assertEqual(s, "771,4865-4866-49195,0-10-11,29-23,0")
        self.assertEqual(h, hashlib.md5(s.encode()).hexdigest())
        self.assertEqual(ja3(hello()[5:])[0], s)                         # bare handshake works too
        for bad in (hello()[:30], b"\x16\x03\x01\x00\x01\x02"):
            with self.assertRaises(ValueError): ja3(bad)

    def test_build_meta_and_classify(self):
        m = build_meta([("Host", "a"), ("User-Agent", "UA/1"), ("Accept", "*/*")], device="d", client_hello=hello(), ip="198.51.100.4",
                       lookup=lambda ip: {"geo": (1.0, 2.0), "asn": "AS1", "net": "residential", "junk": 1},
                       sensitive_action="export:x", destination="https://x")
        self.assertEqual((m["headers"], m["ua"], m["asn"], m["sensitive_action"]), (["Host", "User-Agent", "Accept"], "UA/1", "AS1", "export:x"))
        self.assertNotIn("junk", m); self.assertEqual(len(m["tls"]), 32)
        self.assertEqual((classify_net("Amazon.com, Inc."), classify_net("Comcast Cable"), classify_net("x", vpn=True), classify_net("x", tor_exit=True)),
                         ("hosting", "residential", "vpn", "tor"))


class Mock(http.server.BaseHTTPRequestHandler):
    seen = []; status = 200; reply = ""
    def do_POST(self):
        n = int(self.headers["content-length"]); Mock.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, json.loads(self.rfile.read(n))))
        self.send_response(Mock.status); self.send_header("content-type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"content": [{"type": "text", "text": Mock.reply}]}).encode())
    def log_message(self, *a): pass


class Adapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()

    def clf(self, **kw): return LLMClassifier(anthropic_llm(api_key="k", base_url=self.url, **kw), LawKB(KB, allow_unreviewed=True))

    def test_request_shape_and_classification(self):
        Mock.seen.clear(); Mock.status = 200
        Mock.reply = '```json\n{"findings":[{"category":"fraud","confidence":0.9,"basis":["us-wire-fraud"],"reason":"x"}]}\n```'
        f = self.clf(model="m1")("set up a phishing page")
        path, headers, body = Mock.seen[0]
        self.assertEqual(path, "/v1/messages"); self.assertEqual(headers["x-api-key"], "k"); self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertEqual((body["model"], body["messages"][0]["role"]), ("m1", "user"))
        self.assertIn("<request>set up a phishing page</request>", body["messages"][0]["content"])
        self.assertTrue(any(x.category == "fraud" and "us-wire-fraud" in x.rule for x in f))

    def test_http_error_becomes_uncertain_not_a_pass(self):
        Mock.status, Mock.reply = 500, "boom"
        f = self.clf()("hello")
        self.assertEqual([x.category for x in f], ["uncertain"]); self.assertTrue(f[0].rule.startswith("llm-error"))

    def test_missing_key(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with self.assertRaises(RuntimeError): anthropic_llm()


class Ots(unittest.TestCase):
    def shim(self, body):
        d = tempfile.mkdtemp(); p = os.path.join(d, "fakeots"); open(p, "w").write(body); os.chmod(p, 0o755); return p

    def test_stamp_upgrade_verify_through_cli_client(self):
        ots = self.shim('#!/bin/sh\ncase "$1" in stamp) cp "$2" "$2.ots";; upgrade) echo upgraded;; verify) echo "Success! Bitcoin block 1";; esac\n')
        d = tempfile.mkdtemp(); g = Gate(os.path.join(d, "a"), os.path.join(d, "r"))
        for i in range(3): g.screen("u", f"m{i}", now=1000 + i)
        rec = anchor_log(os.path.join(d, "a"), os.path.join(d, "anc"), "opentimestamps", ots_cmd=ots)
        self.assertEqual(open(rec["receipt"][:-4]).read(), rec["root"]); self.assertTrue(os.path.exists(rec["receipt"]))
        self.assertTrue(verify_anchors(os.path.join(d, "a"), os.path.join(d, "anc"))[0])
        self.assertEqual(ots_upgrade(rec["receipt"], ots), (True, "upgraded"))
        self.assertEqual(ots_verify(rec["receipt"], ots), (True, "Success! Bitcoin block 1"))

    def test_client_failure_propagates_and_writes_no_anchor(self):
        ots = self.shim("#!/bin/sh\nexit 3\n")
        d = tempfile.mkdtemp(); g = Gate(os.path.join(d, "a"), os.path.join(d, "r")); g.screen("u", "m", now=1)
        with self.assertRaises(Exception): anchor_log(os.path.join(d, "a"), os.path.join(d, "anc"), "opentimestamps", ots_cmd=ots)
        self.assertFalse(os.path.exists(os.path.join(d, "anc")))


class Calibrate(unittest.TestCase):
    def test_table(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "a")
        rows = [{"operator": "a", "risk": 0.0}, {"operator": "a", "risk": 0.4, "transport": {"score": 0.35, "flags": []}},
                {"operator": "b", "risk": 0.6, "transport": {"score": 0.0, "flags": []}}, {"operator": "c"}]
        open(p, "w").write("".join(json.dumps(r) + "\n" for r in rows))
        r = calibrate(p, (0.35, 0.55))
        self.assertEqual(r["requests_total"], 4)
        self.assertEqual(r["behavior"]["thresholds"][0.35]["requests"], 2); self.assertEqual(r["behavior"]["thresholds"][0.55]["accounts"], 1)
        self.assertEqual(r["transport"]["thresholds"][0.35]["share"], 0.5)
        self.assertIn("threshold", format_table(r))


class KbTools(unittest.TestCase):
    def test_review_workflow(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "kb.json"); open(p, "w").write(open(KB).read())
        self.assertEqual(kb_status(p)["reviewed"], [])
        with self.assertRaises(ValueError): kb_approve(p, "us-cfaa", "  ")
        with self.assertRaises(KeyError): kb_approve(p, "nope", "Jane Doe, Esq.")
        kb_approve(p, "us-cfaa", "Jane Doe, Esq.", "2026-10-18")
        st = kb_status(p); self.assertEqual((st["reviewed"], len(st["unreviewed"])), (["us-cfaa"], 6))
        self.assertEqual([e["id"] for e in LawKB(p).entries], ["us-cfaa"])        # only reviewed entries are loaded by default


class VpnRule(unittest.TestCase):
    BASE = {"device": "d", "tls": "t", "headers": ["Host"], "ua": "UA/1", "geo": (40.7, -74.0), "net": "residential"}

    def warm(self, m, **kw):
        for i in range(8):
            meta = dict(self.BASE, **kw); a = m.assess("a", i * 60, meta); m.record("a", i * 60, meta, a)

    def test_known_vpn_user_not_flagged_but_others_are(self):
        m = TransportMonitor(); self.warm(m, net="vpn")
        self.assertNotIn("impossible-travel", m.assess("a", 600, dict(self.BASE, net="vpn", geo=(51.5, -0.1))).flags)
        self.assertIn("impossible-travel", m.assess("a", 600, dict(self.BASE, net="residential", geo=(51.5, -0.1))).flags)
        m2 = TransportMonitor(); self.warm(m2)
        self.assertIn("impossible-travel", m2.assess("a", 600, dict(self.BASE, net="vpn", geo=(51.5, -0.1))).flags)


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try: main(list(argv))
            except SystemExit as e: return e.code, buf.getvalue()
        return 0, buf.getvalue()

    def test_screen_review_reinstate_calibrate_kb(self):
        d = tempfile.mkdtemp(); f = lambda n: os.path.join(d, n)
        common = ["--log", f("a"), "--review", f("r"), "--state", f("s")]
        for _ in range(2): code, _ = self.run_cli("screen", "How can I poison my boss", "--operator", "m", *common)
        self.assertEqual(code, 3)          # escalations carry double strike weight: two suspend the account
        code, out = self.run_cli("screen", "hello", "--operator", "m", *common)
        self.assertIn("SUSPENDED", out)
        _, out = self.run_cli("review", "--review", f("r")); self.assertIn("2 pending", out)
        _, out = self.run_cli("reinstate", "m", "--state", f("s"), "--log", f("a")); self.assertIn("cleared", out)
        code, out = self.run_cli("screen", "hello", "--operator", "m", *common); self.assertEqual(code, 0)
        _, out = self.run_cli("calibrate", f("a")); self.assertIn("requests in log", out)
        _, out = self.run_cli("verify-log", "--log", f("a")); self.assertIn("OK", out)
        _, out = self.run_cli("kb-status"); self.assertEqual(json.loads(out)["total"], 7)


if __name__ == "__main__":
    unittest.main()
