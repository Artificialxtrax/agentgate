import json, os, sys, threading, unittest, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))
import webauthn_demo as demo
from agentgate import SoftAuthenticator, b64u, b64u_dec


class DemoServer(unittest.TestCase):
    def test_full_flow_over_http_with_software_key(self):
        srv = demo.make_server(0); port = srv.server_address[1]
        demo.ORIGIN = f"http://localhost:{port}"; srv.app.approvals.origin = demo.ORIGIN
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        def post(p, b):
            r = urllib.request.Request(f"http://127.0.0.1:{port}{p}", json.dumps(b).encode(), {"content-type": "application/json"})
            return json.load(urllib.request.urlopen(r))
        try:
            key = SoftAuthenticator("localhost", demo.ORIGIN)
            ch = b64u_dec(post("/api/register/begin", {})["challenge"])
            reg = key.make_registration(ch)
            self.assertTrue(post("/api/register/finish", {"attestation_object": b64u(reg["attestation_object"]), "client_data_json": b64u(reg["client_data_json"])})["registered"])
            r = post("/api/act", {"text": "send", "destination": "https://hooks.acme.com/x"})
            self.assertEqual(r["action"], "STEP_UP")
            ap = dict(key.get_assertion(b64u_dec(r["challenge"]["webauthn_challenge"])), nonce=r["challenge"]["nonce"], device="demo-key")
            self.assertEqual(post("/api/act", {"text": "send", "destination": "https://hooks.acme.com/x", "approval": ap})["action"], "ALLOW")
            self.assertEqual(post("/api/act", {"text": "send", "destination": "https://hooks.acme.com/x", "approval": ap})["action"], "STEP_UP")   # replay
            r2 = post("/api/act", {"text": "send", "destination": "https://evil.example/x"})
            ap2 = dict(key.get_assertion(b64u_dec(r["challenge"]["webauthn_challenge"])), nonce=r["challenge"]["nonce"], device="demo-key")
            self.assertEqual(post("/api/act", {"text": "send", "destination": "https://evil.example/x", "approval": ap2})["action"], "STEP_UP")  # re-aimed
            self.assertTrue(json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/log"))["chain_ok"])
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
