"""Browser demo: approve a sensitive action with a REAL security key / passkey.

    python examples/webauthn_demo.py            # then open http://localhost:8765 in Chrome, Safari or Firefox

1. Click "Register key" and tap your YubiKey / Touch ID / Windows Hello / phone passkey.
2. Click "Send report" -> the gate answers STEP_UP and asks for the key. Tap it -> ALLOW.
3. Click "Replay that approval to a different destination" -> refused (action-mismatch).
4. Click "Act as a thief with only the session" -> STEP_UP, no challenge it can answer.
5. The log panel shows the hash-chained audit trail and whether it verifies.

This is a demo: one hard-coded user ("alice"), localhost only, `require_hardware=False` (we do not verify vendor
attestation here, so a software passkey also works). In production set require_hardware=True with an
attestation verifier. Please report what happens on your authenticator: that is exactly the test we need.
"""
import json, os, secrets, sys, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agentgate import (Gate, DeviceRegistry, ApprovalService, verify_registration, b64u, b64u_dec,
                       WebAuthnError)

PORT = int(os.environ.get("PORT", "8765"))
RP_ID, ORIGIN = "localhost", f"http://localhost:{PORT}"
USER, DEVICE = "alice", "demo-key"

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>agentgate key demo</title>
<style>body{font:16px system-ui;max-width:760px;margin:2rem auto;padding:0 16px}button{padding:.6rem 1rem;margin:.2rem 0;font-size:15px}
pre{background:#111;color:#cfe;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap}.row{margin:1rem 0}</style>
<h1>agentgate: physical-key approval</h1>
<div class=row><button id=reg>1. Register key</button></div>
<div class=row><input id=dest value="https://hooks.acme.com/report" size=40>
<button id=act>2. Send report (sensitive)</button></div>
<div class=row><button id=replay>3. Replay that approval to a different destination</button>
<button id=thief>4. Act as a thief with only the session</button></div>
<pre id=out>ready</pre><h3>Audit log</h3><pre id=log></pre>
<script>
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const unb=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const post=(p,b)=>fetch(p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
const show=x=>{out.textContent=JSON.stringify(x,null,2);refresh()};
const refresh=()=>fetch('/api/log').then(r=>r.json()).then(j=>log.textContent=(j.chain_ok?'chain OK\\n':'CHAIN BROKEN\\n')+j.tail.join('\\n'));
let lastApproval=null, credId=null;
reg.onclick=async()=>{try{const o=await post('/api/register/begin',{});
 const c=await navigator.credentials.create({publicKey:{challenge:unb(o.challenge),rp:{name:'agentgate demo',id:o.rp_id},
  user:{id:new TextEncoder().encode('alice'),name:'alice',displayName:'Alice'},
  pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-8}],attestation:'none',
  authenticatorSelection:{userVerification:'discouraged'}}});
 show(await post('/api/register/finish',{attestation_object:b64u(c.response.attestationObject),client_data_json:b64u(c.response.clientDataJSON)}));
 }catch(e){show({error:String(e)})}};
async function approve(ch,dest){const a=await navigator.credentials.get({publicKey:{challenge:unb(ch.webauthn_challenge),rpId:'localhost',
  userVerification:'discouraged',allowCredentials:[{type:'public-key',id:unb(credId)}]}});
 return {type:'webauthn',nonce:ch.nonce,device:'demo-key',credential_id:b64u(a.rawId),authenticator_data:b64u(a.response.authenticatorData),
  client_data_json:b64u(a.response.clientDataJSON),signature:b64u(a.response.signature)}}
act.onclick=async()=>{try{const d=dest.value;let r=await post('/api/act',{text:'send the weekly report',destination:d});
 if(r.credential_id)credId=r.credential_id;
 if(r.action==='STEP_UP'&&r.challenge){out.textContent='Tap your key...';lastApproval=await approve(r.challenge,d);
  r=await post('/api/act',{text:'send the weekly report',destination:d,approval:lastApproval});}
 show(r)}catch(e){show({error:String(e)})}};
replay.onclick=async()=>{if(!lastApproval)return show({error:'do step 2 first'});
 show(await post('/api/act',{text:'send the weekly report',destination:'https://attacker.example/steal',approval:lastApproval}))};
thief.onclick=async()=>show(await post('/api/act',{text:'send the weekly report',destination:'https://attacker.example/steal'}));
refresh();
</script>"""


class App:
    def __init__(self):
        d = tempfile.mkdtemp(prefix="agentgate-demo-")
        self.dir = d
        self.registry = DeviceRegistry()
        self.approvals = ApprovalService(self.registry, rp_id=RP_ID, origin=ORIGIN, allow_simple=False,
                                         require_hardware=False)
        self.gate = Gate(os.path.join(d, "audit.jsonl"), os.path.join(d, "review.jsonl"),
                         registry=self.registry, approvals=self.approvals)
        self.reg_challenge = None

    def handle(self, path, body):
        if path == "/api/register/begin":
            self.reg_challenge = secrets.token_bytes(32)
            return {"challenge": b64u(self.reg_challenge), "rp_id": RP_ID}
        if path == "/api/register/finish":
            try:
                cred = verify_registration(b64u_dec(body["attestation_object"]), b64u_dec(body["client_data_json"]),
                                           self.reg_challenge or b"", RP_ID, ORIGIN)
            except (WebAuthnError, KeyError, TypeError) as e:
                return {"registered": False, "error": str(e)}
            self.reg_challenge = None
            self.registry.enroll_webauthn(USER, DEVICE, cred)
            return {"registered": True, "credential_id": cred["credential_id"], "alg": cred["alg"], "fmt": cred["fmt"],
                    "note": "attested=%s (vendor attestation is not verified in this demo)" % cred["attested"]}
        if path == "/api/act":
            meta = {"device": DEVICE, "sensitive_action": "export_report", "destination": str(body.get("destination", ""))}
            d = self.gate.screen(USER, str(body.get("text", "")), meta=meta, approval=body.get("approval"))
            cred = (self.registry.devices.get(USER, {}).get(DEVICE, {}).get("webauthn") or {}).get("credential_id")
            out = {"action": d.action, "rules": d.rules, "message": d.message, "credential_id": cred,
                   "challenge": d.challenge}
            if not cred:
                out["hint"] = "register a key first"
            return out
        return {"error": "not found"}

    def log(self):
        ok, bad = self.gate.verify_log()
        lines = []
        if os.path.exists(self.gate.log_path):
            with open(self.gate.log_path) as f:
                lines = f.read().splitlines()[-6:]
        return {"chain_ok": ok, "tail": [json.dumps({k: v for k, v in json.loads(l).items() if k in ("kind", "action", "rules", "approval")}) for l in lines]}


def make_server(port=PORT):
    app = App()

    class H(BaseHTTPRequestHandler):
        def _send(self, code, data, ctype="application/json"):
            raw = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(code); self.send_header("content-type", ctype); self.send_header("content-length", str(len(raw)))
            self.send_header("cache-control", "no-store"); self.end_headers(); self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/":
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif self.path == "/api/log":
                self._send(200, app.log())
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = min(int(self.headers.get("content-length", 0)), 1_000_000)
                body = json.loads(self.rfile.read(n) or b"{}")
                self._send(200, app.handle(self.path, body))
            except Exception as e:
                self._send(400, {"error": type(e).__name__})

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", port), H)
    srv.app = app
    return srv


if __name__ == "__main__":
    s = make_server()
    print(f"open {ORIGIN}  (Ctrl-C to stop; audit log in {s.app.dir})")
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        pass
