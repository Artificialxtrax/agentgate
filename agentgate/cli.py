"""Command line: screen a request, verify/anchor the audit log, backtest behaviour rules, run the red team."""
from __future__ import annotations
import argparse
import json
import os
import sys

from . import __version__
from .anchor import anchor_log, verify_anchors
from .behavior import backtest
from .gate import Gate


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agent-gate", description="Policy gateway for AI-agent operators (alpha).")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("screen", help="screen one request (exit 3 if it is not allowed)")
    p.add_argument("text"); p.add_argument("--operator", default="cli"); p.add_argument("--tier", type=int, default=0, choices=[0, 1, 2])
    p.add_argument("--log", default="gate_audit.jsonl"); p.add_argument("--review", default="gate_review.jsonl")
    p.add_argument("--state", default="gate_state.json")
    p = sub.add_parser("verify-log", help="check the audit log hash chain"); p.add_argument("--log", default="gate_audit.jsonl")
    p = sub.add_parser("anchor", help="append a Merkle anchor of new log entries")
    p.add_argument("log"); p.add_argument("anchors"); p.add_argument("--backend", choices=["file", "opentimestamps"], default="file")
    p = sub.add_parser("verify-anchors", help="verify the log against its anchors")
    p.add_argument("log"); p.add_argument("anchors"); p.add_argument("--external-roots", help="file with one published root per line")
    p = sub.add_parser("backtest", help="replay an audit log through the behaviour monitor"); p.add_argument("log")
    p = sub.add_parser("review", help="list pending items in the human review queue"); p.add_argument("--review", default="gate_review.jsonl")
    p = sub.add_parser("reinstate", help="clear an operator's strikes after human review")
    p.add_argument("operator"); p.add_argument("--state", default="gate_state.json"); p.add_argument("--log", default="gate_audit.jsonl")
    p = sub.add_parser("calibrate", help="friction at each step-up threshold, from your own audit log"); p.add_argument("log")
    p = sub.add_parser("kb-status", help="which law-KB entries a human has reviewed"); p.add_argument("path", nargs="?")
    p = sub.add_parser("kb-approve", help="record that a qualified reviewer checked a law-KB entry")
    p.add_argument("id"); p.add_argument("--reviewer", required=True); p.add_argument("--path", required=True, help="path to the law-KB json (the packaged sample is never edited in place)")
    sub.add_parser("redteam", help="run the synthetic attacker/owner simulation")
    a = ap.parse_args(argv)

    if a.cmd == "screen":
        g = Gate(a.log, a.review, a.state)
        d = g.screen(a.operator, a.text, a.tier)
        print(json.dumps({"action": d.action, "categories": d.categories, "message": d.message, "strikes": d.strikes}, indent=2))
        sys.exit(0 if d.allowed else 3)
    if a.cmd == "verify-log":
        ok, bad = Gate(a.log, "/dev/null").verify_log()
        print("audit log OK" if ok else f"audit log TAMPERED at entry {bad}")
        sys.exit(0 if ok else 1)
    if a.cmd == "anchor":
        print(json.dumps(anchor_log(a.log, a.anchors, a.backend), indent=2))
    elif a.cmd == "verify-anchors":
        ext = [l.strip() for l in open(a.external_roots)] if a.external_roots else None
        ok, problems = verify_anchors(a.log, a.anchors, ext)
        print("anchors OK" if ok else "PROBLEMS:\n" + "\n".join(problems))
        sys.exit(0 if ok else 1)
    elif a.cmd == "backtest":
        print(json.dumps(backtest(a.log), indent=2))
    elif a.cmd == "review":
        try:
            items = [json.loads(l) for l in open(a.review) if l.strip()]
        except FileNotFoundError:
            items = []
        pending = [i for i in items if i.get("status") == "pending"]
        for i in pending:
            print(f"{i['ts']:.0f}  {i['operator']}  {','.join(i['categories'])}  {i.get('excerpt') or ''}"[:200])
        print(f"{len(pending)} pending")
    elif a.cmd == "reinstate":
        Gate(a.log, "/dev/null", a.state).reinstate(a.operator, by="cli")
        print(f"strikes cleared for {a.operator}")
    elif a.cmd == "calibrate":
        from .calibrate import calibrate, format_table
        print(format_table(calibrate(a.log)))
    elif a.cmd in ("kb-status", "kb-approve"):
        from .llm_classifier import kb_status, kb_approve
        path = a.path or os.path.join(os.path.dirname(__file__), "data", "laws_sample.json")   # kb-status may default
        if a.cmd == "kb-status":
            print(json.dumps(kb_status(path), indent=2))
        else:
            kb_approve(path, a.id, a.reviewer)
            print(f"{a.id} marked reviewed by {a.reviewer}")
    elif a.cmd == "redteam":
        from .redteam import run, report
        report(run()[0])
