"""Phase 8a — free local alerts. The gates in docs/P8_WEBHOOKS_GATES.md.

Every delivery here goes to a real local HTTP server in this process, and the
cross-process cases run a real second interpreter, because the property under
test is that delivery survives the decider and never delays it.
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from trustband.alerts import AlertConfigError, classify, validate
from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall

POLICY = {"version": 1, "grants": [{
    "sess": "*", "max_tier": 2, "actions": ["read", "send"],
    "arg_bands": {"body": "session"}, "bands_when_present": True,
    "confirmable": True}]}


class _Sink:
    """A local endpoint that records every POST body. `hang=True` accepts
    the connection and never answers, which is the worst case for a sender."""

    def __init__(self, hang: bool = False, status: int = 200) -> None:
        self.bodies: list = []
        self.hang = hang
        sink = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n)
                if sink.hang:
                    time.sleep(8)
                    return
                sink.bodies.append(json.loads(raw))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/hook"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def wait(self, n: int = 1, timeout: float = 8.0) -> list:
        t0 = time.time()
        while len(self.bodies) < n and time.time() - t0 < timeout:
            time.sleep(0.05)
        return self.bodies


def _guard(url: str, tmp_path: Path, mode: str = "enforce", **extra) -> Guard:
    return Guard({**POLICY, "alerts": {"*": url, **extra}}, mode=mode,
                 audit_path=tmp_path / "audit.jsonl")


def _poison(g: Guard, session: str = "s1") -> None:
    g.after_tool_result(ToolCall(session, "read", {}), {"t": "poisoned-body-text"},
                        Band.TOOL)


# -- config ------------------------------------------------------------------

def test_alerts_config_is_validated_at_adoption():
    assert validate(None) == {}
    assert validate({"refusal": "https://x/y", "*": "http://z"})["*"] == "http://z"
    with pytest.raises(AlertConfigError):
        validate({"bogus": "https://x"})
    with pytest.raises(AlertConfigError):
        validate({"refusal": "ftp://x"})
    with pytest.raises(GuardConfigError):
        Guard({**POLICY, "alerts": {"refusal": 42}})


def test_classify_reads_the_record_only():
    assert classify({"event": "decision", "allowed": False, "reason": "taint"}) == "refusal"
    assert classify({"event": "decision", "allowed": True}) is None
    assert classify({"event": "decision", "allowed": False,
                     "reason": "session call cap reached: 5/5"}) == "runaway"
    assert classify({"event": "decision", "allowed": False,
                     "reason": "agent 'x' is revoked"}) == "agent_revoked"
    assert classify({"event": "result", "contracts": [{"held": False}]}) == "contract_failure"
    assert classify({"event": "result", "contracts": [{"held": True}]}) is None
    assert classify({"event": "lock_drift"}) == "lock_drift"


# -- P-P8a.3 / pair 1: the payload is the redacted record ---------------------

def test_refusal_delivers_the_redacted_record(tmp_path):
    sink = _Sink()
    g = _guard(sink.url, tmp_path)
    _poison(g)
    d = g.before_tool_call(ToolCall("s1", "send", {
        "body": "poisoned-body-text", "token": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX"}))
    assert not d.allowed
    (body,) = sink.wait(1)
    assert body["class"] == "refusal"
    assert body["text"].startswith("trustband refused send:")
    dumped = json.dumps(body)
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX" not in dumped, "raw credential delivered"
    assert body["event"]["tool"] == "send" and body["event"]["allowed"] is False


# -- pair 5: the delivered event equals the logged entry ----------------------

def test_delivered_event_equals_logged_entry(tmp_path):
    sink = _Sink()
    g = _guard(sink.url, tmp_path)
    _poison(g)
    g.before_tool_call(ToolCall("s1", "send", {"body": "poisoned-body-text"}))
    (body,) = sink.wait(1)
    logged = [json.loads(l)["body"] for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert body["event"] == logged[-1]


# -- P-P8a.5 / pair 2: shadow is silent per event ------------------------------

def test_shadow_does_not_alert_per_event(tmp_path):
    sink = _Sink()
    g = _guard(sink.url, tmp_path, mode="shadow")
    _poison(g)
    for _ in range(5):
        g.before_tool_call(ToolCall("s1", "send", {"body": "poisoned-body-text"}))
    assert g.shadow_log and all(not e["would_allow"] for e in g.shadow_log)
    time.sleep(1.0)
    assert sink.bodies == [] and g.alerts.dispatched == []


def test_shadow_digest_fires_once_from_the_cli(tmp_path):
    sink = _Sink()
    home = tmp_path
    (home / "policy.json").write_text(json.dumps({**POLICY, "alerts": {"*": sink.url}}))
    (home / "config.json").write_text(json.dumps({"policy": "policy.json", "mode": "shadow"}))
    obs = [{"session": "s", "tool": "send", "would_allow": False, "reason": "taint: body is tool",
            "confirmable": True, "bands": {"body": "tool"}}] * 3 + \
          [{"session": "s", "tool": "read", "would_allow": True, "reason": "", "bands": {}}] * 7
    (home / "shadow.jsonl").write_text("\n".join(json.dumps(o) for o in obs) + "\n")
    r = subprocess.run([sys.executable, "-m", "trustband.cli", "shadow-report", "--home", str(home)],
                       capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])))
    assert r.returncode == 0, r.stderr
    (body,) = sink.wait(1)
    assert body["class"] == "shadow_digest"
    assert body["event"]["would_refuse"] == 3 and body["event"]["observed"] == 10
    assert "3 of 10" in body["text"]
    time.sleep(0.5)
    assert len(sink.bodies) == 1, "the digest fires once, not per observation"


# -- P-P8a.1 / pair 4: a hung endpoint does not delay a decision ---------------

def test_hung_endpoint_does_not_delay_decisions(tmp_path):
    """P-P8a.1, measured two ways so noise cannot fake a pass or a fail.

    (1) The cost the design adds -- the spool write in fire() -- at p50 over
    200 calls, against the 1 ms gate. A spawned interpreter measured 67 ms
    here; the spool measures ~0.16 ms. (2) End to end against an endpoint
    that accepts and never answers: the 8 s hang must not appear, and the
    whole decision must stay well under the old notifier's cost.
    """
    hung = _Sink(hang=True)
    g = _guard(hung.url, tmp_path / "b")
    body = {"event": "decision", "tool": "send", "allowed": False, "reason": "taint"}
    xs = []
    for _ in range(200):
        t0 = time.perf_counter(); g.alerts.fire("refusal", body)
        xs.append((time.perf_counter() - t0) * 1000)
    assert statistics.median(xs) < 1.0, f"fire() p50 {statistics.median(xs):.3f} ms"

    _poison(g)
    ys = []
    for _ in range(30):
        t0 = time.perf_counter()
        g.before_tool_call(ToolCall("s1", "send", {"body": "poisoned-body-text"}))
        ys.append((time.perf_counter() - t0) * 1000)
    assert statistics.median(ys) < 5.0, f"decision p50 {statistics.median(ys):.2f} ms with a hung endpoint"


# -- P-P8a.2: delivery failure never changes a decision ------------------------

def test_delivery_failure_never_changes_a_decision(tmp_path):
    dead = "http://127.0.0.1:9/hook"                  # nothing listens on 9
    a = Guard(POLICY, mode="enforce", audit_path=tmp_path / "a.jsonl")
    b = _guard(dead, tmp_path / "b")
    for g in (a, b):
        _poison(g)
    calls = [ToolCall("s1", "send", {"body": "poisoned-body-text"}),
             ToolCall("s1", "send", {"body": "typed by hand"})]
    da = [(d.allowed, d.reason) for d in map(a.before_tool_call, calls)]
    db = [(d.allowed, d.reason) for d in map(b.before_tool_call, calls)]
    assert da == db
    assert b.alerts.errors == []                       # spooled fine; delivery failed later
    failed = tmp_path / "b" / "alerts_failed.jsonl"
    t0 = time.time()
    while not failed.exists() and time.time() - t0 < 8:
        time.sleep(0.1)
    assert failed.exists(), "the child records the failure beside the log"
    assert "refusal" in failed.read_text()


# -- P-P8a.4 / pair 3: delivery outlives a process that exits at once ----------

def test_delivery_outlives_the_deciding_process(tmp_path):
    """Pair 3. The decider exits the instant it decides. Nothing is lost:
    the alert is in the spool, and the NEXT process delivers it."""
    sink = _Sink()
    pol = {**POLICY, "alerts": {"*": sink.url}}
    code = f"""
import os
from trustband.guard import Guard, ToolCall
from trustband.gate import Band
g = Guard({pol!r}, mode="enforce", audit_path={str(tmp_path / 'hook.jsonl')!r})
g.after_tool_result(ToolCall("s1", "read", {{}}), {{"t": "poisoned-body-text"}}, Band.TOOL)
g.before_tool_call(ToolCall("s1", "send", {{"body": "poisoned-body-text"}}))
os._exit(0)   # gone before any thread could deliver
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    # spooled, or claimed by the dead process's drainer -- either survived
    spooled = list((tmp_path / "alerts_spool").glob("*"))
    assert len(spooled) == 1, f"the alert survived the process in the spool: {spooled}"
    # the next process -- here, the next hook call constructing a Guard
    r2 = subprocess.run([sys.executable, "-c", f"""
import time
from trustband.guard import Guard
g = Guard({pol!r}, mode="enforce", audit_path={str(tmp_path / 'hook.jsonl')!r})
g.alerts.drain_now()
"""], capture_output=True, text=True, env=env)
    assert r2.returncode == 0, r2.stderr
    (body,) = sink.wait(1)
    assert body["class"] == "refusal"
    assert not list((tmp_path / "alerts_spool").glob("*")), "spool is empty after delivery"


# -- other classes -------------------------------------------------------------

def test_runaway_and_contract_failure_and_revoked_classes(tmp_path):
    sink = _Sink()
    pol = {**POLICY, "session": {"max_calls": 1},
           "contracts": [{"name": "cov", "field": "coverage", "op": "at_least", "value": 90}]}
    g = Guard({**pol, "alerts": {"*": sink.url}}, mode="enforce",
              audit_path=tmp_path / "a.jsonl")
    g.before_tool_call(ToolCall("s1", "read", {}))
    g.before_tool_call(ToolCall("s1", "read", {}))                 # cap -> runaway
    g.after_tool_result(ToolCall("s1", "read", {}), {"coverage": 50})  # contract fails
    a = g.mint_agent("w", "w", "s2")
    g.revoke_agent(a)
    g.before_tool_call(ToolCall("s2", "read", {}, agent=a))        # revoked
    classes = sorted(b["class"] for b in sink.wait(3))
    assert classes == ["agent_revoked", "contract_failure", "runaway"]


def test_chain_break_fires_on_resume(tmp_path):
    sink = _Sink()
    log = tmp_path / "audit.jsonl"
    g = _guard(sink.url, tmp_path)
    g.before_tool_call(ToolCall("s1", "read", {}))
    g.before_tool_call(ToolCall("s1", "read", {}))
    lines = log.read_text().splitlines()
    d = json.loads(lines[0]); d["body"]["tool"] = "EDITED"
    log.write_text(json.dumps(d) + "\n" + "\n".join(lines[1:]) + "\n")
    _guard(sink.url, tmp_path)                                     # resume -> chain_break
    (body,) = sink.wait(1)
    assert body["class"] == "chain_break" and body["event"]["seq"] == 0


# -- pair 6: no hosted path, and identical under entitlement -------------------

def test_alerts_have_no_entitlement_path():
    import inspect
    import trustband.alerts as m
    src = inspect.getsource(m).lower()
    assert not any(w in src for w in ("entitlement", "api_key", "licen", "subscription"))
