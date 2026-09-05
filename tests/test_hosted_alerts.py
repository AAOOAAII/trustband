"""`hosted` as an alert destination, without the real service.

P-HA.1, 2, 4 (no key), 7 and 8 from docs/HOSTED_ALERTS_GATES.md. The
service half and the end-to-end run are in the cloud repository's suite.
"""
from __future__ import annotations

import json
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from trustband.alerts import HOSTED, NO_KEY, AlertConfigError, validate
from trustband.gate import Band
from trustband.guard import Guard, ToolCall

POLICY = {"version": 1, "grants": [
    {"sess": "*", "max_tier": 2, "actions": ["send", "read"],
     "arg_bands": {"body": "session"}, "bands_when_present": True}]}


class Sink:
    """A stand-in for api.trust.band/v1/alerts that records what arrives."""

    def __init__(self, status: int = 200):
        self.got: list = []
        sink = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                sink.got.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                 "body": json.loads(self.rfile.read(n) or b"{}")})
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"detail":{"reason":"cap"}}' if status == 429 else b'{"id":1}')

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"


def _home(tmp_path: Path, key: str | None, url: str) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    cfg = {"policy": "policy.json", "api_url": url}
    if key:
        cfg["api_key"] = key
    (home / "config.json").write_text(json.dumps(cfg))
    return home


def _guard(home: Path, dest: str, mode: str = "enforce") -> Guard:
    return Guard({**POLICY, "alerts": {"*": dest}}, mode=mode, audit_path=home / "audit.jsonl")


def _refuse(g: Guard, value: str = "poisoned-body-text") -> None:
    g.after_tool_result(ToolCall("s1", "read", {}), {"t": value}, Band.TOOL)
    g.before_tool_call(ToolCall("s1", "send", {"body": value}))


def test_hosted_is_a_valid_destination_and_nothing_else_new_is():
    assert validate({"*": HOSTED}) == {"*": HOSTED}
    assert validate({"refusal": "https://x/y", "runaway": HOSTED}) == {"refusal": "https://x/y", "runaway": HOSTED}
    with pytest.raises(AlertConfigError):
        validate({"*": "hosted-ish"})
    with pytest.raises(AlertConfigError):
        validate({"*": "trust.band"})


# -- P-HA.1: the decision path is unchanged ----------------------------------

def test_fire_costs_the_same_hosted_or_webhook(tmp_path):
    home = _home(tmp_path, "tb_live_" + "a" * 32, "http://127.0.0.1:9")
    body = {"event": "decision", "tool": "send", "allowed": False, "reason": "taint"}
    g_web = Guard({**POLICY, "alerts": {"*": "http://127.0.0.1:9/hook"}}, mode="enforce",
                  audit_path=home / "w" / "audit.jsonl")
    g_host = _guard(home, HOSTED)
    xs, ys = [], []
    for _ in range(200):
        t0 = time.perf_counter(); g_web.alerts.fire("refusal", body); xs.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); g_host.alerts.fire("refusal", body); ys.append(time.perf_counter() - t0)
    web, host = statistics.median(xs) * 1000, statistics.median(ys) * 1000
    assert host < max(1.0, 2 * web), f"hosted p50 {host:.3f} ms vs webhook {web:.3f} ms"


# -- P-HA.2: no key in the spool, ever ---------------------------------------

def test_no_key_in_any_spool_file_or_log(tmp_path):
    key = "tb_live_" + "b" * 32
    sink = Sink()
    home = _home(tmp_path, key, sink.url)
    g = _guard(home, HOSTED)
    g.alerts.background = False
    for i in range(100):
        _refuse(g, f"poisoned-{i}")
    spool = home / "alerts_spool"
    for f in spool.glob("*"):
        assert key not in f.read_text(), f"key in {f.name}"
    n = g.alerts.drain_now()
    assert n == 100 and len(sink.got) == 100
    assert all(r["auth"] == f"Bearer {key}" and r["path"] == "/v1/alerts" for r in sink.got)
    assert list(spool.glob("*")) == []
    failed = home / "alerts_failed.jsonl"
    assert not failed.exists() or key not in failed.read_text()


# -- P-HA.4: no key configured -----------------------------------------------

def test_no_key_records_a_reason_naming_the_addon_and_others_still_deliver(tmp_path):
    sink = Sink()
    home = _home(tmp_path, None, sink.url)
    g = Guard({**POLICY, "alerts": {"refusal": HOSTED, "runaway": sink.url + "/hook"}},
              mode="enforce", audit_path=home / "audit.jsonl")
    g.alerts.background = False
    _refuse(g)
    g.alerts.drain_now()
    failed = json.loads((home / "alerts_failed.jsonl").read_text().splitlines()[-1])
    assert "Unattended add-on" in failed["error"] and failed["error"] == NO_KEY[:200]
    assert sink.got == [], "nothing was sent without a key"
    # a webhook destination in the same policy is untouched
    g.alerts.fire("runaway", {"event": "decision", "tool": "send", "allowed": False, "reason": "cap reached"})
    g.alerts.drain_now()
    assert len(sink.got) == 1 and sink.got[0]["path"] == "/hook" and sink.got[0]["auth"] is None


def test_service_refusal_is_logged_and_the_spool_is_emptied(tmp_path):
    sink = Sink(status=429)
    home = _home(tmp_path, "tb_live_" + "c" * 32, sink.url)
    g = _guard(home, HOSTED)
    g.alerts.background = False
    _refuse(g)
    g.alerts.drain_now()
    failed = json.loads((home / "alerts_failed.jsonl").read_text().splitlines()[-1])
    assert failed["error"].startswith("HTTP 429") and "cap" in failed["error"]
    assert list((home / "alerts_spool").glob("*")) == []


# -- P-HA.7: shadow does not alert -------------------------------------------

def test_shadow_never_fires_per_event_through_hosted(tmp_path):
    sink = Sink()
    home = _home(tmp_path, "tb_live_" + "d" * 32, sink.url)
    g = _guard(home, HOSTED, mode="shadow")
    g.alerts.background = False
    _refuse(g)
    g.alerts.drain_now()
    assert sink.got == []
    # the digest is the one shadow alert, and it goes through hosted
    g.alerts.fire("shadow_digest", {"event": "shadow_digest", "would_refuse": 1, "observed": 2})
    g.alerts.drain_now()
    assert len(sink.got) == 1 and sink.got[0]["body"]["class"] == "shadow_digest"


# -- P-HA.5 at the package: the payload is the redacted record ----------------

def test_payload_is_the_redacted_record(tmp_path):
    from trustband.redact import from_config as redact_from_config
    sink = Sink()
    home = _home(tmp_path, "tb_live_" + "e" * 32, sink.url)
    g = Guard({**POLICY, "alerts": {"*": HOSTED}}, mode="enforce", audit_path=home / "audit.jsonl",
              redactor=redact_from_config({}))
    g.alerts.background = False
    secret = "sk-proj-ABCDEF1234567890XYZ"
    _refuse(g, secret)
    g.alerts.drain_now()
    assert secret not in json.dumps(sink.got[-1]["body"])
    assert "[redacted" in json.dumps(sink.got[-1]["body"])
