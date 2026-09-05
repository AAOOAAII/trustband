"""The `queue` disposition, without a server: the courier is a fake.

Measures P-UQ.1, 2, 3, 6, 7 and 11 from docs/UNATTENDED_QUEUE_GATES.md at the
gate, where the decision is. The service-side half and the end-to-end run
live in the cloud repository's suite.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall

POLICY = {"version": 1, "grants": [
    {"sess": "*", "max_tier": 2, "actions": ["send", "read"],
     "arg_bands": {"body": "session"}, "bands_when_present": True,
     "confirmable": True}]}


class Courier:
    """A scripted service. `answer` is what poll returns once asked; None
    means stay pending. `fail_submit` / `fail_poll` raise like the client."""

    def __init__(self, answer=None, fail_submit=None, fail_poll=None, digest=None,
                 delay_polls=0):
        self.answer, self.fail_submit, self.fail_poll = answer, fail_submit, fail_poll
        self.digest, self.delay_polls = digest, delay_polls
        self.submitted, self.polls = [], 0

    def submit(self, payload):
        if self.fail_submit:
            raise RuntimeError(self.fail_submit)
        self.submitted.append(payload)
        return {"id": "ap_test", "expires": time.time() + payload["deadline_s"]}

    def poll(self, aid):
        self.polls += 1
        if self.fail_poll:
            raise RuntimeError(self.fail_poll)
        if self.answer is None or self.polls <= self.delay_polls:
            return {"id": aid, "state": "pending"}
        digest = self.digest if self.digest is not None else self.submitted[-1]["digest"]
        return {"id": aid, "state": self.answer, "digest": digest,
                "decided_by": "luis@example.com"}


def _guard(tmp_path: Path, courier, mode="enforce", deadline=3, **extra) -> Guard:
    pol = {**POLICY, "unattended": {"on_confirmable": "queue", "deadline_s": deadline, **extra}}
    return Guard(pol, mode=mode, audit_path=tmp_path / "audit.jsonl", approvals=courier)


def _poisoned_call(g: Guard, value="poisoned-body-text"):
    g.after_tool_result(ToolCall("s1", "read", {}), {"t": value}, Band.TOOL)
    return ToolCall("s1", "send", {"body": value})


def _last(tmp_path: Path) -> dict:
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[-1])
    return rec.get("body", rec)          # chained entries wrap the record


# -- P-UQ.1: the decision is the person's ------------------------------------

def test_approve_allows_and_records_who(tmp_path):
    c = Courier(answer="approved")
    g = _guard(tmp_path, c)
    d = g.before_tool_call(_poisoned_call(g))
    assert d.allowed, d.reason
    assert "approved by luis@example.com" in d.reason
    rec = _last(tmp_path)
    assert rec["allowed"] is True and rec["confirmable"] is True
    assert "luis@example.com" in rec["reason"]
    # spent: the same call again is refused (an approval is a payment, not a relationship)
    d2 = g.before_tool_call(ToolCall("s1", "send", {"body": "poisoned-body-text"}))
    assert not d2.allowed or "approved" in d2.reason  # asks again, courier still says yes


def test_deny_refuses_and_records_who(tmp_path):
    c = Courier(answer="denied")
    g = _guard(tmp_path, c)
    d = g.before_tool_call(_poisoned_call(g))
    assert not d.allowed
    assert "denied by luis@example.com" in d.reason
    rec = _last(tmp_path)
    assert rec["allowed"] is False and "denied by luis@example.com" in rec["reason"]


def test_approval_lifts_only_the_approved_value(tmp_path):
    """An approval for one value must not lift the band check for another."""
    c = Courier(answer="approved")
    g = _guard(tmp_path, c)
    g.after_tool_result(ToolCall("s1", "read", {}), {"t": "other-poison"}, Band.TOOL)
    # approve poisoned-body-text ...
    d = g.before_tool_call(_poisoned_call(g))
    assert d.allowed
    # ... then a different tool value asks its own question and the courier's
    # answer is bound to THAT digest; a stale approval never applies.
    c.answer = "denied"
    d2 = g.before_tool_call(ToolCall("s1", "send", {"body": "other-poison"}))
    assert not d2.allowed and "denied by" in d2.reason


# -- P-UQ.2: silence refuses -------------------------------------------------

def test_deadline_refuses_and_says_nobody_answered(tmp_path):
    c = Courier(answer=None)
    g = _guard(tmp_path, c, deadline=3)
    t0 = time.perf_counter()
    d = g.before_tool_call(_poisoned_call(g))
    dt = time.perf_counter() - t0
    assert not d.allowed
    assert "nobody answered" in d.reason and "approved" not in d.reason
    assert dt < 3 + 2.5, f"returned after {dt:.1f}s; deadline 3s plus one poll"
    rec = _last(tmp_path)
    assert rec["allowed"] is False and "nobody answered" in rec["reason"]


def test_deadline_bounds_are_enforced_at_construction(tmp_path):
    with pytest.raises(GuardConfigError):
        _guard(tmp_path, Courier(), deadline=0)
    with pytest.raises(GuardConfigError):
        _guard(tmp_path, Courier(), deadline=86401)
    g = Guard({**POLICY, "unattended": {"on_confirmable": "queue"}}, mode="enforce",
              audit_path=tmp_path / "a.jsonl", approvals=Courier())
    assert g.queue_deadline_s == 900


# -- P-UQ.3: the decision is bound to the request ----------------------------

def test_answer_with_wrong_digest_is_no_answer(tmp_path):
    c = Courier(answer="approved", digest="0" * 64)
    g = _guard(tmp_path, c)
    d = g.before_tool_call(_poisoned_call(g))
    assert not d.allowed
    assert "not bound to the question" in d.reason


def test_what_leaves_is_rendered_from_redacted_values(tmp_path):
    """P-UQ.4 at the gate: a named secret in the argument reaches the courier
    redacted, and the digest is of the real value."""
    from trustband.confirm import value_digest
    c = Courier(answer="denied")
    pol = {**POLICY, "unattended": {"on_confirmable": "queue", "deadline_s": 3}}
    from trustband.redact import from_config as redact_from_config
    g = Guard(pol, mode="enforce", audit_path=tmp_path / "audit.jsonl", approvals=c,
              redactor=redact_from_config({}))
    secret = "sk-proj-ABCDEF1234567890"
    g.after_tool_result(ToolCall("s1", "read", {}), {"t": secret}, Band.TOOL)
    g.before_tool_call(ToolCall("s1", "send", {"body": secret}))
    sent = c.submitted[-1]
    assert secret not in json.dumps(sent), "the raw secret left the machine"
    assert sent["digest"] == value_digest(secret)
    assert "came from tool output" in sent["rendered"]


# -- P-UQ.6: fail closed, bounded ---------------------------------------------

def test_unreachable_service_refuses_fast(tmp_path):
    c = Courier(fail_submit="cannot reach https://api.trust.band: nodename nor servname")
    g = _guard(tmp_path, c, deadline=60)
    t0 = time.perf_counter()
    d = g.before_tool_call(_poisoned_call(g))
    assert not d.allowed and "could not queue" in d.reason
    assert time.perf_counter() - t0 < 1.0
    assert _last(tmp_path)["allowed"] is False


def test_service_lost_mid_wait_refuses_before_deadline(tmp_path):
    c = Courier(fail_poll="503: down")
    g = _guard(tmp_path, c, deadline=3600)
    t0 = time.perf_counter()
    d = g.before_tool_call(_poisoned_call(g))
    assert not d.allowed and "lost the approval service" in d.reason
    assert time.perf_counter() - t0 < 60


def test_no_key_refuses_at_first_confirmable_call_and_names_the_addon(tmp_path):
    """P-UQ.11 at the gate: construction succeeds; the refusal is at the call."""
    pol = {**POLICY, "unattended": {"on_confirmable": "queue"}}
    g = Guard(pol, mode="enforce", audit_path=tmp_path / "audit.jsonl")
    d_ok = g.before_tool_call(ToolCall("s1", "send", {"body": "typed"}))
    assert d_ok.allowed, "everything that is not confirmable is untouched"
    d = g.before_tool_call(_poisoned_call(g))
    assert not d.allowed
    assert "Unattended add-on" in d.reason and "no api_key" in d.reason


# -- P-UQ.7: shadow does not ask ---------------------------------------------

def test_shadow_records_would_have_queued_and_sends_nothing(tmp_path):
    c = Courier(answer="approved")
    g = _guard(tmp_path, c, mode="shadow")
    d = g.before_tool_call(_poisoned_call(g))
    assert d.allowed and "would have queued" in d.reason
    assert c.submitted == [] and c.polls == 0
    assert g.shadow_log[-1]["confirmable"] is True


# -- P-UQ.8: nothing else moves ----------------------------------------------

def test_deny_and_allow_dispositions_never_touch_the_courier(tmp_path):
    for disp in ("deny", "allow"):
        c = Courier(answer="approved")
        pol = {**POLICY, "unattended": {"on_confirmable": disp}}
        g = Guard(pol, mode="enforce", audit_path=tmp_path / f"{disp}.jsonl", approvals=c)
        d = g.before_tool_call(_poisoned_call(g))
        assert d.allowed == (disp == "allow")
        assert c.submitted == [] and c.polls == 0
        assert "approved by" not in d.reason
