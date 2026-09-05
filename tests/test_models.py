"""Model constraints in policy. P-MC.1 to P-MC.7, P-MC.9, P-MC.10 from
docs/MODEL_CONSTRAINTS_GATES.md. The LangChain half is test_model_gate_langchain.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall
from trustband.models import ModelConfigError, ModelPolicy

BASE = {"version": 1, "grants": [
    {"sess": "*", "max_tier": 2, "actions": ["send", "read"],
     "arg_bands": {"body": "session"}, "bands_when_present": True}]}

MODELS = {
    "allow": ["gpt-4o*", "claude-*", "local-*"],
    "by_band": {"tool": ["gpt-4o-mini", "local-*"], "user": ["gpt-4o-mini"]},
    "max_tokens_per_call": 20000,
    "max_cost_per_session": 100,
    "prices": {"gpt-4o": {"in": 250, "out": 1000}, "gpt-4o-mini": {"in": 15, "out": 60}},
    "pin": True,
}


def _g(tmp_path: Path, models=MODELS, mode="enforce", **kw) -> Guard:
    pol = {**BASE, **({"models": models} if models is not None else {})}
    return Guard(pol, mode=mode, audit_path=tmp_path / "audit.jsonl", **kw)


def _entries(tmp_path: Path, event: str) -> list:
    out = []
    for line in (tmp_path / "audit.jsonl").read_text().splitlines():
        rec = json.loads(line); rec = rec.get("body", rec)
        if rec.get("event") == event:
            out.append(rec)
    return out


# -- P-MC.1: absent is unchanged --------------------------------------------

def test_absent_allows_everything_and_says_so(tmp_path):
    g = _g(tmp_path, models=None)
    d = g.before_model_call("s1", "anything-at-all")
    assert d.allowed and "no model constraints" in d.reason and d.hint == {"models": ["*"], "max_tokens": None}
    assert g.models.enabled is False


def test_validation_at_adoption():
    for bad in ({"allow": []}, {"by_band": {"nope": ["x"]}}, {"max_tokens_per_call": 0},
                {"max_cost_per_session": -1}, {"max_cost_per_session": 1.5}, {"prices": {"m": {"in": "a"}}}, {"prices": {"m": {"in": 2.5}}}, {"pin": "yes"},
                {"unknown": 1}):
        with pytest.raises(ModelConfigError):
            ModelPolicy.from_policy(bad)
    with pytest.raises(GuardConfigError):
        Guard({**BASE, "models": {"allow": []}}, mode="enforce")


# -- P-MC.2: residency by band ------------------------------------------------

def test_session_only_reaches_anything_in_allow(tmp_path):
    g = _g(tmp_path)
    assert g.before_model_call("s1", "gpt-4o").allowed
    assert g.before_model_call("s1", "claude-opus").allowed
    d = g.before_model_call("s1", "llama-70b")
    assert not d.allowed and "not in models.allow" in d.reason


def test_tool_content_narrows_to_by_band_tool(tmp_path):
    g = _g(tmp_path)
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    d = g.before_model_call("s1", "gpt-4o")
    assert not d.allowed and "tool-band content" in d.reason and "gpt-4o-mini" in d.reason
    assert g.before_model_call("s1", "gpt-4o-mini").allowed
    assert g.before_model_call("s1", "local-qwen").allowed
    assert d.hint["models"] == ["gpt-4o-mini", "local-*"]
    assert d.conjunct == "model"


def test_two_bands_intersect(tmp_path):
    g = _g(tmp_path)
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    g.after_tool_result(ToolCall("s1", "read", {}), {"msg": "an external user wrote this text"}, Band.USER)
    d = g.before_model_call("s1", "local-qwen")
    assert not d.allowed and "user-band" in d.reason
    assert g.before_model_call("s1", "gpt-4o-mini").allowed
    assert g.before_model_call("s1", "gpt-4o-mini").hint["models"] == ["gpt-4o-mini"]


def test_explicit_context_bands_win_over_the_store(tmp_path):
    g = _g(tmp_path)
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    # the adapter saw the messages and none of them carries tool content
    assert g.before_model_call("s1", "gpt-4o", context_bands={Band.SESSION}).allowed
    # and the reverse: the store is clean but the messages carry it
    assert not g.before_model_call("s2", "gpt-4o", context_bands={Band.SESSION, Band.TOOL}).allowed
    # context_bands from texts recalls each text's band
    bands = g.context_bands("s1", ["typed by hand", "some untrusted page text here"])
    assert bands == {Band.SESSION, Band.TOOL}


# -- P-MC.3: cost is refused at the gate ---------------------------------------

def test_cost_ceiling_refuses_the_next_call(tmp_path):
    g = _g(tmp_path)
    assert g.before_model_call("s1", "gpt-4o").allowed
    spent = g.record_model_usage("s1", "gpt-4o", 200_000, 50_000)      # 50 + 50 = 100 minor units
    assert abs(spent - 100.0) < 1e-9
    d = g.before_model_call("s1", "gpt-4o")
    assert not d.allowed and "cost ceiling" in d.reason and "100.00" in d.reason
    assert g.before_model_call("s2", "gpt-4o").allowed, "per session"
    usage = _entries(tmp_path, "model_usage")
    assert usage[-1]["cost"] == 100.0 and usage[-1]["priced"] is True
    # an unpriced model is charged at zero and the record says so
    g.record_model_usage("s3", "claude-opus", 1_000_000, 1_000_000)
    assert _entries(tmp_path, "model_usage")[-1]["priced"] is False


def test_per_call_limit_refuses_before_the_call(tmp_path):
    g = _g(tmp_path)
    d = g.before_model_call("s1", "gpt-4o", tokens_in=20_001)
    assert not d.allowed and "per call" in d.reason
    assert g.before_model_call("s1", "gpt-4o", tokens_in=20_000).allowed


def test_refusals_alert_as_runaway_or_refusal(tmp_path):
    from trustband.alerts import classify
    g = _g(tmp_path)
    g.record_model_usage("s1", "gpt-4o", 400_000, 0)
    g.before_model_call("s1", "gpt-4o")
    g.before_model_call("s2", "llama-70b")
    recs = _entries(tmp_path, "model")
    assert classify(recs[-2]) == "runaway" and classify(recs[-1]) == "refusal"
    assert classify(_entries(tmp_path, "model")[0]) in ("runaway", "refusal")


# -- P-MC.4: the hint is the intersection ----------------------------------------

def test_hint_models_and_tokens(tmp_path):
    g = _g(tmp_path)
    d = g.before_model_call("s1", "gpt-4o")
    assert d.hint["models"] == ["gpt-4o*", "claude-*", "local-*"]
    # budget 100 at the cheapest permitted priced rate (gpt-4o-mini in: 15/M -> 6.67M tokens) vs per-call 20000
    assert d.hint["max_tokens"] == 20000
    g.record_model_usage("s1", "gpt-4o", 399_000, 0)                    # spent 99.75; 0.25 left
    d2 = g.before_model_call("s1", "gpt-4o")
    assert d2.allowed and d2.hint["max_tokens"] == int(0.25 * 1_000_000 / 15)


# -- P-MC.5: the pin is drift ----------------------------------------------------

def test_version_change_is_drift(tmp_path):
    g = _g(tmp_path)
    assert g.before_model_call("s1", "gpt-4o", version="gpt-4o-2025-01-01").allowed
    g.record_model_usage("s1", "gpt-4o", 10, 10, version="gpt-4o-2025-01-01")
    assert g.accept_lock() >= 1
    assert g.before_model_call("s1", "gpt-4o", version="gpt-4o-2025-01-01").allowed
    # the provider answers with a new snapshot: recorded as drift, next call refuses
    g.record_model_usage("s1", "gpt-4o", 10, 10, version="gpt-4o-2026-06-01")
    drift = _entries(tmp_path, "lock_drift")
    assert drift and drift[-1]["item"] == "model:gpt-4o" and drift[-1]["kind"] == "model"
    d = g.before_model_call("s1", "gpt-4o")
    assert not d.allowed and "changed since it was pinned" in d.reason
    assert g.accept_lock() >= 1
    assert g.before_model_call("s1", "gpt-4o", version="gpt-4o-2026-06-01").allowed


def test_version_change_flags_under_shadow(tmp_path):
    g = _g(tmp_path, mode="shadow")
    g.record_model_usage("s1", "gpt-4o", 10, 10, version="v1")
    g.accept_lock()
    g.record_model_usage("s1", "gpt-4o", 10, 10, version="v2")
    d = g.before_model_call("s1", "gpt-4o")
    assert d.allowed and "would have refused" in d.reason and "pinned" in d.reason


# -- P-MC.6: shadow, and no key vocabulary -----------------------------------------

def test_shadow_allows_and_records_would_refuse(tmp_path):
    g = _g(tmp_path, mode="shadow")
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    d = g.before_model_call("s1", "gpt-4o")
    assert d.allowed and d.reason.startswith("SHADOW: would have refused")
    assert g.shadow_log[-1]["would_allow"] is False and g.shadow_log[-1]["tool"] == "model:gpt-4o"
    assert _entries(tmp_path, "model")[-1]["allowed"] is False


def test_models_module_has_no_billing_vocabulary():
    import inspect
    import trustband.models as m
    src = inspect.getsource(m).lower()
    assert not any(w in src for w in ("entitlement", "api_key", "licen", "subscription"))


# -- P-MC.7: recorded and rendered ----------------------------------------------

def test_model_decisions_are_recorded_and_traced(tmp_path):
    from trustband.trace import main as trace_main
    g = _g(tmp_path)
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    g.before_model_call("s1", "gpt-4o")
    g.before_model_call("s1", "gpt-4o-mini")
    recs = _entries(tmp_path, "model")
    assert recs[-2]["allowed"] is False and recs[-2]["bands"] == ["session", "tool"] and recs[-2]["hint"]["models"]
    assert recs[-1]["allowed"] is True and recs[-1]["model"] == "gpt-4o-mini"
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        trace_main(tmp_path / "audit.jsonl", "s1", None, [])
    text = buf.getvalue()
    assert "model gpt-4o" in text and "REFUSED" in text and "may reach: gpt-4o-mini" in text


# -- P-MC.9: nothing prior moves --------------------------------------------------

def test_tool_path_is_unchanged_with_and_without_models(tmp_path):
    outs = []
    for models in (None, MODELS):
        g = _g(tmp_path / ("a" if models else "b"), models=models)
        g.after_tool_result(ToolCall("s1", "read", {}), {"t": "poisoned-body-text"}, Band.TOOL)
        outs.append((g.before_tool_call(ToolCall("s1", "send", {"body": "poisoned-body-text"})).allowed,
                     g.before_tool_call(ToolCall("s1", "send", {"body": "typed"})).allowed))
    assert outs[0] == outs[1] == (False, True)


# -- P-MC.10: the saving, synthetic --------------------------------------------------

def test_synthetic_saving_is_arithmetic_on_the_table(tmp_path):
    g = _g(tmp_path)
    steps, tool_steps, tokens = 100, 70, 2000
    chosen = []
    for i in range(steps):
        sess = f"s{i}"
        if i < tool_steps:
            g.after_tool_result(ToolCall(sess, "read", {}), {"page": f"untrusted page text number {i}"}, Band.TOOL)
        d = g.before_model_call(sess, "gpt-4o")
        model = "gpt-4o" if d.allowed else d.hint["models"][0]
        chosen.append(model)
    assert chosen.count("gpt-4o-mini") == tool_steps and chosen.count("gpt-4o") == steps - tool_steps
    mp = g.models
    routed = sum(mp.cost(m, tokens, tokens // 4) for m in chosen)
    all_big = steps * mp.cost("gpt-4o", tokens, tokens // 4)
    saving = 1 - routed / all_big
    assert 0.6 < saving < 0.7, f"saving {saving:.3f}"
    (tmp_path / "saving.txt").write_text(f"{saving:.4f}")
