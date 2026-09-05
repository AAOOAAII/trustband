"""The LiteLLM adapter, against the installed library with mock responses.
P-LL.1 to P-LL.7 from docs/LITELLM_ADAPTER_GATES.md."""
from __future__ import annotations

import asyncio
import json

import pytest

litellm = pytest.importorskip("litellm")
from litellm import ModelResponse  # noqa: E402
from litellm.integrations.custom_logger import CustomLogger  # noqa: E402

from trustband.adapters.litellm import ModelRefused, gated  # noqa: E402
from trustband.gate import Band  # noqa: E402
from trustband.guard import Guard, ToolCall  # noqa: E402

litellm.suppress_debug_info = True

POLICY = {"version": 1, "grants": [{"sess": "*", "max_tier": 2, "actions": ["read"]}],
          "models": {"allow": ["gpt-4o*"], "by_band": {"tool": ["gpt-4o-mini"]},
                     "max_cost_per_session": 100,
                     "prices": {"gpt-4o": {"in": 1000, "out": 1000}, "gpt-4o-mini": {"in": 10, "out": 10}}}}
PAGE = "some untrusted page text here"


class Counter(CustomLogger):
    def __init__(self):
        super().__init__()
        self.pre = 0

    def log_pre_api_call(self, model, messages, kwargs):
        self.pre += 1


@pytest.fixture(autouse=True)
def _clean_callbacks():
    litellm.callbacks = []
    yield
    litellm.callbacks = []


def _guard(tmp_path, **extra):
    pol = json.loads(json.dumps(POLICY))
    pol["models"].update(extra)
    return Guard(pol, mode="enforce", audit_path=tmp_path / "audit.jsonl")


def _poison(g):
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": PAGE}, Band.TOOL)


def _entries(tmp_path, event):
    out = []
    for line in (tmp_path / "audit.jsonl").read_text().splitlines():
        rec = json.loads(line); rec = rec.get("body", rec)
        if rec.get("event") == event:
            out.append(rec)
    return out


# -- P-LL.1: refused before the call --------------------------------------------

def test_refused_before_any_request_when_messages_carry_tool_content(tmp_path):
    g = _guard(tmp_path); _poison(g)
    c = Counter(); litellm.callbacks = [c]
    gate = gated(g, "s1")
    with pytest.raises(ModelRefused) as e:
        gate.completion(model="gpt-4o", messages=[{"role": "user", "content": f"summarise: {PAGE}"}], mock_response="big")
    assert "tool-band" in e.value.reason and e.value.hint["models"] == ["gpt-4o-mini"]
    assert c.pre == 0, "no request was made"
    r = gate.completion(model="gpt-4o-mini", messages=[{"role": "user", "content": f"summarise: {PAGE}"}], mock_response="small")
    assert r.choices[0].message.content == "small" and c.pre == 1


def test_messages_decide_the_bands_not_only_the_store(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    r = gate.completion(model="gpt-4o", messages=[{"role": "user", "content": "what is 2+2"}], mock_response="four")
    assert r.choices[0].message.content == "four"


# -- P-LL.2: usage, spend, ceiling ----------------------------------------------

def test_usage_is_recorded_and_the_ceiling_refuses_the_next_call(tmp_path):
    g = _guard(tmp_path, max_cost_per_session=50)
    gate = gated(g, "s1")
    msgs = [{"role": "user", "content": "hello"}]
    # mock usage is 10 in / 20 out; gpt-4o at 1000/1000 per million = 0.03 per call
    for _ in range(3):
        gate.completion(model="gpt-4o", messages=msgs, mock_response="ok")
    used = _entries(tmp_path, "model_usage")
    assert len(used) == 3 and used[-1]["tokens_in"] == 10 and used[-1]["tokens_out"] == 20
    assert used[-1]["version"] == "gpt-4o" and used[-1]["priced"] is True
    # push the spend to the ceiling with a big fake usage, then the next call refuses
    g.record_model_usage("s1", "gpt-4o", 60_000, 0)
    with pytest.raises(ModelRefused) as e:
        gate.completion(model="gpt-4o", messages=msgs, mock_response="ok")
    assert "cost ceiling" in e.value.reason


# -- P-LL.3: per-call limit before the call ------------------------------------

def test_per_call_limit_uses_the_library_counter(tmp_path):
    g = _guard(tmp_path, max_tokens_per_call=20)
    c = Counter(); litellm.callbacks = [c]
    gate = gated(g, "s1")
    long = [{"role": "user", "content": "word " * 200}]
    with pytest.raises(ModelRefused) as e:
        gate.completion(model="gpt-4o", messages=long, mock_response="ok")
    assert "per call limit" in e.value.reason and c.pre == 0
    assert gate.completion(model="gpt-4o", messages=[{"role": "user", "content": "hi"}], mock_response="ok")


def test_no_counter_means_no_guess(tmp_path, monkeypatch):
    g = _guard(tmp_path, max_tokens_per_call=1)
    gate = gated(g, "s1")
    monkeypatch.setattr(litellm, "token_counter", lambda **kw: (_ for _ in ()).throw(RuntimeError("no tokenizer")))
    assert gate.completion(model="gpt-4o", messages=[{"role": "user", "content": "hi"}], mock_response="ok")


# -- P-LL.4: the hint acts on a real Router --------------------------------------

def _router():
    return litellm.Router(model_list=[
        {"model_name": "chat", "litellm_params": {"model": "gpt-4o", "mock_response": "from-large"}},
        {"model_name": "chat", "litellm_params": {"model": "gpt-4o-mini", "mock_response": "from-small"}},
    ], enable_pre_call_checks=True, num_retries=0)


def test_route_narrows_the_group_to_what_the_context_permits(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    router = _router()
    msgs = [{"role": "user", "content": f"summarise: {PAGE}"}]
    answers = {gate.route(router, "chat", msgs).choices[0].message.content for _ in range(5)}
    assert answers == {"from-small"}
    # the gate's own record shows the context and the hint that narrowed the group
    decided = _entries(tmp_path, "model")
    assert decided and decided[-1]["hint"]["models"] == ["gpt-4o-mini"] and "tool" in decided[-1]["bands"]
    used = _entries(tmp_path, "model_usage")
    assert len(used) == 5 and all(u["model"] == "gpt-4o-mini" for u in used)


def test_route_with_session_content_alone_keeps_the_whole_group(tmp_path):
    g = _guard(tmp_path)
    gate = gated(g, "s1")
    router = _router()
    r = gate.route(router, "chat", [{"role": "user", "content": "go"}])
    assert r.choices[0].message.content == "from-large", "hint order: the first permitted deployment"
    assert _entries(tmp_path, "model")[-1]["hint"]["models"] == ["gpt-4o*"]


def test_route_says_why_when_nothing_permitted_remains(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    router = litellm.Router(model_list=[
        {"model_name": "big-only", "litellm_params": {"model": "gpt-4o", "mock_response": "from-large"}},
    ], num_retries=0)
    with pytest.raises(ModelRefused) as e:
        gate.route(router, "big-only", [{"role": "user", "content": f"summarise: {PAGE}"}])
    assert "tool-band" in e.value.reason and e.value.hint["models"] == ["gpt-4o-mini"]
    assert not _entries(tmp_path, "model_usage"), "no call was made"
    refused = [r for r in _entries(tmp_path, "model") if not r["allowed"]]
    assert refused and refused[-1]["model"] == "gpt-4o"


def test_logger_is_the_safety_net_for_a_router_called_directly(tmp_path):
    """The library runs pre_call_check after choosing and fails the call on a
    raise (measured; it does not choose again). So with the logger registered
    a refused deployment cannot be called through the router by any path."""
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    litellm.callbacks = [gate.logger]
    router = litellm.Router(model_list=[
        {"model_name": "big-only", "litellm_params": {"model": "gpt-4o", "mock_response": "from-large"}},
    ], enable_pre_call_checks=True, num_retries=0)
    with pytest.raises(Exception):
        router.completion(model="big-only", messages=[{"role": "user", "content": "go"}])
    refused = [r for r in _entries(tmp_path, "model") if not r["allowed"]]
    assert refused and "tool-band" in refused[-1]["reason"]
    assert not _entries(tmp_path, "model_usage"), "nothing was called, so nothing was recorded"


def test_wrapper_and_logger_together_record_once(tmp_path):
    g = _guard(tmp_path)
    gate = gated(g, "s1")
    litellm.callbacks = [gate.logger]
    gate.completion(model="gpt-4o", messages=[{"role": "user", "content": "hi"}], mock_response="ok")
    assert len(_entries(tmp_path, "model_usage")) == 1


# -- P-LL.5: version and pin ----------------------------------------------------

def test_version_is_the_response_model_and_a_change_is_drift(tmp_path):
    g = _guard(tmp_path, pin=True)
    gate = gated(g, "s1")
    msgs = [{"role": "user", "content": "hi"}]
    v1 = ModelResponse(model="gpt-4o-2024-08-06", choices=[{"message": {"role": "assistant", "content": "a"}}])
    v2 = ModelResponse(model="gpt-4o-2024-11-20", choices=[{"message": {"role": "assistant", "content": "b"}}])
    gate.completion(model="gpt-4o", messages=msgs, mock_response=v1)
    assert _entries(tmp_path, "model_usage")[-1]["version"] == "gpt-4o-2024-08-06"
    # the first observation is pending until a person accepts it; then it is the pin
    assert g.accept_lock() >= 1
    gate.completion(model="gpt-4o", messages=msgs, mock_response=v2)
    assert _entries(tmp_path, "lock_drift"), "a changed version is drift"
    with pytest.raises(ModelRefused) as e:
        gate.completion(model="gpt-4o", messages=msgs, mock_response=v2)
    assert "changed since it was pinned" in e.value.reason


# -- P-LL.6: async is the same gate ---------------------------------------------

def test_async_refuses_and_records_like_sync(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")

    async def run():
        with pytest.raises(ModelRefused):
            await gate.acompletion(model="gpt-4o", messages=[{"role": "user", "content": PAGE}], mock_response="big")
        r = await gate.acompletion(model="gpt-4o-mini", messages=[{"role": "user", "content": PAGE}], mock_response="small")
        return r.choices[0].message.content
    assert asyncio.run(run()) == "small"
    assert len(_entries(tmp_path, "model_usage")) == 1


def test_async_route_narrows_like_sync(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    router = _router()

    async def run():
        r = await gate.aroute(router, "chat", [{"role": "user", "content": f"summarise: {PAGE}"}])
        return r.choices[0].message.content
    assert asyncio.run(run()) == "from-small"
    assert _entries(tmp_path, "model_usage")[-1]["model"] == "gpt-4o-mini"


# -- P-LL.7: the logger cannot refuse, and the adapter never says it can ---------

def test_library_ignores_a_raising_pre_call_logger():
    class Refuser(CustomLogger):
        def log_pre_api_call(self, model, messages, kwargs):
            raise RuntimeError("REFUSED")
    litellm.callbacks = [Refuser()]
    r = litellm.completion(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}], mock_response="went-through")
    assert r.choices[0].message.content == "went-through", (
        "litellm now propagates logger exceptions; update LITELLM_ADAPTER_RESULT.md and reconsider the logger path")


# -- streaming: gated before it starts; usage only if the final chunk carries it --

def test_stream_is_gated_and_usage_is_recorded_when_present(tmp_path):
    g = _guard(tmp_path); _poison(g)
    gate = gated(g, "s1")
    with pytest.raises(ModelRefused):
        gate.completion(model="gpt-4o", messages=[{"role": "user", "content": PAGE}], mock_response="x", stream=True)
    chunks = list(gate.completion(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}],
                                  mock_response="streamed reply", stream=True,
                                  stream_options={"include_usage": True}))
    assert chunks
    recs = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    recs = [r.get("body", r) for r in recs]
    usage = [r for r in recs if r.get("event") == "model_usage"]
    assert usage, "either recorded usage or said it was unavailable"
