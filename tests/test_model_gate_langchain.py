"""P-MC.8: the LangChain model gate, against the installed library's fake chat model."""
from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage

from trustband.adapters.langchain import ModelRefused, model_gate
from trustband.gate import Band
from trustband.guard import Guard, ToolCall

POLICY = {"version": 1, "grants": [{"sess": "*", "max_tier": 2, "actions": ["read"]}],
          "models": {"allow": ["fake-*"], "by_band": {"tool": ["fake-small"]},
                     "max_cost_per_session": 100,
                     "prices": {"fake-big": {"in": 1000, "out": 1000}, "fake-small": {"in": 10, "out": 10}}}}


class _Named(GenericFakeChatModel):
    """The fake has no model name of its own. Real chat models expose theirs
    through `_identifying_params`, which LangChain folds into the callback's
    invocation params; this does the same."""
    model_name: str = "fake"

    @property
    def _identifying_params(self):
        return {"model": self.model_name}


def _model(name: str, reply: str = "ok"):
    return _Named(messages=iter([AIMessage(content=reply)]), model_name=name)


def _invoke(m, guard, session, text):
    gate = model_gate(guard, session)
    return m.invoke([HumanMessage(content=text)], config={"callbacks": [gate]})


def test_refused_before_the_call_when_context_holds_tool_content(tmp_path):
    g = Guard(POLICY, mode="enforce", audit_path=tmp_path / "a.jsonl")
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    with pytest.raises(ModelRefused) as e:
        _invoke(_model("fake-big"), g, "s1", "summarise: some untrusted page text here")
    assert "tool-band" in e.value.reason and e.value.hint["models"] == ["fake-small"]
    assert _invoke(_model("fake-small"), g, "s1", "summarise: some untrusted page text here").content == "ok"


def test_messages_decide_the_bands_not_only_the_store(tmp_path):
    g = Guard(POLICY, mode="enforce", audit_path=tmp_path / "a.jsonl")
    g.after_tool_result(ToolCall("s1", "read", {}), {"page": "some untrusted page text here"}, Band.TOOL)
    # the store holds TOOL content, but the messages being sent do not carry it
    assert _invoke(_model("fake-big"), g, "s1", "what is 2+2").content == "ok"


def test_usage_is_recorded_after_the_call(tmp_path):
    g = Guard(POLICY, mode="enforce", audit_path=tmp_path / "a.jsonl")
    m = _model("fake-big")
    _invoke(m, g, "s1", "hello")
    # the fake reports no usage; the record is still written, at zero
    lines = [l for l in (tmp_path / "a.jsonl").read_text().splitlines() if '"model_usage"' in l]
    assert lines, "usage recorded"


def test_model_outside_allow_is_refused(tmp_path):
    g = Guard(POLICY, mode="enforce", audit_path=tmp_path / "a.jsonl")
    with pytest.raises(ModelRefused):
        _invoke(_model("gpt-4o"), g, "s1", "hello")
