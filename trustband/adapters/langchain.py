"""LangChain and LangGraph: gate a tool, do not merely watch it.

WHY THIS IS A TOOL WRAPPER AND NOT A CALLBACK HANDLER
    The obvious integration is `BaseCallbackHandler.on_tool_start`, and it is
    the wrong one. That method returns `Any` and LangChain does not consult it:
    a callback observes. An adapter built on callbacks could record provenance
    and run shadow mode and would **never be able to refuse**, which is the one
    thing the Claude Code adapter exists to do. Two adapters that disagree
    about whether a tool runs are two products.

    `BaseTool.run` raises on error and LangChain already handles tool
    exceptions, so a wrapper can deny by raising. That is the interception
    point with teeth.

BOTH HOOKS, OR IT IS NOT AN ADAPTER
    Wrapping the call is the half every competitor has. Banding the *result* on
    the way back is the half that catches an argument built from a previous
    tool's output, and `conformance.py` fails an adapter that implements only
    the first.

SESSIONS ARE NOT OPTIONAL
    LangChain has no session concept of its own. A caller supplies one; there
    is no default, because a shared default would let one run's tool output
    taint another's arguments, and silently is the worst way for that to
    happen.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall


class ToolRefused(Exception):
    """Raised in place of running the tool. LangChain surfaces it to the agent.

    A refusal is an exception rather than a returned string on purpose: a
    string would flow onward as though the tool had succeeded, and the model
    would treat a refusal as data.
    """

    def __init__(self, reason: str, confirmable: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.confirmable = confirmable


def guarded_tool(tool: Any, guard: Guard, session: str,
                 tier: int = 2) -> Any:
    """Wrap one LangChain tool so the gate decides before its body runs.

    Returns the same tool object with `_run`/`_arun` wrapped, so anything
    holding a reference to it — an agent, a graph node, a toolkit — is gated
    too. Rewrapping is idempotent.
    """
    if not session:
        raise GuardConfigError(
            "a session identity is required: provenance is scoped to it, and "
            "LangChain supplies none, so the caller must")
    if getattr(tool, "_trustband_wrapped", False):
        return tool

    name = getattr(tool, "name", None) or type(tool).__name__

    def _decide(kwargs: Dict[str, Any]) -> None:
        d = guard.before_tool_call(
            ToolCall(session=session, tool=name, args=dict(kwargs), tier=tier))
        if not d.allowed:
            raise ToolRefused(d.reason, d.confirmable)

    def _remember(result: Any) -> None:
        guard.after_tool_result(
            ToolCall(session=session, tool=name, args={}), result, Band.TOOL)

    # THE WRAPPER MUST KEEP THE ORIGINAL SIGNATURE.
    #
    # LangChain inspects `_run` to decide what to inject -- `config`, the
    # callback manager, the tool-call id. A `*args, **kwargs` wrapper looks
    # like a function that wants none of them, so they are not passed and the
    # real `_run` raises "missing 1 required keyword-only argument: 'config'".
    # Found against langchain_core 1.6.1, not against its documentation.
    import functools
    import inspect as _inspect

    def _wrap(fn: Callable[..., Any], is_async: bool) -> Callable[..., Any]:
        if is_async:
            @functools.wraps(fn)
            async def inner(*args: Any, **kwargs: Any) -> Any:
                _decide(_as_kwargs(fn, args, kwargs))
                out = await fn(*args, **kwargs)
                _remember(out)
                return out
        else:
            @functools.wraps(fn)
            def inner(*args: Any, **kwargs: Any) -> Any:
                _decide(_as_kwargs(fn, args, kwargs))
                out = fn(*args, **kwargs)
                _remember(out)
                return out
        try:
            inner.__signature__ = _inspect.signature(fn)   # type: ignore[attr-defined]
        except (TypeError, ValueError):
            pass
        return inner

    original = getattr(tool, "_run", None)
    if callable(original):
        object.__setattr__(tool, "_run", _wrap(original, False))

    aoriginal = getattr(tool, "_arun", None)
    if callable(aoriginal):
        object.__setattr__(tool, "_arun", _wrap(aoriginal, True))

    object.__setattr__(tool, "_trustband_wrapped", True)
    return tool


def _as_kwargs(fn: Callable[..., Any], args: tuple, kwargs: Dict[str, Any]
               ) -> Dict[str, Any]:
    """Positional arguments named, so a policy can talk about them.

    A policy names arguments; a tool called positionally would present none,
    and every band rule would silently not apply. Falls back to positional
    indices only if the signature cannot be read -- visible in a trace as
    `arg0`, which is at least honest about what happened.
    """
    import inspect
    try:
        names = [p for p in inspect.signature(fn).parameters
                 if p not in ("self", "args", "kwargs")]
    except (TypeError, ValueError):
        names = []
    # Framework plumbing is not a tool argument. `config`, `callbacks` and the
    # run manager are injected by LangChain, and presenting them to a policy
    # would put objects in the record that no rule will ever name.
    _PLUMBING = {"config", "callbacks", "run_manager", "tool_call_id"}
    out = {k: v for k, v in kwargs.items() if k not in _PLUMBING}
    for i, v in enumerate(args):
        name = names[i] if i < len(names) else f"arg{i}"
        if name not in _PLUMBING:
            out[name] = v
    return out


def guard_tools(tools: Any, guard: Guard, session: str, tier: int = 2) -> Any:
    """Wrap every tool in a list. The usual entry point for an agent or graph."""
    return [guarded_tool(t, guard, session, tier) for t in tools]
