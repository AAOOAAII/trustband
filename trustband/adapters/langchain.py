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

from typing import Any, Callable, Dict, Optional  # noqa: F401

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


class ModelRefused(Exception):
    """Raised from the callback before the model is called. LangChain
    propagates callback exceptions, so the call does not happen."""

    def __init__(self, reason: str, hint: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.hint = hint or {}


def model_gate(guard: Guard, session: str, agent: Any = None) -> Any:
    """A LangChain callback handler that asks the gate before every chat model
    call and records usage and version after it.

    WHY A CALLBACK HERE AND NOT FOR TOOLS
        For tools a callback cannot refuse, so the adapter wraps the tool.
        For model calls the framework raises callback exceptions before the
        request is made (`on_chat_model_start` runs first, and an exception
        there aborts the run), so a callback CAN refuse -- and it is the only
        place the adapter sees the model name and the messages together.

    WHAT IT SEES
        The messages, so the bands in context are computed from what is
        actually being sent, not only from what the store remembers. The
        model name from the invocation parameters. After the call, token
        usage and the model version the provider named, if any.
    """
    from langchain_core.callbacks import BaseCallbackHandler

    class _ModelGate(BaseCallbackHandler):
        raise_error = True

        def _model_of(self, serialized: Any, kwargs: Dict[str, Any]) -> str:
            inv = kwargs.get("invocation_params") or {}
            for k in ("model", "model_name", "model_id"):
                if inv.get(k):
                    return str(inv[k])
            sk = (serialized or {}).get("kwargs") or {}
            for k in ("model", "model_name", "model_id"):
                if sk.get(k):
                    return str(sk[k])
            return str(((serialized or {}).get("id") or ["unknown"])[-1])

        def _ask(self, model: str, texts: list) -> None:
            bands = guard.context_bands(session, texts)
            d = guard.before_model_call(session, model, context_bands=bands, agent=agent)
            if not d.allowed:
                raise ModelRefused(d.reason, d.hint)

        def on_chat_model_start(self, serialized: Any, messages: Any, **kwargs: Any) -> Any:
            texts = []
            for batch in messages or []:
                for m in batch or []:
                    c = getattr(m, "content", None)
                    if isinstance(c, str):
                        texts.append(c)
            self._ask(self._model_of(serialized, kwargs), texts)

        def on_llm_start(self, serialized: Any, prompts: Any, **kwargs: Any) -> Any:
            self._ask(self._model_of(serialized, kwargs), [p for p in (prompts or []) if isinstance(p, str)])

        def on_llm_end(self, response: Any, **kwargs: Any) -> Any:
            out = getattr(response, "llm_output", None) or {}
            usage = out.get("token_usage") or out.get("usage") or {}
            tin = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
            tout = usage.get("completion_tokens") or usage.get("output_tokens") or 0
            model = out.get("model_name") or out.get("model") or "unknown"
            version = out.get("model_name") or out.get("model")
            if not tin and not tout:
                # Chat generations carry usage on the message in newer versions.
                for gens in getattr(response, "generations", None) or []:
                    for g in gens:
                        um = getattr(getattr(g, "message", None), "usage_metadata", None) or {}
                        tin += um.get("input_tokens", 0) or 0
                        tout += um.get("output_tokens", 0) or 0
                        rm = getattr(getattr(g, "message", None), "response_metadata", None) or {}
                        if rm.get("model_name") or rm.get("model"):
                            model = version = rm.get("model_name") or rm.get("model")
            guard.record_model_usage(session, str(model), int(tin), int(tout), version=version)

    return _ModelGate()


def agent_for(guard: Guard, session: str, name: str, role: str = "") -> Any:
    """A named identity for a graph node or a crew member."""
    return guard.mint_agent(name, role, session)


def agent_for_crewai(guard: Guard, session: str, crew_agent: Any) -> Any:
    """CrewAI names an agent by its `role`. Read from the object, not
    documentation; a missing role is a config error, not a default."""
    role = getattr(crew_agent, "role", None)
    if not role:
        raise GuardConfigError("a CrewAI agent needs a non-empty role to be "
                               "identified")
    return guard.mint_agent(str(role), "crewai", session)


def agent_for_langgraph(guard: Guard, session: str, node: str) -> Any:
    """LangGraph has no agent object; the node name is the identity."""
    if not node:
        raise GuardConfigError("a LangGraph node needs a name to be identified")
    return guard.mint_agent(str(node), "langgraph-node", session)


def guarded_tool(tool: Any, guard: Guard, session: str,
                 tier: int = 2, agent: Any = None) -> Any:
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
            ToolCall(session=session, tool=name, args=dict(kwargs), tier=tier,
                     agent=agent))
        if not d.allowed:
            raise ToolRefused(d.reason, d.confirmable)

    def _remember(result: Any) -> None:
        guard.after_tool_result(
            ToolCall(session=session, tool=name, args={}, agent=agent),
            result, Band.TOOL)

    def _remember_error(exc: BaseException) -> None:
        # AN ERROR IS A TOOL RESULT. Measured (P8): a tool that raised with a
        # payload in its message left nothing in the store, so the model's
        # next argument built from that message looked session-authored.
        # Error text carries implicit authority -- the agent must read it to
        # self-correct -- which makes it the better injection channel, not
        # the safer one. Banded TOOL, then re-raised untouched.
        try:
            guard.after_tool_result(
                ToolCall(session=session, tool=name, args={}, agent=agent),
                f"{type(exc).__name__}: {exc}", Band.TOOL)
        except Exception:
            pass

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
                try:
                    out = await fn(*args, **kwargs)
                except ToolRefused:
                    raise
                except BaseException as exc:
                    _remember_error(exc)
                    raise
                _remember(out)
                return out
        else:
            @functools.wraps(fn)
            def inner(*args: Any, **kwargs: Any) -> Any:
                _decide(_as_kwargs(fn, args, kwargs))
                try:
                    out = fn(*args, **kwargs)
                except ToolRefused:
                    raise
                except BaseException as exc:
                    _remember_error(exc)
                    raise
                _remember(out)
                return out
        try:
            inner.__signature__ = _inspect.signature(fn)   # type: ignore[attr-defined]
        except (TypeError, ValueError):
            pass
        return inner

    # WRAP WHAT THE FRAMEWORK ACTUALLY CALLS, NOT WHAT ITS BASE CLASS DECLARES.
    #
    # LangChain's BaseTool.run calls self._run. CrewAI's BaseTool.run also
    # calls self._run -- but its `Tool` subclass, which the @tool decorator
    # returns, overrides run() and calls `self.func(...)` directly. A wrapper
    # on _run is installed on a method that framework never invokes, and the
    # tool executes while every check looks green. Found by running CrewAI
    # 1.15.18, not by reading its base class.
    #
    # So every entry point present is wrapped. Wrapping more than the framework
    # uses is harmless -- the guard is idempotent per call path and a tool is
    # entered once.
    wrapped_any = False
    for attr, is_async in (("_run", False), ("_arun", True), ("func", False),
                           ("coroutine", True)):
        fn = getattr(tool, attr, None)
        if callable(fn):
            object.__setattr__(tool, attr, _wrap(fn, is_async))
            wrapped_any = True
    if not wrapped_any:
        raise GuardConfigError(
            f"{name!r} exposes no callable entry point among _run/_arun/func/"
            f"coroutine, so it cannot be gated. Refusing rather than returning "
            f"an ungated tool that looks guarded.")

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


def restore_state(guard: Guard, session: str, state: Any,
                  from_session: str = "") -> int:
    """Memory across time is a handoff across time.

    Measured (P8): a value a tool returned in session one, carried in a
    LangGraph checkpoint into session two, arrived in session two's store
    unknown and was accepted as session-authored. The same laundering
    handoff banding closes between agents, across a persistence boundary.

    Call this with the loaded state before the new session's first action.
    Every string reachable in it is remembered TOOL for `session`; the old
    session's store is not shared. Returns how many strings were banded.
    """
    if not session:
        raise GuardConfigError("restore_state needs the new session's identity")
    before = len(guard._store(session))
    guard.handoff(session, state, from_session=from_session or None)
    return len(guard._store(session)) - before


def guard_tools(tools: Any, guard: Guard, session: str, tier: int = 2,
                agent: Any = None) -> Any:
    """Wrap every tool in a list. The usual entry point for an agent or graph.

    Also the observation point for the lockfile: name, description and the
    argument schema of every tool, as the framework exposes them, pinned on
    first acceptance and checked here on every later construction.
    """
    from trustband.lock import observe as _obs
    items = []
    for t in tools:
        name = getattr(t, "name", None) or type(t).__name__
        try:
            schema = getattr(t, "args", None)
        except Exception:
            schema = None
        items.append(_obs("tool", str(name), getattr(t, "description", "") or "", schema))
    try:
        guard.observe_catalog(session, "tool", items, full=False)
    except Exception:
        pass
    return [guarded_tool(t, guard, session, tier, agent) for t in tools]
