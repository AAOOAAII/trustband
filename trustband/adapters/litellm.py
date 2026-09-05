"""LiteLLM adapter: the model gate in front of the router people already run.

WHERE THE GATE CAN STAND, MEASURED FIRST (litellm 1.99.0)
    A `CustomLogger` that raises in `log_pre_api_call` does NOT stop
    `litellm.completion`; the library catches logger exceptions and the call
    proceeds. So the logger is not a refusal surface in the SDK path, and
    nothing here pretends it is. The wrapper below is: it asks the gate and
    only then calls the library.

    A `CustomLogger.pre_call_check(deployment)` that raises FAILS the call.
    It runs after the Router has chosen, and the Router treats the exception
    as the call's failure, not as a reason to choose again -- measured with
    two deployments in one group. So the hint cannot act there. It acts in
    `route()` below, BEFORE the Router chooses: the group is narrowed to the
    deployments the gate permits, in the hint's order, and the Router runs
    the chosen one. The `pre_call_check` stays as the safety net: a
    deployment the gate refuses cannot be called through a Router that has
    the logger registered, whichever path chose it.

THE GATE DOES NOT ROUTE
    `before_model_call` answers; LiteLLM makes the call and the Router
    chooses. Nothing here forwards or rewrites a request.

WHAT IT SEES
    The wrapper: the model name, the messages (so the bands are computed from
    what is actually being sent), a token count from the library's own
    counter, and the response's usage and `model`. The Router check: only the
    deployment, so its bands come from the session's store; the Router does
    not hand it the messages. Stated in the result, not hidden.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from trustband.guard import Guard


class ModelRefused(Exception):
    """Raised by the wrapper before any request, and by the Router check to
    drop a deployment. Carries the gate's hint so a caller can re-route."""

    def __init__(self, reason: str, hint: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.hint = hint or {}


def _texts(messages: Any) -> List[str]:
    """The strings a request carries: string contents and text parts."""
    out: List[str] = []
    for m in messages or []:
        c = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            for part in c:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    out.append(part["text"])
    return out


def _field(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _usage(resp: Any) -> tuple:
    u = _field(resp, "usage")
    return int(_field(u, "prompt_tokens") or 0), int(_field(u, "completion_tokens") or 0)


def _version(resp: Any) -> Optional[str]:
    m = _field(resp, "model")
    return str(m) if m else None


class LiteLLMGate:
    """One gate per (guard, session). `completion` / `acompletion` wrap the
    library's; `logger` goes into `litellm.callbacks` for a Router."""

    def __init__(self, guard: Guard, session: str, agent: Any = None) -> None:
        self.guard = guard
        self.session = session
        self.agent = agent
        self._logger: Any = None

    # -- the question ------------------------------------------------------
    def _count(self, model: str, messages: Any) -> Optional[int]:
        """The library's own count, or None. Never a guess: with no count the
        per-call limit is not judged, and the other constraints are."""
        try:
            import litellm
            return int(litellm.token_counter(model=model, messages=list(messages or [])))
        except Exception:
            return None

    def ask(self, model: str, messages: Any) -> Dict[str, Any]:
        bands = self.guard.context_bands(self.session, _texts(messages))
        d = self.guard.before_model_call(self.session, model, tokens_in=self._count(model, messages),
                                         context_bands=bands, agent=self.agent)
        if not d.allowed:
            raise ModelRefused(d.reason, d.hint)
        return d.hint

    # -- the record --------------------------------------------------------
    def _marked(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Metadata that tells the logger this call is recorded by the wrapper,
        so a Router with the logger registered does not count it twice."""
        md = dict(kwargs.get("metadata") or {})
        md["trustband_recorded"] = True
        md["trustband_session"] = self.session
        return {**kwargs, "metadata": md}

    def record(self, model: str, resp: Any) -> float:
        tin, tout = _usage(resp)
        return self.guard.record_model_usage(self.session, model, tin, tout, version=_version(resp))

    def _usage_unavailable(self, model: str) -> None:
        audit = getattr(self.guard, "audit", None)
        if audit is None:
            return
        try:
            import time
            audit.append({"ts": time.time(), "session": self.session, "event": "model_usage",
                          "model": model, "usage": "unavailable",
                          "note": "streamed response without usage in its final chunk; "
                                  "pass stream_options={'include_usage': True} to record it",
                          "mode": self.guard.mode})
        except Exception:
            pass

    def _streamed(self, model: str, chunks: Any):
        last = None
        for ch in chunks:
            last = ch
            yield ch
        if last is not None and _field(last, "usage") is not None:
            self.record(model, last)
        else:
            self._usage_unavailable(model)

    async def _astreamed(self, model: str, chunks: Any):
        last = None
        async for ch in chunks:
            last = ch
            yield ch
        if last is not None and _field(last, "usage") is not None:
            self.record(model, last)
        else:
            self._usage_unavailable(model)

    # -- the calls ---------------------------------------------------------
    def completion(self, **kwargs: Any) -> Any:
        import litellm
        model = str(kwargs.get("model") or "unknown")
        self.ask(model, kwargs.get("messages"))
        resp = litellm.completion(**self._marked(kwargs))
        if kwargs.get("stream"):
            return self._streamed(model, resp)
        self.record(model, resp)
        return resp

    async def acompletion(self, **kwargs: Any) -> Any:
        import litellm
        model = str(kwargs.get("model") or "unknown")
        self.ask(model, kwargs.get("messages"))
        resp = await litellm.acompletion(**self._marked(kwargs))
        if kwargs.get("stream"):
            return self._astreamed(model, resp)
        self.record(model, resp)
        return resp

    # -- the Router: narrow the group, then let it run ---------------------
    def _permitted_deployments(self, router: Any, group: str, hint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The group's deployments whose underlying model the hint permits,
        in the hint's order: the first pattern's matches first. The hint is
        the intersection the gate computed for THIS context (P-MC.4)."""
        import fnmatch
        deployments = list(router.get_model_list(model_name=group) or [])
        out: List[Dict[str, Any]] = []
        for pat in hint.get("models") or []:
            for d in deployments:
                m = str((d.get("litellm_params") or {}).get("model") or "")
                if fnmatch.fnmatchcase(m, pat) and d not in out:
                    out.append(d)
        return out

    def _pick(self, router: Any, group: str, messages: Any) -> Dict[str, Any]:
        """The hint first, with nothing recorded; narrow the group by it; then
        the gate's one recorded question is about the deployment actually
        chosen, so the record names the model that ran. With nothing
        permitted, the question is asked about the group's first deployment
        so the refusal and its reason are on the record, and no call is made."""
        deployments = list(router.get_model_list(model_name=group) or [])
        if not deployments:
            raise ModelRefused(f"the router has no deployments in group {group!r}", {})
        bands = self.guard.context_bands(self.session, _texts(messages))
        hint = self.guard.model_hint(self.session, bands)
        allowed = self._permitted_deployments(router, group, hint)
        chosen = allowed[0] if allowed else deployments[0]
        model = str((chosen.get("litellm_params") or {}).get("model") or group)
        d = self.guard.before_model_call(self.session, model, tokens_in=self._count(model, messages),
                                         context_bands=bands, agent=self.agent)
        if not d.allowed:
            raise ModelRefused(d.reason, d.hint)
        if not allowed:
            raise ModelRefused(f"no deployment in group {group!r} is among the models this context "
                               f"permits {hint.get('models')}", d.hint)
        return chosen

    def route(self, router: Any, model: str, messages: Any, **kwargs: Any) -> Any:
        """`router.completion` through the gate: the group is narrowed to
        what the context permits and the first permitted deployment runs."""
        dep = self._pick(router, model, messages)
        target = str(((dep.get("model_info") or {}).get("id")) or dep.get("model_name") or model)
        resp = router.completion(model=target, messages=messages, **self._marked(kwargs))
        self.record(str((dep.get("litellm_params") or {}).get("model") or model), resp)
        return resp

    async def aroute(self, router: Any, model: str, messages: Any, **kwargs: Any) -> Any:
        dep = self._pick(router, model, messages)
        target = str(((dep.get("model_info") or {}).get("id")) or dep.get("model_name") or model)
        resp = await router.acompletion(model=target, messages=messages, **self._marked(kwargs))
        self.record(str((dep.get("litellm_params") or {}).get("model") or model), resp)
        return resp

    # -- the Router hook: the safety net ------------------------------------
    @property
    def logger(self) -> Any:
        if self._logger is None:
            self._logger = _make_logger(self)
        return self._logger


def _make_logger(gate: LiteLLMGate) -> Any:
    from litellm.integrations.custom_logger import CustomLogger

    class _ModelGateLogger(CustomLogger):
        """Registered in `litellm.callbacks`. Drops Router deployments the
        gate refuses; records usage for calls the wrapper did not make."""

        def _deployment_model(self, deployment: Dict[str, Any]) -> str:
            lp = deployment.get("litellm_params") or {}
            return str(lp.get("model") or deployment.get("model_name") or "unknown")

        def pre_call_check(self, deployment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            # The Router hands over the deployment it has ALREADY chosen and
            # nothing else, so the bands are the session's stored ones, and a
            # refusal here fails the call rather than choosing again. It is
            # the safety net behind `route()`, not the router.
            model = self._deployment_model(deployment)
            d = gate.guard.before_model_call(gate.session, model,
                                             context_bands=gate.guard.context_bands(gate.session),
                                             agent=gate.agent)
            if not d.allowed:
                raise ModelRefused(d.reason, d.hint)
            return None

        async def async_pre_call_check(self, deployment: Dict[str, Any],
                                       parent_otel_span: Any = None) -> Optional[Dict[str, Any]]:
            return self.pre_call_check(deployment)

        def _record_unless_wrapped(self, kwargs: Dict[str, Any], response_obj: Any) -> None:
            md = ((kwargs.get("litellm_params") or {}).get("metadata") or {})
            if md.get("trustband_recorded"):
                return
            model = str(kwargs.get("model") or _version(response_obj) or "unknown")
            gate.record(model, response_obj)

        def log_success_event(self, kwargs: Dict[str, Any], response_obj: Any,
                              start_time: Any, end_time: Any) -> None:
            self._record_unless_wrapped(kwargs, response_obj)

        async def async_log_success_event(self, kwargs: Dict[str, Any], response_obj: Any,
                                          start_time: Any, end_time: Any) -> None:
            self._record_unless_wrapped(kwargs, response_obj)

    return _ModelGateLogger()


def gated(guard: Guard, session: str, agent: Any = None) -> LiteLLMGate:
    """The one entry point. `gate = gated(guard, "s1")`, then
    `gate.completion(model=..., messages=...)`, or `litellm.callbacks =
    [gate.logger]` in front of a Router."""
    return LiteLLMGate(guard, session, agent)
