"""Emit decisions as OpenTelemetry spans, without taking the SDK.

WHY THE WIRE FORMAT AND NOT THE LIBRARY
    `pip install trustband` ships zero dependencies, which is a claim on the
    PyPI page and a reason to trust the install. The OTel SDK is a large one,
    and unstable ground besides: the GenAI conventions moved to their own
    repository at v1.42.0 and are still pre-stable with no 1.0. Installing one
    unrelated package into this project's environment was already enough to
    break `opentelemetry-exporter-otlp`'s declared pins.

    OTLP/JSON over HTTP is a documented wire format. `urllib` speaks it. The
    contract is the payload, not somebody's object model.

WHAT IS OURS TO CONTRIBUTE
    `gen_ai.*` describes model calls and token usage, and every observability
    vendor already emits it. **Nobody emits provenance.** `trustband.*` carries
    the band each argument arrived at, the grant that decided, and whether a
    refusal was one a person could answer. That is the attribute set no other
    exporter can produce, and it is why being a data source beats competing
    with a dashboard.

EXPORT NEVER TOUCHES A DECISION
    Fire-and-forget, like the notifier -- which taught this lesson once already
    by stalling every refused call five seconds while "not changing the
    outcome". An unreachable collector must cost nothing.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

#: OTLP wants 16-byte trace ids and 8-byte span ids, hex-encoded.
def _tid() -> str:
    return os.urandom(16).hex()


def _sid() -> str:
    return os.urandom(8).hex()


def _attr(k: str, v: Any) -> Dict[str, Any]:
    """One OTLP attribute. Types are explicit in OTLP; a bare value is invalid."""
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    if isinstance(v, float):
        return {"key": k, "value": {"doubleValue": v}}
    return {"key": k, "value": {"stringValue": "" if v is None else str(v)}}


def span_for(event: Dict[str, Any], service: str = "trustband") -> Dict[str, Any]:
    """One recorded event as an OTLP span record."""
    ts = int(float(event.get("ts", time.time())) * 1_000_000_000)
    dur = int(float(event.get("ms", 0.0)) * 1_000_000)
    is_decision = event.get("event") == "decision"
    allowed = bool(event.get("allowed"))

    attrs: List[Dict[str, Any]] = [
        _attr("trustband.event", event.get("event", "decision")),
        _attr("trustband.session", event.get("session", "")),
        _attr("gen_ai.tool.name", event.get("tool", "")),
    ]
    if is_decision:
        attrs += [
            _attr("trustband.decision", "allow" if allowed else "refuse"),
            _attr("trustband.reason", event.get("reason", "")),
            _attr("trustband.confirmable", bool(event.get("confirmable"))),
            _attr("trustband.mode", event.get("mode", "")),
        ]
        # The grant is an identity, and None is not 0. Emitting 0 for "no rule
        # matched" would attribute a decision to a rule that did not make it.
        g = event.get("grant")
        attrs.append(_attr("trustband.grant",
                           -1 if g is None else int(g)))
        # THE ATTRIBUTES NOBODY ELSE HAS.
        for arg, band in (event.get("bands") or {}).items():
            attrs.append(_attr(f"trustband.band.{arg}", band))
    else:
        attrs += [
            _attr("trustband.band", event.get("band", "")),
            _attr("trustband.strings_remembered",
                  int(event.get("strings_remembered", 0))),
        ]
        if event.get("from"):
            attrs.append(_attr("trustband.handoff.from", event["from"]))

    return {
        "traceId": _tid(),
        "spanId": _sid(),
        "name": f"{event.get('tool', 'tool')}.{event.get('event', 'decision')}",
        "kind": 1,                       # SPAN_KIND_INTERNAL
        "startTimeUnixNano": str(ts),
        "endTimeUnixNano": str(ts + dur),
        "attributes": attrs,
        # A refusal is not an error: the gate worked. Only a decision that
        # could not be made would be one, and there is no such state.
        "status": {"code": 1},           # STATUS_CODE_OK
    }


def _version() -> str:
    """The installed version, read rather than typed.

    It was typed once and was a release out of date by the time anyone looked,
    which in a telemetry stream is worse than absent: it silently attributes
    spans to the wrong build.
    """
    try:
        from importlib.metadata import version
        return version("trustband")
    except Exception:                                   # noqa: BLE001
        return "unknown"


def payload(events: List[Dict[str, Any]], service: str = "trustband"
            ) -> Dict[str, Any]:
    """A complete OTLP/JSON ExportTraceServiceRequest."""
    return {"resourceSpans": [{
        "resource": {"attributes": [_attr("service.name", service)]},
        "scopeSpans": [{
            "scope": {"name": "trustband", "version": _version()},
            "spans": [span_for(e, service) for e in events],
        }],
    }]}


class Exporter:
    """Ships spans to an OTLP/HTTP endpoint, or writes them to a file."""

    def __init__(self, endpoint: Optional[str] = None,
                 path: Optional[str] = None,
                 service: str = "trustband") -> None:
        self.endpoint = endpoint
        self.path = path
        self.service = service
        self.errors: List[str] = []

    def export(self, events: List[Dict[str, Any]]) -> bool:
        """Send. Returns whether it went; never raises, never blocks a caller.

        A collector that is down, slow or lying is not a security event and
        must not become one. Failures are recorded here and nowhere else.
        """
        if not events or (not self.endpoint and not self.path):
            return False
        body = json.dumps(payload(events, self.service))
        try:
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(body + "\n")
                return True
            req = urllib.request.Request(
                self.endpoint, data=body.encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
            return False
