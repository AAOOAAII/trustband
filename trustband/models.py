"""Model constraints: which models a step may reach, with how much, given what
is in its context. The policy section, its validation, and the arithmetic.

THE GATE DOES NOT ROUTE
    It answers a question the framework asks -- "may this step reach this
    model?" -- with a decision and a hint (the set every band present
    permits). Whatever the framework does with the hint is the framework's.
    Nothing here makes, forwards or rewrites a model call.

ONE MECHANISM, TWO USES
    `by_band` says which models content at a band may reach. Read one way it
    is residency: untrusted TOOL content goes only to a sandboxed model, and
    GOVERNANCE material never leaves to a third party. Read the other way it
    is cost: the cheap model for the steps that carry nothing sensitive. The
    operator writes one table and gets both.

WHAT THE BANDS IN CONTEXT ARE
    By default SESSION plus every band the session's provenance store has
    remembered -- if a tool's output was remembered, TOOL is in context. An
    adapter that can see the messages may pass the bands it computed from
    them instead; the store is the fallback, never the only source.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from trustband.gate import Band

BAND_NAMES = {b.value: b for b in Band}


class ModelConfigError(ValueError):
    """A malformed `models` section. Raised at adoption, never at a call."""


@dataclass(frozen=True)
class ModelPolicy:
    allow: List[str]
    by_band: Dict[Band, List[str]]
    max_tokens_per_call: Optional[int]
    #: In MINOR UNITS (pence, cents) as an integer: the policy domain has no
    #: floats, for the same reason the lockfile stringifies them -- a policy
    #: is digested, and a float has two spellings of one value.
    max_cost_per_session: Optional[int]
    #: model -> {"in": minor units per 1M input tokens, "out": per 1M output}
    prices: Dict[str, Any]
    pin: bool
    enabled: bool = True

    # -- construction -------------------------------------------------------
    @classmethod
    def absent(cls) -> "ModelPolicy":
        return cls(allow=["*"], by_band={}, max_tokens_per_call=None,
                   max_cost_per_session=None, prices={}, pin=False, enabled=False)

    @classmethod
    def from_policy(cls, section: Any) -> "ModelPolicy":
        if section is None:
            return cls.absent()
        if not isinstance(section, dict):
            raise ModelConfigError("policy.models must be a map")
        known = {"allow", "by_band", "max_tokens_per_call", "max_cost_per_session", "prices", "pin"}
        unknown = sorted(set(section) - known)
        if unknown:
            raise ModelConfigError(f"policy.models: unknown key(s) {unknown}; known: {sorted(known)}")
        allow = section.get("allow", ["*"])
        if not isinstance(allow, list) or not allow or not all(isinstance(m, str) and m for m in allow):
            raise ModelConfigError("policy.models.allow must be a non-empty list of model patterns")
        by_band: Dict[Band, List[str]] = {}
        for name, pats in (section.get("by_band") or {}).items():
            if name not in BAND_NAMES:
                raise ModelConfigError(f"policy.models.by_band: unknown band {name!r}; "
                                       f"one of {sorted(BAND_NAMES)}")
            if not isinstance(pats, list) or not all(isinstance(m, str) and m for m in pats):
                raise ModelConfigError(f"policy.models.by_band[{name!r}] must be a list of model patterns")
            by_band[BAND_NAMES[name]] = list(pats)
        mt = section.get("max_tokens_per_call")
        if mt is not None and (not isinstance(mt, int) or isinstance(mt, bool) or mt < 1):
            raise ModelConfigError("policy.models.max_tokens_per_call must be a positive integer")
        mc = section.get("max_cost_per_session")
        if mc is not None and (not isinstance(mc, int) or isinstance(mc, bool) or mc <= 0):
            raise ModelConfigError("policy.models.max_cost_per_session must be a positive integer "
                                   "in minor units (pence, cents); the policy domain has no floats")
        prices = section.get("prices") or {}
        if not isinstance(prices, dict):
            raise ModelConfigError("policy.models.prices must be a map of model -> {in, out}")
        for m, p in prices.items():
            if (not isinstance(p, dict) or set(p) - {"in", "out"}
                    or not all(isinstance(p.get(k, 0), int) and not isinstance(p.get(k, 0), bool)
                               and p.get(k, 0) >= 0 for k in ("in", "out"))):
                raise ModelConfigError(f"policy.models.prices[{m!r}] must be {{'in': n, 'out': n}}: integers, "
                                       f"minor units per million tokens")
        pin = section.get("pin", False)
        if not isinstance(pin, bool):
            raise ModelConfigError("policy.models.pin must be true or false")
        return cls(allow=list(allow), by_band=by_band, max_tokens_per_call=mt,
                   max_cost_per_session=mc,
                   prices={k: dict(v) for k, v in prices.items()}, pin=pin, enabled=True)

    # -- the question -------------------------------------------------------
    @staticmethod
    def _matches(model: str, patterns: List[str]) -> bool:
        return any(fnmatch.fnmatchcase(model, p) for p in patterns)

    def permitted(self, bands: Set[Band]) -> List[str]:
        """The patterns every band present permits: `allow`, narrowed by each
        band's list. Policy order, no duplicates. Empty means nothing may be
        reached from this context, which is a refusal, not a silence."""
        out: List[str] = list(self.allow)
        for band in sorted(bands, key=lambda b: b.value):
            pats = self.by_band.get(band)
            if pats is None:
                continue
            # A pattern survives if it is (or is covered by) one of the
            # band's patterns. Concretely: keep the band's own patterns that
            # are also inside `allow` by name or by wildcard.
            narrowed = [p for p in pats if any(fnmatch.fnmatchcase(p, a) or a == p for a in out)]
            out = narrowed
        return out

    def check(self, model: str, bands: Set[Band]) -> Optional[str]:
        """None if `model` may be reached from this context, else why not."""
        if not self._matches(model, self.allow):
            return f"model {model!r} is not in models.allow {self.allow}"
        for band in sorted(bands, key=lambda b: b.value):
            pats = self.by_band.get(band)
            if pats is not None and not self._matches(model, pats):
                return (f"context holds {band.value}-band content, which may reach only "
                        f"{pats}; {model!r} is not among them")
        return None

    # -- the arithmetic -----------------------------------------------------
    def price_of(self, model: str) -> Optional[Dict[str, int]]:
        for pat, p in self.prices.items():
            if fnmatch.fnmatchcase(model, pat):
                return {"in": int(p.get("in", 0)), "out": int(p.get("out", 0))}
        return None

    def cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """Minor units, as a float only because tokens do not divide evenly
        into millions; the policy never holds this number."""
        p = self.price_of(model)
        if p is None:
            return 0.0
        return (tokens_in * p["in"] + tokens_out * p["out"]) / 1_000_000.0

    def cheapest_in_rate(self, patterns: List[str]) -> Optional[float]:
        rates = [int(p.get("in", 0)) for pat, p in self.prices.items()
                 if any(fnmatch.fnmatchcase(pat, q) or fnmatch.fnmatchcase(q, pat) for q in patterns)]
        rates = [r for r in rates if r > 0]
        return min(rates) if rates else None

    def hint(self, bands: Set[Band], spent: float) -> Dict[str, Any]:
        """What a router may act on: the permitted set, and the tokens left
        under the smaller of the per-call limit and the remaining budget at
        the cheapest permitted input rate."""
        models = self.permitted(bands)
        max_tokens: Optional[int] = self.max_tokens_per_call
        if self.max_cost_per_session is not None:
            remaining = max(self.max_cost_per_session - spent, 0.0)
            rate = self.cheapest_in_rate(models)
            if rate:
                by_budget = int(remaining * 1_000_000 / rate)
                max_tokens = by_budget if max_tokens is None else min(max_tokens, by_budget)
        return {"models": models, "max_tokens": max_tokens}
