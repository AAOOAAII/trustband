"""Policy unit tests — the thing that would have caught most of today's bugs.

WHY THIS EXISTS
    Six policy-authoring defects on 2026-08-29/30, every one mine, every one
    found by a benchmark run rather than by reading the policy. Five were the
    same shape: a constraint applied to an action that does not take that
    argument. The sixth was inside the inference itself.

    Each cost between twenty minutes and three runs to find. A test file naming
    the expected answers would have caught them in milliseconds, and the
    authorization world has had `opa test` since 2016.

WHAT A TEST LOOKS LIKE
    A policy, and cases with the answer written down:

        {"policy": "banking.json",
         "context": {"known_payees": ["UK12345678901234567890"]},
         "cases": [
           {"name": "the bill the user asked for",
            "session": 7, "action": "send_money",
            "args": {"recipient": ["UK12345678901234567890", "tool"],
                     "amount": [98.70, "tool"]},
            "expect": "allow"},
           {"name": "the attacker's payee, same provenance",
            "args": {"recipient": ["US133000000121212121212", "tool"]},
            "expect": "deny",
            "because": "known_payees"}
         ]}

    `because` is a substring the refusal must contain. It is what stops a case
    passing for the wrong reason -- a test that only asserts "deny" goes green
    when the policy refuses for a reason nobody intended, which is exactly how
    a whole afternoon's numbers looked fine while a grant was refusing calls
    for constraining an argument they never passed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from trustband.gate import Band, Gate
from trustband.issuance import Issuer
from trustband.taint import Tainted


@dataclass
class CaseResult:
    name: str
    passed: bool
    detail: str


def _args(spec: Any) -> Dict[str, Any]:
    """`{"amount": [98.70, "tool"]}` -> a tainted argument map.

    A bare value means untagged, which a policy with `min_band` refuses -- that
    is a case worth being able to write, so it is representable rather than
    silently coerced.
    """
    out: Dict[str, Any] = {}
    for name, v in (spec or {}).items():
        if isinstance(v, list) and len(v) == 2 and isinstance(v[1], str):
            out[name] = Tainted(v[0], Band(v[1]))
        else:
            out[name] = v
    return out


def run_suite(spec: Dict[str, Any], base: Optional[Path] = None
              ) -> Tuple[List[CaseResult], Dict[str, Any]]:
    """Run one test file. Returns (results, the policy it ran against)."""
    base = base or Path(".")
    pol = spec.get("policy")
    policy = (json.loads((base / pol).read_text(encoding="utf-8"))
              if isinstance(pol, str) else pol)
    policy = dict(policy)
    policy.pop("_inferred", None)

    issuer = Issuer(Gate(budget=1))
    adopted = issuer.adopt(policy)
    if not adopted:
        return ([CaseResult("(adopt policy)", False, adopted.reason)], policy)

    shared = spec.get("context") or {}
    results: List[CaseResult] = []
    for i, case in enumerate(spec.get("cases", [])):
        name = case.get("name") or f"case {i}"
        ctx = {**shared, **(case.get("context") or {})}
        # A context of lists is friendlier to write than one of sets, and the
        # predicates only ever ask for membership.
        ctx = {k: (set(v) if isinstance(v, list) else v) for k, v in ctx.items()}
        ok, why = issuer.evaluate(case.get("session", 7),
                                  case.get("tier", 2),
                                  case["action"],
                                  _args(case.get("args")),
                                  ctx)
        want = case.get("expect", "allow").lower()
        got = "allow" if ok else "deny"
        if got != want:
            results.append(CaseResult(name, False,
                                      f"expected {want}, got {got}: {why}"))
            continue
        because = case.get("because")
        if because and because not in why:
            # Right answer, wrong reason. This is the check that matters.
            results.append(CaseResult(
                name, False,
                f"{got} as expected, but for the wrong reason -- "
                f"{because!r} not in {why!r}"))
            continue
        results.append(CaseResult(name, True, why))
    return results, policy


def run_files(paths: List[Path]) -> int:
    """Run every test file. Returns a process exit code."""
    total = failed = 0
    for p in paths:
        spec = json.loads(p.read_text(encoding="utf-8"))
        results, _ = run_suite(spec, base=p.parent)
        print(f"{p}")
        for r in results:
            total += 1
            if r.passed:
                print(f"  ok    {r.name}")
            else:
                failed += 1
                print(f"  FAIL  {r.name}")
                print(f"        {r.detail}")
    print(f"\n  {total - failed}/{total} cases passed")
    return 0 if failed == 0 else 1
