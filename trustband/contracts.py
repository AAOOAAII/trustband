"""Rules about what came back, not about whether the call was allowed.

WHAT A CONTRACT IS
    Every other rule in this codebase constrains a permission: may this call
    happen. A contract constrains the RESULT: coverage above a threshold, a
    reviewer who is not the author, a required section present, an artifact
    that exists.

    It runs after the tool ran, and it can fail work that was correctly
    permitted. A rule that only re-examines the call's arguments is a
    permission rule wearing a different name.

WHAT IT DOES NOT CLAIM
    **Contracts verify what is checkable, not that the work is good.** A
    coverage threshold says a number cleared a bar. It says nothing about
    whether the tests are worth having, and a contract implying otherwise
    would be the overclaim this product exists not to make.

SHADOW FIRST, PER CONTRACT
    Default is record-and-permit. Blocking is opt-in on each contract rather
    than globally, because one wrong threshold that blocks CI gets the whole
    tool removed on the first Friday -- and the operator who wants a hard gate
    on `coverage` rarely wants one on `required_sections` yet.

ABSENCE SATISFIES NOTHING
    A missing field, an unparseable number, a threshold against data that is
    not there: the contract FAILS with a reason. It never passes because
    nothing was found. That rule holds everywhere else here and does not get an
    exception for being new.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

#: op -> the field it requires in the contract definition.
OPERATORS: Dict[str, Optional[str]] = {
    "at_least": "value",       # numeric floor, e.g. coverage
    "at_most": "value",        # numeric ceiling, e.g. failures
    "present": None,           # the field exists and is non-empty
    "absent": None,            # the field is missing or empty
    "not_equal": "value",      # reviewer != author
    "matches": "pattern",      # a required section, a ticket reference
    "contains_all": "values",  # every required section present
}


class ContractError(ValueError):
    """A malformed contract. Raised at adoption, never at evaluation."""


def validate(contracts: Any) -> None:
    if contracts is None:
        return
    if not isinstance(contracts, list):
        raise ContractError("policy.contracts must be a list")
    for i, c in enumerate(contracts):
        where = f"contracts[{i}]"
        if not isinstance(c, dict):
            raise ContractError(f"{where} must be a map")
        for field in ("name", "field", "op"):
            if field not in c:
                raise ContractError(f"{where} missing {field!r}")
        op = c["op"]
        if op not in OPERATORS:
            raise ContractError(
                f"{where}.op {op!r} is not one of {sorted(OPERATORS)}")
        need = OPERATORS[op]
        if need and need not in c:
            raise ContractError(f"{where}: {op!r} requires {need!r}")
        if op in ("at_least", "at_most"):
            v = c["value"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ContractError(f"{where}.value must be a number")
        if op == "matches":
            try:
                re.compile(c["pattern"])
            except re.error as exc:
                raise ContractError(f"{where}.pattern is not a regex: {exc}")
        if "actions" in c and not isinstance(c["actions"], list):
            raise ContractError(f"{where}.actions must be a list")


def _dig(result: Any, path: str) -> Tuple[bool, Any]:
    """Follow a dotted path into the result. Returns (found, value).

    `found` is returned separately from the value because `0`, `""` and
    `False` are all legitimate values and all falsey. Conflating "absent" with
    "empty" is how a threshold silently passes on missing data.
    """
    cur = result
    if isinstance(cur, str):
        try:
            cur = json.loads(cur)
        except Exception:
            return (False, None)
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return (False, None)
    return (True, cur)


def _number(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip().rstrip("%"))
        except ValueError:
            return None
    return None


def evaluate(contracts: List[Dict[str, Any]], action: str, result: Any
             ) -> List[Dict[str, Any]]:
    """Every contract that applies to this action, and how it fared."""
    out: List[Dict[str, Any]] = []
    for c in contracts or []:
        scope = c.get("actions")
        if scope and action not in scope and "*" not in scope:
            continue
        found, value = _dig(result, c["field"])
        op = c["op"]
        held, why = _one(op, c, found, value)
        out.append({
            "name": c["name"], "field": c["field"], "op": op,
            "held": held, "reason": why,
            "blocking": bool(c.get("blocking", False)),
        })
    return out


def _one(op: str, c: Dict[str, Any], found: bool, value: Any
         ) -> Tuple[bool, str]:
    field = c["field"]
    if op == "absent":
        return (not found or value in ("", None, [], {}),
                f"{field} is present" if found else f"{field} is absent")
    if not found:
        # THE RULE THAT DOES NOT GET AN EXCEPTION.
        return (False,
                f"{field} is not in the result, so {op!r} cannot be checked. "
                f"An unevaluable contract fails; absence satisfies nothing.")
    if op == "present":
        ok = value not in ("", None, [], {})
        return (ok, f"{field} is present" if ok else f"{field} is empty")
    if op in ("at_least", "at_most"):
        n = _number(value)
        if n is None:
            return (False, f"{field}={value!r} is not a number, so it cannot "
                           f"be compared to {c['value']}")
        ok = n >= c["value"] if op == "at_least" else n <= c["value"]
        rel = ">=" if op == "at_least" else "<="
        return (ok, f"{field}={n:g} {rel} {c['value']:g}" if ok
                else f"{field}={n:g} is not {rel} {c['value']:g}")
    if op == "not_equal":
        ok = str(value) != str(c["value"])
        return (ok, f"{field}={value!r} equals {c['value']!r}" if not ok
                else f"{field} differs from {c['value']!r}")
    if op == "matches":
        ok = re.search(c["pattern"], str(value)) is not None
        return (ok, f"{field} matches {c['pattern']!r}" if ok
                else f"{field}={str(value)[:60]!r} does not match "
                     f"{c['pattern']!r}")
    if op == "contains_all":
        text = str(value)
        missing = [v for v in c["values"] if str(v) not in text]
        return (not missing,
                f"{field} contains all {len(c['values'])} required"
                if not missing else f"{field} is missing {missing}")
    return (False, f"unknown operator {op!r}")
