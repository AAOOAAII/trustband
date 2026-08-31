"""Predicates over an argument's VALUE, not its provenance.

WHY THIS EXISTS
    Measured 2026-08-29: a poisoned bill yields the legitimate payee and the
    attacker's payee from the SAME DOCUMENT, so both carry band TOOL and no
    provenance rule separates them.

        recipient: session  ->  legit bill=refuse  attack=refuse
        recipient: tool     ->  legit bill=ALLOW   attack=ALLOW

    Strict refuses the bill; permissive admits the attack. CaMeL's dependency
    tracking fails the same case, because "where did this come from" has one
    answer for both IBANs.

    What separates them is a question about the value: is this payee one the
    policy named in advance. That is authorization rather than data flow.

WHAT IT IS NOT
    **Not injection detection.** A poisoned document naming an allowlisted
    payee passes, and should. The claim is narrower: a consequential action
    cannot execute unless its arguments satisfy a policy fixed in advance, and
    the audit record names the predicate that decided.

    **Not a replacement for taint.** Bands answer whether a provenance may
    reach an argument; predicates answer whether a value is permitted.
    Predicates alone would admit a laundered value that happens to be
    allowlisted. Bands alone cannot separate two values from one document.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from trustband.taint import Tainted

#: Every operator, and the field each one requires. Used by validation and by
#: evaluation, so a new operator cannot be added to one and forgotten in the
#: other.
OPERATORS: Dict[str, Optional[str]] = {
    "in_set": "values",
    "in_context": "key",
    "max_int": "value",
    "max_minor": "value",
    "confirmed": None,
}


class PredicateError(Exception):
    """A predicate that is not well formed. Raised at validation, never at
    evaluation -- an ill-formed policy is a bug, not a refusal."""


def plain(value: Any) -> Any:
    """The value with every layer of tainting removed.

    `Tainted(Tainted(x, TOOL), SESSION)` is reachable, so unwrapping only the
    outer layer would compare a wrapper against an allowlist and never match.
    """
    while isinstance(value, Tainted):
        value = value.value
    return value


def validate_predicate(p: Any, where: str) -> None:
    """Reject an ill-formed predicate, naming where it was found."""
    if not isinstance(p, dict):
        raise PredicateError(f"{where} must be an object")
    op = p.get("op")
    if op not in OPERATORS:
        raise PredicateError(
            f"{where}.op {op!r} is not a predicate; expected one of "
            f"{sorted(OPERATORS)}")
    arg = p.get("arg")
    if not isinstance(arg, str) or not arg:
        raise PredicateError(f"{where}.arg must be a non-empty string")
    for flag in ("confirmable", "when_present"):
        if flag in p and not isinstance(p[flag], bool):
            raise PredicateError(f"{where}.{flag} must be a boolean")
    field = OPERATORS[op]
    if field is None:
        return
    if field not in p:
        raise PredicateError(f"{where} with op {op!r} requires {field!r}")
    v = p[field]
    if op == "in_set":
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise PredicateError(f"{where}.values must be a list of strings")
    elif op == "in_context":
        if not isinstance(v, str) or not v:
            raise PredicateError(f"{where}.key must be a non-empty string")
    elif op in ("max_int", "max_minor"):
        # A float bound could not be encoded: policy.py rejects floats because
        # NaN has no equality and signed zero has two representations, either
        # of which breaks the digest's injectivity. So a bound that cannot be
        # bound into a capability is refused here rather than at encode time.
        if not isinstance(v, int) or isinstance(v, bool):
            raise PredicateError(
                f"{where}.value must be an int in minor units (25000 is "
                f"250.00); floats cannot be encoded into a policy digest")


def check(predicates: List[Any], args: Mapping[str, Any],
          context: Optional[Mapping[str, Any]] = None
          ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Every predicate must hold. Returns (holds, reason, failed_predicate).

    The failing predicate is returned so a caller can ask whether a human is
    permitted to override THIS refusal. That permission is declared per
    predicate in the policy and defaults to false: an operator decides which
    denials a person may wave through, and "the payee is unknown" being one of
    them does not make "the MAC is forged" one too.

    Fail-closed throughout: an absent argument, an absent context and a
    wrong-typed value all refuse. Absence does not satisfy a constraint.
    """
    for p in predicates:
        arg, op = p["arg"], p["op"]
        # An explicit None is ABSENCE, not a value. A tool signature with
        # optional parameters is called with `recipient=None` to mean "leave
        # the payee alone", and AgentDojo passes them that way rather than
        # omitting the key. Treating None as a value made `max_minor` refuse
        # `amount None is not a number` on a call that was not setting an
        # amount at all -- fail-closed firing on a question nobody asked.
        #
        # This only relaxes anything under `when_present`; without that flag
        # the predicate still refuses, because a policy that names an argument
        # the call does not set is still unsatisfied by its absence.
        if arg not in args or args[arg] is None or plain(args[arg]) is None:
            # `when_present` constrains an argument only when it is being set.
            # Sound where omission means NO CHANGE -- omitting `recipient` from
            # update_scheduled_transaction leaves the existing payee standing,
            # so there is nothing to constrain. It is NOT sound in general, and
            # the default stays false: absence does not otherwise satisfy a
            # constraint, which is what stops a renamed parameter from quietly
            # dropping its own rule.
            if p.get("when_present"):
                continue
            return False, (
                f"grant constrains {arg!r}, which this call does not pass. "
                f"A constraint on an absent argument is not satisfied by its "
                f"absence."), p
        value = plain(args[arg])

        if op == "in_set":
            allowed = p["values"]
            if value not in allowed:
                return False, (f"{arg} {value!r} is not in the "
                               f"{len(allowed)}-entry allowlist"), p

        elif op == "in_context":
            key = p["key"]
            if context is None or key not in context:
                return False, (
                    f"{arg} requires membership of context {key!r}, which was "
                    f"not supplied. A missing set is not an empty set."), p
            if value not in context[key]:
                return False, f"{arg} {value!r} was not found in {key!r}", p

        elif op == "max_minor":
            # Money arrives from a tool in MAJOR units as a float (98.70) and a
            # policy bound must be an integer, because policy.py cannot encode
            # a float. Converted explicitly rather than coerced: an amount that
            # is not exact to the cent is REFUSED, not rounded, because
            # rounding a monetary comparison quietly is worse than declining
            # to make it.
            bound = p["value"]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False, (f"{arg} {value!r} is not a number, so it cannot "
                               f"be compared against the bound {bound} minor "
                               f"units"), p
            scaled = value * 100
            if abs(scaled - round(scaled)) > 1e-6:
                return False, (f"{arg} {value!r} is not exact to the cent, so "
                               f"it has no exact value in minor units"), p
            if round(scaled) > bound:
                return False, (f"{arg} {value} exceeds the bound of "
                               f"{bound / 100:.2f}"), p

        elif op == "max_int":
            bound = p["value"]
            if isinstance(value, bool) or not isinstance(value, int):
                return False, (f"{arg} {value!r} is not an integer in minor "
                               f"units, so it cannot be compared against the "
                               f"bound {bound}"), p
            if value > bound:
                return False, f"{arg} {value} exceeds the bound {bound}", p

        elif op == "confirmed":
            # BINDS TO THE VALUE, never to the argument name. Checking the name
            # would make one approval a standing permission: a human approves
            # paying UK123, and the next call sends to US133 through the same
            # "recipient is confirmed" fact. An approval is about a payment,
            # not about a parameter.
            confirmed = (context or {}).get("confirmed")
            if confirmed is None:
                return False, (f"{arg} requires human confirmation, and no "
                               f"confirmation set was supplied"), p
            approved = confirmed.get(arg) if isinstance(confirmed, dict) else None
            if not approved:
                return False, f"{arg} has no approved value", p
            if value not in approved:
                return False, (f"{arg} {value!r} was not the value a human "
                               f"approved"), p

    return True, f"all {len(predicates)} predicate(s) hold", None
