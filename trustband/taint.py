"""Taint propagation over the band lattice.

`Band` already answers "where did this arrive from", unforgeably: it is stamped
from the accepting channel and the payload's own claim is never read. This
module answers the next question — where did a value *derived* from it come
from — by propagating the band through operations.

THE LATTICE
    GOVERNANCE > SESSION > TOOL > USER, most to least trusted. Combining values
    takes the LEAST trusted band. A value derived from anything tool-returned is
    tool-tainted, however much trusted data it was mixed with, because an
    attacker who controls one input controls the result.

WHAT THIS BUYS
    An action can require a minimum band on its arguments. "Tier 2 transfers
    may not be parameterised by tool output" becomes a check rather than a
    convention, and the refusal names which argument failed.

WHAT THIS IS NOT — read before quoting it
    **It tracks taint through the HARNESS, not through the model.** If an agent
    reads tool output and the model then emits new text about it, that text is
    a fresh value and nothing here knows it was influenced. Marking it tainted
    is the caller's job, and the discipline that makes it sound is CaMeL's
    quarantined-LLM split: the privileged model never sees untrusted content at
    all. This module cannot enforce that and does not claim to.

    **No implicit flows.** Branching on tainted data and returning a constant
    launders the taint, and this does not catch it:

        if untrusted == "yes": return TRUSTED_CONSTANT

    That is the classic soundness hole in every dynamic taint system. Sound
    implicit-flow tracking needs static analysis of the whole program, which is
    a different technique with a different cost. Recorded because a taint layer
    quoted as sound when it is not is worse than none.

    **Four bands, not reader sets.** CaMeL tracks fine-grained per-source
    provenance. This is coarse by construction — the band comes from a socket,
    and there are four. Coarse and unforgeable beats fine and forgeable for the
    enforcement decision, but they are not the same thing and this does not
    replace CaMeL's data-flow analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from trustband.gate import Band

#: Most trusted first. GOVERNANCE mints; SESSION is the authenticated user's
#: own input; TOOL is whatever a tool returned; USER is unauthenticated input.
#: TOOL and USER are both attacker-influenced and are ordered only so the meet
#: is total — nothing should depend on TOOL outranking USER.
TRUST_ORDER: Tuple[Band, ...] = (Band.GOVERNANCE, Band.SESSION, Band.TOOL,
                                 Band.USER)
_RANK: Dict[Band, int] = {b: i for i, b in enumerate(TRUST_ORDER)}


class TaintError(ValueError):
    """An operation required a band its inputs do not carry."""


def rank(b: Band) -> int:
    return _RANK[b]


def meet(a: Band, b: Band) -> Band:
    """The less trusted of two bands. Associative, commutative, idempotent."""
    return a if _RANK[a] >= _RANK[b] else b


def at_least(actual: Band, minimum: Band) -> bool:
    """Is `actual` at least as trusted as `minimum`?"""
    return _RANK[actual] <= _RANK[minimum]


# ---------------------------------------------------------------------------
# PHASE 5 -- THE CONFIDENTIALITY AXIS
#
# The band answers "where did this come from". It cannot answer "who may see
# this", and the CaMeL mapping investigation measured the cost of that gap:
# 9 of their 17 suite policies -- 53% -- turn on a confidentiality constraint a
# band cannot express. This is that dimension, in our own lattice.
#
# THE TWO AXES ARE NOT COMBINED INTO ONE SCALAR. Integrity is a total order of
# four joined by `meet`; confidentiality is a powerset joined by INTERSECTION,
# with PUBLIC on top. Both increase restrictiveness under combination, by
# different operations on different orders. Collapsing them would reintroduce
# exactly what disqualified the mapping.
# ---------------------------------------------------------------------------


class _Public:
    """Top of the reader lattice: readable by anyone. Absorbing under `&`."""
    __slots__ = ()
    def __and__(self, other): return other
    def __rand__(self, other): return other
    def __repr__(self): return "PUBLIC"
    def __hash__(self): return hash("trustband.readers.PUBLIC")
    def __eq__(self, other): return isinstance(other, _Public)


PUBLIC = _Public()
Readers = object   # PUBLIC | frozenset[str]


def readers_of(x: Any) -> Any:
    """The reader set of any value. Untagged values are PUBLIC.

    Same permissive default as `taint_of`, and for the same reason: defaulting
    to "readable by nobody" would make every literal unusable. The demand for a
    reader set is enforced where a grant makes it, not in the lattice.
    """
    r = getattr(x, "readers", None)
    return PUBLIC if r is None else r


def intersect(a: Any, b: Any) -> Any:
    """The narrower of two reader sets. PUBLIC is absorbing."""
    if isinstance(a, _Public):
        return b
    if isinstance(b, _Public):
        return a
    return frozenset(a) & frozenset(b)


def combine_readers(*values: Any) -> Any:
    """The reader set of anything derived from all of `values`.

    INTERSECTION, not union: a value derived from two sources may be shown only
    to those who could see both. This is the opposite direction from the band,
    which takes the *least* trusted -- and getting that backwards would leak.
    """
    out: Any = PUBLIC
    for v in values:
        out = intersect(out, readers_of(v))
    return out


def can_read(recipients: Any, value: Any) -> bool:
    """May every one of `recipients` see `value`?"""
    r = readers_of(value)
    if isinstance(r, _Public):
        return True
    return set(recipients).issubset(set(r))


def check_readers(recipients: Any, **arguments: Any) -> Tuple[bool, str]:
    """Non-raising audience check over named arguments, naming what failed."""
    bad = [n for n, v in arguments.items() if not can_read(recipients, v)]
    if bad:
        return False, (f"recipients {sorted(recipients)} cannot read "
                       f"{', '.join(sorted(bad))}")
    return True, f"all arguments readable by {sorted(recipients)}"


@dataclass(frozen=True)
class Tainted:
    """A value with the band it derives from. Frozen: retagging is a new value.

    The band is not a property of the data's *content*. Identical bytes arriving
    on two channels carry two bands, which is the whole point — provenance comes
    from where it arrived, never from what it says.
    """

    value: Any
    band: Band
    #: Who may see this. PUBLIC (the default) means anyone.
    readers: Any = PUBLIC

    def __post_init__(self) -> None:
        """RE-TAGGING IS MONOTONE: it can only make a value more tainted.

        `Tainted(Tainted(x, TOOL), SESSION)` used to report SESSION, because
        `taint_of` looked at the outer wrapper and stopped. That laundered tool
        output into session-band and walked it straight through a
        `min_band=session` gate -- found in the sweep, and the most dangerous
        thing it turned up, because re-wrapping a value you received is an
        ordinary thing to do.

        Wrapping now flattens: the inner value is unwrapped and the band is the
        meet of both. A caller cannot raise trust by re-tagging, only lower it.
        """
        if isinstance(self.value, Tainted):
            inner: "Tainted" = self.value
            object.__setattr__(self, "band", meet(self.band, inner.band))
            object.__setattr__(self, "value", inner.value)

    def __repr__(self) -> str:
        r = "" if isinstance(self.readers, _Public) else f", readers={sorted(self.readers)}"
        return f"Tainted({self.value!r}, {self.band.value}{r})"


def taint_of(x: Any) -> Band:
    """The band of any value. Untagged values are GOVERNANCE-clean.

    That default is deliberate and is the module's sharpest edge: an untagged
    value is treated as trusted, so **forgetting to tag untrusted input fails
    open**. The alternative — defaulting to USER — fails closed but makes every
    literal in the program tainted and the system unusable, which in practice
    gets the checks disabled altogether.

    So the burden is on ingestion to tag, and `combine` below is the only thing
    that propagates. A caller that never tags gets no protection and should not
    imagine otherwise.
    """
    return x.band if isinstance(x, Tainted) else Band.GOVERNANCE


def combine(*values: Any) -> Band:
    """The band of anything derived from all of `values` — their meet.

    `combine()` of NOTHING is GOVERNANCE, the identity of meet. Mathematically
    right and a fail-open trap: a value "derived from no inputs" is trusted, but
    a no-argument tool that reaches the world is derived from something the meet
    never saw. Callers computing a result band from a possibly-empty argument
    set must decide the empty case themselves -- `Runtime.call`'s `output_band`
    is where that decision is made for tool calls.
    """
    out = Band.GOVERNANCE
    for v in values:
        out = meet(out, taint_of(v))
    return out


def derive(fn_result: Any, *inputs: Any) -> Tainted:
    """Tag a computed result with the meet of what it was computed from."""
    return Tainted(fn_result, combine(*inputs))


def require(minimum: Band, **arguments: Any) -> None:
    """Raise unless every argument is at least `minimum`. Names the failures.

    Used at the boundary of an action, not inside it: the point is to refuse
    before the side effect, and to say which argument was responsible.
    """
    # NB: require(minimum) with no arguments passes -- there is nothing to
    # constrain. That is correct for a genuinely argument-free operation and a
    # trap for a caller who built `arguments` dynamically and passed an empty
    # dict expecting a check. The demand is over the arguments given; zero
    # arguments satisfy it vacuously.
    bad: List[str] = []
    for name, v in arguments.items():
        b = taint_of(v)
        if not at_least(b, minimum):
            bad.append(f"{name} is {b.value}")
    if bad:
        raise TaintError(
            f"requires arguments at {minimum.value} or better; " + ", ".join(bad))


def check(minimum: Band, **arguments: Any) -> Tuple[bool, str]:
    """Non-raising `require`, for a gate that wants a Decision rather than an
    exception."""
    try:
        require(minimum, **arguments)
        return True, f"all arguments at {minimum.value} or better"
    except TaintError as exc:
        return False, str(exc)


def check_each(requirements: Dict[str, Band], **arguments: Any
               ) -> Tuple[bool, str]:
    """Per-argument band check. Names every argument that failed, and why.

    A blanket minimum over a whole call cannot express the rule real workflows
    need. Paying a bill legitimately takes its AMOUNT from a document while the
    RECIPIENT must come from the user -- one blanket rule is either too strict
    (refuses the bill) or too loose (permits the attacker's payee). So the
    requirement is per argument.

    An argument with no entry in `requirements` is UNCONSTRAINED. An argument
    that has a requirement but carries no provenance is refused: silence about
    where a value came from is not evidence that it came from somewhere safe.
    """
    untagged = [n for n, v in arguments.items()
                if n in requirements and not isinstance(v, Tainted)]
    if untagged:
        need = ", ".join(f"{n} needs {requirements[n].value}"
                         for n in sorted(untagged))
        return False, (f"argument(s) {', '.join(sorted(untagged))} carry no "
                       f"provenance ({need}). An untagged value is not a "
                       f"trusted value; tag it at ingestion.")
    bad = []
    for name, value in arguments.items():
        need = requirements.get(name)
        if need is None:
            continue
        actual = taint_of(value)
        if not at_least(actual, need):
            bad.append(f"{name} is {actual.value}, needs {need.value}")
    if bad:
        return False, "; ".join(sorted(bad))
    named = sorted(n for n in arguments if n in requirements)
    return True, (f"arguments {', '.join(named)} meet their bands"
                  if named else "no argument carries a band requirement")
