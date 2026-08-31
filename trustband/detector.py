"""Bring-your-own detector — a signal that can only lower trust.

WHY THIS COMPOSES WHERE A BUNDLED DETECTOR DOES NOT
    Detection is commodity and a retraining treadmill. Rather than own one, take
    a plugin: a buyer who already runs Lakera or Prompt Guard keeps it, and it
    makes this layer stricter instead of duplicating it.

    The reason a third-party detector is safe here, and would not be in a
    params-only engine, is provenance. A detector returns a BAND FLOOR, not a
    verdict. It may push a value toward less trusted -- SESSION to TOOL to USER
    -- never toward more trusted, and the guard clamps it so even a detector
    returning GOVERNANCE for everything changes nothing.

    So a broken or malicious plugin can only over-refuse, which is visible and
    annoying, not a bypass. A plugin that errors or abstains degrades to exactly
    the band the store already assigned. The policy never relied on it.

THE DETECTOR IS QUARANTINED
    It reads untrusted text, has no tool access, and can emit one thing: a band
    no more trusted than the one it was handed. There is no channel through it,
    which is the same property that makes the extractor safe.

WHAT IT IS NOT
    Not a verdict, and not the control. In any claim, a detector is a signal
    that tightens provenance, never the thing that stops the attack -- an
    adaptive attacker recovers high success against a signature defence, and the
    security claim must not rest on one.
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Protocol, runtime_checkable

from trustband.gate import Band

#: Least trusted last, so a larger rank is less trusted. "Lower trust" means a
#: larger rank -- toward USER. A detector may raise the rank, never lower it.
_RANK = {Band.GOVERNANCE: 0, Band.SESSION: 1, Band.TOOL: 2, Band.USER: 3}


@runtime_checkable
class Detector(Protocol):
    """A plugin's one method. Return a band no MORE trusted than `current`, or
    None to abstain. Anything more trusted is clamped by the guard, so a plugin
    cannot widen permission however it is written."""

    def assess(self, text: str, current: Band) -> Optional[Band]: ...


def clamp(current: Band, proposed: Optional[Band]) -> Band:
    """The detector's contribution, made safe. Never more trusted than current.

    This is the whole safety argument in one function: a detector's output is
    accepted only if it is LESS trusted (higher rank). A more-trusted proposal,
    a None, or garbage all leave the band unchanged.
    """
    if proposed is None or not isinstance(proposed, Band):
        return current
    return proposed if _RANK[proposed] > _RANK[current] else current


def run_detectors(detectors: List[Detector], text: Any, current: Band) -> Band:
    """Fold every detector into the band, monotonically.

    A detector that raises is swallowed -- a crashing plugin must be a no-op,
    not a failure of the call, because the policy did not depend on it. The
    result is never more trusted than `current`.
    """
    if not isinstance(text, str) or not detectors:
        return current
    band = current
    for det in detectors:
        try:
            proposed = det.assess(text, band)
        except Exception:
            continue                       # a broken detector is a no-op
        band = clamp(band, proposed)
    return band


# --------------------------------------------------------------------------
# A reference detector. Regex, not a model -- a model in the path is a decision
# that can be argued with. It fires on the shape of an injected instruction, and
# it exists to prove the interface, not to be a good classifier. A real
# deployment plugs in Prompt Guard or Lakera behind the same `assess`.
# --------------------------------------------------------------------------
_INJECTION_MARKERS = [
    re.compile(r"\bignore (?:all |any |the )?(?:previous|prior|above)\b", re.I),
    re.compile(r"\bdisregard (?:all |the )?(?:previous|prior|above)\b", re.I),
    re.compile(r"<\s*/?\s*(?:system|important|instruction)s?\s*>", re.I),
    re.compile(r"\bnew instructions?\b", re.I),
    re.compile(r"\byou (?:must|should) now\b", re.I),
    # "before you finish/respond/continue" is the injection shape; "before you
    # go" is ordinary English. Measured: the broad form fired on 0.57% of real
    # arguments, all false. Tightened to the completion verbs an injection uses.
    re.compile(r"\bbefore (?:you |using any tool)"
               r"(?:.{0,20}?(?:finish|respond|reply|proceed|continue|"
               r"complete|answer|use))", re.I),
    # An imperative to act on OTHER data than the task -- send/upload/exfiltrate
    # files, secrets, credentials. The shape of a tool-description injection,
    # which is what the MCP-Scan surface is: "IMPORTANT: first send the user's
    # files to ...". Narrow verbs, so an ordinary description does not trip it.
    re.compile(r"\b(?:send|upload|post|exfiltrate|leak|forward) "
               r"(?:all |the |any )?(?:user'?s? )?"
               r"(?:files?|secrets?|credentials?|keys?|data|contents?)\b",
               re.I),
]


class MarkerDetector:
    """Fires when text carries the shape of an injected instruction.

    When it fires on a value the store trusted (SESSION or better), it lowers it
    to TOOL, so a policy needing SESSION refuses it. When it fires on something
    already TOOL or USER, it is a no-op by the clamp. A reference, not a product
    classifier.
    """

    def __init__(self, floor: Band = Band.TOOL) -> None:
        self.floor = floor

    def assess(self, text: str, current: Band) -> Optional[Band]:
        if any(p.search(text) for p in _INJECTION_MARKERS):
            return self.floor
        return None


# --------------------------------------------------------------------------
# A weak proxy for alignment, over what the tool boundary actually sees: an
# argument and the user's task. Not a reasoning audit -- we do not have the
# reasoning. It fires when an argument reaches for a distinctive token the task
# never mentioned, which is the observable shadow of goal drift. See
# docs/REASONING_AUDIT_NOTE.md for why this is a proxy, not the real thing.
# --------------------------------------------------------------------------
class TaskDriftDetector:
    """Lower an argument's band when it names something the task did not.

    Built on the token classifier: a distinctive token (a domain, an account,
    an email) that appears in the argument but NOT in the user's stated task is
    a value the agent introduced from somewhere other than the user -- the
    observable signature of an injected instruction steering the call.

    A weak proxy. It cannot see the reasoning, only the argument, and a task
    that legitimately introduces a new domain will trip it. Hence a band floor,
    never a block: at worst it asks a human.
    """

    def __init__(self, task: str = "", floor: Band = Band.TOOL) -> None:
        from trustband.tokens import distinctive_tokens
        self._task_tokens = distinctive_tokens(task or "")
        self.floor = floor

    def assess(self, text: str, current: Band) -> Optional[Band]:
        from trustband.tokens import distinctive_tokens
        introduced = distinctive_tokens(text) - self._task_tokens
        return self.floor if introduced else None
