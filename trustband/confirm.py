"""Turning a refusal a human may answer into a question they can answer.

WHY THIS EXISTS
    Measured 2026-08-29: a conjunctive value rule took successful attacks from
    36/144 to 4/144, and cost two benign tasks of sixteen. Both losses are the
    same shape -- a payee the user has never paid before. That is not a defect
    in the rule. It is the rule working, on a payment a person would have
    approved in one click.

    A gate that can only refuse pushes that decision into the operator's
    inbox as a support ticket. A gate that can ASK converts it into an
    approval, and the approval is itself an auditable artefact.

WHAT MAKES THIS SAFE RATHER THAN AN OVERRIDE BUTTON
    An escape hatch that lets a human wave anything through is worse than no
    hatch, because it becomes the attacker's target. Four properties, each
    enforced here and tested:

    1. **Only what the policy declares.** A predicate carries
       `"confirmable": true` or a human may not override it. Default false.
       "The payee is unknown" being answerable does not make "the MAC is
       forged" answerable -- structural refusals never reach this module.
    2. **An approval binds to the VALUE.** Approving a payment to UK123 does
       not permit US133. Enforced in the `confirmed` predicate, not here.
    3. **An approval binds to the epoch.** Rotation invalidates it, so an
       approval cannot outlive the key material it was granted under.
    4. **An approval is single-use.** It authorises a payment, not a standing
       relationship with a payee.

WHAT IT IS NOT
    Not a fraud check. A human who approves the attacker's payee has approved
    it, and the log will show they did. The claim is that the decision was put
    in front of a person with the provenance rendered, and that what they
    approved is exactly what executed.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


def value_digest(value: Any) -> str:
    """A short stable digest of a value, for records that must not store it.

    The ledger keeps this rather than the payee itself, for the same reason
    the audit entry keeps bands rather than values: a record that accumulates
    every payee becomes a store of exactly what it exists to protect, and it
    outlives all of it.
    """
    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ConfirmationRequest:
    """A refusal rendered as a question, with the provenance a person needs."""

    session: int
    action: str
    arg: str
    value: Any
    reason: str
    arg_bands: Dict[str, str]
    epoch: int
    at: float = field(default_factory=lambda: round(time.time(), 6))

    @property
    def digest(self) -> str:
        return value_digest(self.value)

    def render(self) -> str:
        """What a human is shown. Provenance first, because that is the part
        they cannot reconstruct and the part that should give them pause."""
        lines = [f"{self.action} needs your approval.",
                 f"  {self.arg}: {self.value!r}"]
        for name, band in sorted(self.arg_bands.items()):
            origin = {"tool": "came from tool output (untrusted)",
                      "session": "came from your request",
                      "governance": "came from governance",
                      "user": "came from an external user"}.get(band, band)
            lines.append(f"    {name}: {origin}")
        lines.append(f"  refused because: {self.reason}")
        return "\n".join(lines)


class ConfirmationLedger:
    """Pending questions, and the approvals that answer them."""

    def __init__(self) -> None:
        self.pending: List[ConfirmationRequest] = []
        #: (session, action, arg, digest, epoch) -> approver
        self._approved: Dict[Tuple[int, str, str, str, int], str] = {}
        self.history: List[Dict[str, Any]] = []

    # -- raising the question ---------------------------------------------
    @staticmethod
    def is_confirmable(failed: Any) -> bool:
        """Only a predicate the policy marked confirmable. Default false.

        Accepts one predicate or the list of confirmable failures collected
        across grants, because grants are a disjunction: a human may be asked
        if ANY grant's refusal is one they are permitted to answer.

        A refusal that never reached a predicate -- a forged tag, a retired
        epoch, a revoked session -- arrives as None or an empty list and is not
        confirmable. Those are not judgements a person is entitled to reverse.
        """
        if isinstance(failed, list):
            return any(bool(f) and bool(f.get("confirmable")) for f in failed)
        return bool(failed) and bool(failed.get("confirmable", False))

    def ask(self, *, session: int, action: str, arg: str, value: Any,
            reason: str, arg_bands: Dict[str, str], epoch: int
            ) -> ConfirmationRequest:
        req = ConfirmationRequest(session=session, action=action, arg=arg,
                                  value=value, reason=reason,
                                  arg_bands=dict(arg_bands), epoch=epoch)
        self.pending.append(req)
        return req

    # -- answering it -------------------------------------------------------
    def approve(self, req: ConfirmationRequest, approver: str) -> None:
        """Record that a person approved THIS value, for THIS call, THIS epoch."""
        key = (req.session, req.action, req.arg, req.digest, req.epoch)
        self._approved[key] = approver
        self.history.append({"decision": "approved", "approver": approver,
                             "session": req.session, "action": req.action,
                             "arg": req.arg, "value_digest": req.digest,
                             "epoch": req.epoch, "at": req.at})
        if req in self.pending:
            self.pending.remove(req)

    def deny(self, req: ConfirmationRequest, approver: str) -> None:
        self.history.append({"decision": "denied", "approver": approver,
                             "session": req.session, "action": req.action,
                             "arg": req.arg, "value_digest": req.digest,
                             "epoch": req.epoch, "at": req.at})
        if req in self.pending:
            self.pending.remove(req)

    # -- spending it --------------------------------------------------------
    def as_context(self, *, session: int, action: str, args: Dict[str, Any],
                   epoch: int, consume: bool = True) -> Dict[str, Any]:
        """The `confirmed` fragment for this exact call, and nothing wider.

        Built per call from the arguments actually being passed, so an approval
        for one payment cannot be read as permission for another. `consume`
        removes it: an approval authorises a payment, not a relationship.
        """
        from trustband.predicates import plain
        out: Dict[str, Set[Any]] = {}
        for arg, value in args.items():
            v = plain(value)
            key = (session, action, arg, value_digest(v), epoch)
            if key in self._approved:
                out.setdefault(arg, set()).add(v)
                if consume:
                    del self._approved[key]
        return {"confirmed": out} if out else {"confirmed": {}}
