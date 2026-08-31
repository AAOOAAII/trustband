"""Shadow mode: watch, decide, refuse nothing — then write the policy.

WHY THIS EXISTS
    Warrantable enforces a policy you must author by hand, correctly, with no
    feedback until it blocks something in production. Running AgentDojo's
    banking suite proved how hard that is: a policy written from the suite's own
    stated intent was wrong in two separate ways and dropped benign utility from
    13/16 to 6/16.

    A gate that blocks legitimate work gets switched off, and then it protects
    nothing. So the dangerous number is not attacks getting through -- it is
    benign work being refused, and nothing in the product measured it.

WHAT SHADOW MODE DOES
    Runs the full decision path -- taint, policy, mint, ingest, authorize -- and
    then executes the tool REGARDLESS, recording what it would have done. That
    gives three things a hand-written policy cannot:

      * a safe first install, because nothing is blocked
      * the would-have-refused rate, which is the number a buyer asks for
      * a draft policy inferred from what the agent actually did

    The operator then TIGHTENS a policy that already permits real work, instead
    of authoring one from scratch and discovering the gaps in production.

WHAT IT IS NOT
    **Shadow mode is not protection.** Every call executes. It is a measurement
    and authoring tool, and a deployment left in shadow is unguarded — which is
    why `report()` says so on every line and `Runtime` refuses to seal an audit
    that was produced in shadow without recording the mode.

    **An inferred policy is a floor, not a policy.** It permits what was
    observed, so it is exactly as good as the traffic it saw. Traffic containing
    an attack infers a policy that permits that attack. Infer from traffic you
    trust, review before enforcing, and treat the output as a first draft.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from trustband.gate import Band
from trustband.taint import Tainted, taint_of

TRUST_RANK = {Band.GOVERNANCE: 0, Band.SESSION: 1, Band.TOOL: 2, Band.USER: 3}


@dataclass
class Observation:
    """One call, and what the gate would have decided."""

    session: int
    action: str
    tier: int
    would_allow: bool
    reason: str
    conjunct: Optional[str]
    arg_bands: Dict[str, str] = field(default_factory=dict)


class ShadowRecorder:
    """Accumulates observations and infers a policy from them."""

    def __init__(self) -> None:
        self.observations: List[Observation] = []

    def record(self, session: int, action: str, tier: int, would_allow: bool,
               reason: str, conjunct: Optional[str],
               args: Optional[Dict[str, Any]] = None) -> Observation:
        bands = {k: taint_of(v).value for k, v in (args or {}).items()}
        o = Observation(session, action, tier, would_allow, reason, conjunct,
                        bands)
        self.observations.append(o)
        return o

    # -- the number a buyer asks for --------------------------------------
    def report(self) -> Dict[str, Any]:
        n = len(self.observations)
        refused = [o for o in self.observations if not o.would_allow]
        by_action: Dict[str, int] = defaultdict(int)
        by_conjunct: Dict[str, int] = defaultdict(int)
        for o in refused:
            by_action[o.action] += 1
            by_conjunct[o.conjunct or "policy"] += 1
        return {
            "mode": "SHADOW — every call executed; this is measurement, not protection",
            "calls": n,
            "would_have_refused": len(refused),
            "would_have_refused_rate": (len(refused) / n) if n else None,
            "by_action": dict(sorted(by_action.items(), key=lambda kv: -kv[1])),
            "by_conjunct": dict(sorted(by_conjunct.items(), key=lambda kv: -kv[1])),
        }

    # -- the draft policy --------------------------------------------------
    def infer_policy(self, *, require_bands: bool = True) -> Dict[str, Any]:
        """A policy permitting exactly what was observed.

        One grant per session. `min_band` is set to the LEAST trusted band
        actually seen for that session's arguments -- so the inferred policy
        permits the observed traffic and nothing looser. Setting it tighter
        would refuse the very calls it was inferred from; setting it looser
        would permit what was never seen.

        `require_bands=False` omits `min_band` entirely, which produces a
        permissive draft for an operator who wants to add the taint constraint
        by hand after reading the band column in `report()`.
        """
        # PER ACTION, not per session. Merging every action into one grant
        # gives it `arg_bands` for every argument seen anywhere in the suite,
        # and the fail-closed rule then refuses each call for constraining
        # arguments it does not pass -- an inferred policy that refuses the
        # very traffic it was inferred from. Measured on slack: 48 refusals,
        # 0 of 21 tasks completed.
        tiers: Dict[Tuple[int, str], int] = defaultdict(int)
        worst: Dict[Tuple[int, str, str], Band] = {}
        seen: Set[Tuple[int, str]] = set()
        for o in self.observations:
            key = (o.session, o.action)
            seen.add(key)
            tiers[key] = max(tiers[key], o.tier)
            for name, b in o.arg_bands.items():
                band = Band(b)
                cur = worst.get((o.session, o.action, name))
                if cur is None or TRUST_RANK[band] > TRUST_RANK[cur]:
                    worst[(o.session, o.action, name)] = band
        grants: List[Dict[str, Any]] = []
        for sess, action in sorted(seen):
            g: Dict[str, Any] = {"sess": sess,
                                 "max_tier": tiers[(sess, action)],
                                 "actions": [action]}
            ab = {n: band.value for (s2, a2, n), band in sorted(worst.items())
                  if s2 == sess and a2 == action}
            if require_bands and ab:
                g["arg_bands"] = ab
                # An INFERRED refusal means "this differs from what I observed",
                # which is exactly the judgement a person should make -- so the
                # floor asks rather than blocks. Without this the confirmation
                # path is dead on any inferred policy: measured on workspace,
                # where even an oracle approving everything left utility
                # unchanged because nothing was ever put to it.
                #
                # Set only for INFERENCE. A hand-written band rule stays
                # unconfirmable unless its author says otherwise.
                g["confirmable"] = True
                # Inference observes which arguments were passed, never which
                # are required. Constraining an argument a later call omits
                # would refuse traffic the floor was built from.
                g["bands_when_present"] = True
            grants.append(g)
        return {
            "version": 1,
            "_inferred": {
                "from_calls": len(self.observations),
                "warning": ("A floor, not a policy. It permits what was "
                            "observed and is exactly as good as the traffic it "
                            "saw. Traffic containing an attack infers a policy "
                            "permitting that attack. Review before enforcing."),
            },
            "grants": grants,
        }

    def diff_against(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """What an existing policy would refuse that the traffic actually did.

        The tightening loop: infer a floor, hand-write something stricter, then
        check what the stricter one breaks before enforcing it.
        """
        from trustband.gate import Gate
        from trustband.issuance import Issuer
        probe = Issuer(Gate(budget=1))
        probe._policy = policy                      # evaluate only, never mint
        probe.gate.gov_policy = probe.gate.gov_policy
        broken: List[Dict[str, Any]] = []
        for o in self.observations:
            if not o.would_allow:
                continue
            args = {k: Tainted(None, Band(v)) for k, v in o.arg_bands.items()}
            ok, why = probe.evaluate(o.session, o.tier, o.action, args)
            if not ok and "out of step" not in why:
                broken.append({"action": o.action, "session": o.session,
                               "why": why})
        return {"observed_allowed": sum(1 for o in self.observations
                                        if o.would_allow),
                "would_now_break": len(broken),
                "examples": broken[:10]}
