"""Capability issuance from a policy — deciding what an agent may have.

`Gate.govern_issue` mints what it is asked for, subject only to a budget. It is
the *minting* step, not the *authorisation* step: nothing in it reads a policy
or decides whether this agent should get this tier. That decision is here.

    policy  --(evaluate)-->  grant or refusal  --(mint)-->  capability

THE SHAPE OF THE POLICY
    A policy is a restricted value (see `trustband.policy`) with a schema:

        {"version": 1,
         "grants": [{"sess": 7, "max_tier": 1, "actions": ["read", "list"]}]}

    Malformed policies are rejected at adoption, not at issuance time, for the
    same reason the encoder rejects at construction: a policy that cannot be
    evaluated must stop issuance, never fall through to a permissive default.

WHAT A CAPABILITY IS AND IS NOT SCOPED TO
    The model's `Cap` binds (sess, tier, nonce, policy_digest). It carries **no
    action**. So a capability is *policy-scoped*, not *action-scoped*: it is
    valid for any action the policy permits at that tier, and dies the moment
    the policy changes — because the digest changes and conjunct (G) refuses it.

    That is weaker than per-action capabilities and it is stated rather than
    glossed. Binding the action would mean a sixth MAC field and a new
    counterexample, the same shape as Phase 2 and Phase 3. It is not done here.

WHAT THIS DOES NOT DO
    No taint tracking. Nothing here knows whether the request was influenced by
    untrusted content; it decides only whether the policy grants the tier. An
    agent manipulated into making a *permitted* request gets a valid capability,
    correctly. That is the layer above, and it is CaMeL's contribution, not this
    one.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from trustband.gate import Cap, Decision, Gate
from trustband.policy import PolicyDomainError, digest
from trustband.predicates import (PredicateError, check as predicate_check,
                                   validate_predicate)
from trustband.taint import (Band, Tainted, at_least, taint_of,
                               check as taint_check,
                               check_each as taint_check_each,
                               check_readers)

SCHEMA_VERSION = 1


class PolicySchemaError(ValueError):
    """The policy is a valid encodable value but not a valid POLICY.

    Distinct from `PolicyDomainError`, which means it could not be encoded at
    all. Both stop issuance; they fail for different reasons and a refusal
    should say which.
    """


def validate(policy: Any) -> None:
    """Reject a malformed policy. Called at adoption, not at issuance."""
    try:
        digest(policy)                      # must be encodable at all
    except PolicyDomainError as exc:
        raise PolicySchemaError(f"policy is not encodable: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicySchemaError(
            f"policy must be a map, got {type(policy).__name__}")
    if policy.get("version") != SCHEMA_VERSION:
        raise PolicySchemaError(
            f"policy version {policy.get('version')!r} != {SCHEMA_VERSION}. "
            f"Versions are not silently accepted: a policy written for another "
            f"schema may mean something different under this one.")
    grants = policy.get("grants")
    if not isinstance(grants, list):
        raise PolicySchemaError("policy.grants must be a list")
    for i, g in enumerate(grants):
        if not isinstance(g, dict):
            raise PolicySchemaError(f"grants[{i}] must be a map")
        for field, typ in (("sess", int), ("max_tier", int), ("actions", list)):
            if field not in g:
                raise PolicySchemaError(f"grants[{i}] missing {field!r}")
            if field == "sess" and g[field] == "*":
                continue
            if not isinstance(g[field], typ) or isinstance(g[field], bool):
                raise PolicySchemaError(
                    f"grants[{i}].{field} must be {typ.__name__}"
                    + (' (or "*" for any session)' if field == "sess" else ""))
        if "recipients" in g:
            if not isinstance(g["recipients"], list) or not all(
                    isinstance(x, str) for x in g["recipients"]):
                raise PolicySchemaError(
                    f"grants[{i}].recipients must be a list of strings")
        valid = {b.value for b in Band}
        if "min_band" in g:
            if g["min_band"] not in valid:
                raise PolicySchemaError(
                    f"grants[{i}].min_band {g['min_band']!r} is not a band; "
                    f"expected one of {sorted(valid)}")
        if "bands_when_present" in g and not isinstance(
                g["bands_when_present"], bool):
            raise PolicySchemaError(
                f"grants[{i}].bands_when_present must be a boolean")
        if "arg_bands" in g:
            ab = g["arg_bands"]
            if not isinstance(ab, dict):
                raise PolicySchemaError(
                    f"grants[{i}].arg_bands must be a map of argument name to "
                    f"band")
            for k, v in ab.items():
                if not isinstance(k, str):
                    raise PolicySchemaError(
                        f"grants[{i}].arg_bands keys must be str")
                if v not in valid:
                    raise PolicySchemaError(
                        f"grants[{i}].arg_bands[{k!r}] {v!r} is not a band; "
                        f"expected one of {sorted(valid)}")
        if "require" in g:
            if not isinstance(g["require"], list):
                raise PolicySchemaError(
                    f"grants[{i}].require must be a list of predicates")
            for j, pred in enumerate(g["require"]):
                try:
                    validate_predicate(pred, f"grants[{i}].require[{j}]")
                except PredicateError as e:
                    raise PolicySchemaError(str(e)) from None
        if not 0 <= g["max_tier"] <= 2:
            raise PolicySchemaError(
                f"grants[{i}].max_tier {g['max_tier']} outside 0..2")
        for j, a in enumerate(g["actions"]):
            if not isinstance(a, str):
                raise PolicySchemaError(f"grants[{i}].actions[{j}] must be str")


class Issuer:
    """Evaluates a policy and mints only what it grants.

    Holds no keys and performs no cryptography. It decides; `Gate.govern_issue`
    mints. Keeping those apart is deliberate: the minting step is the one the
    model proves is the sole writer of `issued`, and adding policy logic inside
    it would put an evaluator in the trusted path for no reason.
    """

    def __init__(self, gate: Gate) -> None:
        self.gate = gate
        self._policy: Optional[Dict[str, Any]] = None
        self.refusals: List[Dict[str, Any]] = []

    # -- adoption ----------------------------------------------------------
    def adopt(self, policy: Any) -> Decision:
        """Validate, then hand the policy to the gate. Both or neither.

        The gate's digest and this evaluator's rules must describe the SAME
        policy, or a capability could be bound to a digest whose rules nobody
        applied. So validation happens first and `govern_repolicy` second.
        """
        validate(policy)
        d = self.gate.govern_repolicy(policy)
        self._policy = policy
        return d

    # -- the decision ------------------------------------------------------
    def evaluate(self, sess: int, tier: int, action: str,
                 args: Optional[Dict[str, Any]] = None,
                 context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Does the policy grant this? Returns (allowed, reason).

        Pure: reads the policy and nothing else. Separated from `issue` so it
        can be tested, logged and dry-run without minting anything.
        """
        if self._policy is None:
            return False, "no policy adopted; issuance is closed by default"
        # THE DIGEST THE GATE ENFORCES MUST BE THE POLICY THESE RULES CAME FROM.
        #
        # Conjunct (G) proves a capability was minted while a given policy was
        # in force. It does NOT prove that the rules evaluated to authorise the
        # minting were that policy's rules. If governance calls
        # `gate.govern_repolicy` directly, this evaluator keeps applying the old
        # rules while the gate binds the new digest -- and every capability it
        # mints then passes (G), because the digest matches by construction.
        #
        # Demonstrated: gate locked down to a policy granting session 7 nothing,
        # issuer still holding one that granted it tier 1, capability minted and
        # ACCEPTED. Access the enforced policy forbids.
        #
        # So the evaluator refuses when it is not evaluating what is enforced.
        # This is a composition property: both components were correct and the
        # pair was not.
        if digest(self._policy) != self.gate.gov_policy:
            return False, ("evaluator is out of step with the gate: these rules "
                           "are not the enforced policy. Adopt through "
                           "Issuer.adopt so both move together.")
        # EVERY grant for this session is tried, not just the first.
        #
        # This loop used to `return` on the first grant whose session matched,
        # so a policy with two grants for one session -- "may read these tools,
        # and may write those subject to a band requirement", an entirely
        # ordinary shape -- silently ignored everything after the first. Found
        # by running AgentDojo's banking suite: benign utility fell from 13/16
        # to 6/16 because send_money was checked against the read-only grant
        # and never reached the grant that permits it.
        #
        # A session is permitted if ANY of its grants permits. Refusal reports
        # the last grant's reason, which is the most specific one tried.
        matched = False
        # THE MOST INFORMATIVE REASON, NOT THE LAST ONE TRIED.
        #
        # Grants are a disjunction, so every one is attempted and each failure
        # overwrote the previous. A band failure on the grant that actually
        # governs the action was then reported as "action not in the actions
        # granted" from an unrelated grant tried afterwards -- which sent a
        # diagnosis down the wrong path for an hour on 2026-08-30, and made the
        # audit record name a rule that had nothing to do with the decision.
        #
        # Rank instead: a grant that matched the action and failed a specific
        # check says more than one that never matched the action at all.
        last_reason = ""
        last_rank = -1

        def _note(rank: int, text: str, gi: Optional[int] = None) -> None:
            nonlocal last_reason, last_rank
            if rank > last_rank:
                last_reason, last_rank = text, rank
                _last_note_grant[0] = gi
        # Grants are a DISJUNCTION, so a human may be asked if ANY grant's
        # refusal is one the policy says they may answer. Keeping only the last
        # -- which is right for `last_reason`, the most specific message --
        # would hide a confirmable refusal behind a later grant that failed for
        # a reason nobody may wave through.
        self.last_failed_predicate: Optional[Dict[str, Any]] = None
        self.confirmable_failures: List[Dict[str, Any]] = []
        #: WHICH grant decided, by index, alongside the prose reason.
        #: `last_reason` is the most specific MESSAGE; it is not an identity,
        #: and grouping decisions by message text is not grouping them by rule.
        #: Replay needs the rule. Set to the index whose refusal is being
        #: reported, or left None when no grant matched at all -- naming an
        #: arbitrary one would have a replay attribute a decision to a rule
        #: that did not make it.
        self.deciding_grant: Optional[int] = None
        _last_note_grant: List[Optional[int]] = [None]
        for _gi, g in enumerate(self._policy["grants"]):
            # "*" matches any session. Needed because a host's sessions are
            # dynamic -- a Claude Code conversation id is not known when the
            # policy is written -- and without it a starter policy refuses
            # every call, which is what dogfooding found on the first run.
            #
            # A wildcard grant applies to EVERY session, which is what its
            # author asked for. Provenance is unaffected: its store is keyed by
            # the session string, so one session's tool output still cannot
            # taint another's arguments.
            if g["sess"] != "*" and g["sess"] != sess:
                continue
            matched = True
            if tier > g["max_tier"]:
                _note(1, f"tier {tier} exceeds max_tier {g['max_tier']} "
                         f"granted to session {sess}", _gi)
                continue
            # "*" matches any action, for the same reason "*" matches any
            # session: a host allocates tool names the policy author cannot
            # know. MCP servers add tools at runtime.
            if "*" not in g["actions"] and action not in g["actions"]:
                _note(0, f"action {action!r} not in the actions granted "
                         f"to session {sess}: {g['actions']}", _gi)
                continue
            # TAINT. A grant may require a minimum band on the arguments, so
            # "tier 2 transfers may not be parameterised by tool output" is a
            # check rather than a convention. Absent min_band, arguments are
            # unconstrained -- stated, because silence here is permissive.
            #
            # `arg_bands` names a band PER ARGUMENT and overrides `min_band`
            # for the arguments it names; `min_band` still covers the rest.
            # A blanket rule cannot say "the recipient must come from the user
            # but the amount may come from the document", which is the shape
            # every real payment workflow has, so a grant carrying only
            # `min_band` is either too strict or too loose.
            if "arg_bands" in g or "min_band" in g:
                default = Band(g["min_band"]) if "min_band" in g else None
                req: Dict[str, Band] = {}
                for k in (args or {}):
                    named = g.get("arg_bands", {}).get(k)
                    if named is not None:
                        req[k] = Band(named)
                    elif default is not None:
                        req[k] = default
                # An arg_bands entry for an argument that was not passed is a
                # policy naming something the call does not have. Refused
                # rather than ignored: silently skipping it would let a
                # renamed parameter drop its own constraint.
                # An INFERRED floor cannot know which arguments are optional.
                # `search_emails` passes `sender` on some calls and not others,
                # so a floor naming both refuses every call that omits one --
                # 13 of them on workspace, and the policy was rejected by its
                # own replay guard. `bands_when_present` constrains only what a
                # call actually passes.
                #
                # Set by inference, never the default: a HAND-written policy
                # naming an argument still means it, and absence still does not
                # satisfy a constraint.
                missing = ([] if g.get("bands_when_present")
                           else sorted(set(g.get("arg_bands", {}))
                                       - set(args or {})))
                if missing:
                    _note(2,
                          f"taint: grant constrains argument(s) "
                          f"{', '.join(missing)}, which this call does not "
                          f"pass. A constraint on an absent argument is not "
                          f"satisfied by its absence.", _gi)
                    continue
                ok, why = taint_check_each(req, **(args or {}))
                if not ok and g.get("confirmable"):
                    # A PERSON ANSWERED THIS EXACT QUESTION. `confirmed` is
                    # built per call from the values actually being passed
                    # (confirm.py as_context), so it names an argument AND
                    # the value a person approved. The band check is lifted
                    # only for the arguments that fail it, only when every
                    # such value is the approved one, and only under a grant
                    # the policy marked confirmable. An approval for UK123
                    # lifts nothing for US133, and nothing for a grant that
                    # never offered a person the question.
                    confirmed = (context or {}).get("confirmed")
                    if isinstance(confirmed, dict) and confirmed:
                        from trustband.predicates import plain as _plain_value
                        failing = [k for k, need in req.items()
                                   if k in (args or {})
                                   and not at_least(taint_of(args[k]), need)]
                        if failing and all(
                                _plain_value(args[k]) in (confirmed.get(k) or ())
                                for k in failing):
                            ok, why = True, (f"band refusal lifted by a person's "
                                             f"approval of {', '.join(failing)}")
                if not ok:
                    _note(2, f"taint: {why} (grant for session {sess})", _gi)
                    # A BAND refusal may also be one a human is allowed to
                    # answer, when the policy says so. "A document wants to
                    # change your address" is a decision a person should make;
                    # "the MAC is forged" is not, and a structural refusal
                    # never reaches this code at all. Default stays false.
                    if g.get("confirmable"):
                        failing = [k for k, need in req.items()
                                   if k in (args or {})
                                   and not at_least(taint_of(args[k]), need)]
                        for k in failing or list(req):
                            self.confirmable_failures.append(
                                {"arg": k, "op": "band", "confirmable": True})
                    continue
            if "recipients" in g:
                ok, why = check_readers(set(g["recipients"]), **(args or {}))
                if not ok:
                    _note(2, f"confidentiality: {why} (grant for session "
                             f"{sess})", _gi)
                    continue
            # VALUE PREDICATES, last because they are the most expensive and
            # the most likely to need runtime context, and because a refusal
            # from an earlier conjunct is the more specific one.
            #
            # Bands cannot separate two values that came from one document:
            # the legitimate payee and the attacker's payee on a poisoned bill
            # are both TOOL, so a strict rule refuses the bill and a permissive
            # one admits the attack. This asks the other question -- is this
            # value one the policy named in advance.
            if "require" in g:
                ok, why, failed = predicate_check(g["require"], args or {},
                                                  context)
                if not ok:
                    _note(2, f"predicate: {why} (grant for session {sess})", _gi)
                    # The failing predicate is kept so a caller can ask whether
                    # a human may answer THIS refusal. Keeping only the last
                    # one matches `last_reason`: both describe the most
                    # specific grant tried.
                    self.last_failed_predicate = failed
                    if failed and failed.get("confirmable"):
                        self.confirmable_failures.append(failed)
                    continue
            # An ALLOW names its grant too. A record showing None for a
            # permitted call would say "no rule decided this", which is false
            # and would leave a replay unable to group allows by rule at all.
            self.deciding_grant = _gi
            return True, (f"granted by session {sess} at tier <= "
                          f"{g['max_tier']} for {action!r}")
        if matched:
            self.deciding_grant = _last_note_grant[0]
            return False, last_reason or f"no grant matched for session {sess}"
        return False, (f"session {sess} appears in no grant. Absence is "
                       f"refusal: there is no default grant.")

    def issue(self, sess: int, tier: int, action: str, nonce: int,
              args: Optional[Dict[str, Any]] = None,
              context: Optional[Dict[str, Any]] = None
              ) -> Tuple[Decision, Optional[Cap]]:
        """Evaluate, then mint only if allowed.

        `args` carries the tool call's arguments so their bands can be checked
        against the grant's `min_band`. Passing none means none are checked.
        """
        allowed, reason = self.evaluate(sess, tier, action, args, context)
        if not allowed:
            self.refusals.append({"sess": sess, "tier": tier, "action": action,
                                  "reason": reason})
            return Decision(False, f"policy refused: {reason}", "policy"), None
        return self.gate.govern_issue(sess=sess, tier=tier, nonce=nonce)
