"""The integrator's surface: one guarded tool call.

Everything else in this package is a component. This is the thing a user calls,
and it is deliberately small — if the composed path needs more than one function
to describe, the components are wrong.

    rt = Runtime(policy=POLICY, budget=64)
    out = rt.call(session=7, action="transfer", tier=2,
                  args={"amount": amount, "payee": payee},
                  fn=bank.transfer)

WHAT HAPPENS, IN ORDER, AND WHY THE ORDER MATTERS
    1. taint + policy   `Issuer.evaluate` — the arguments' bands are checked
                        against the grant BEFORE anything is minted, so a
                        refused call never produces a capability at all.
    2. mint             only if step 1 allowed it.
    3. ingest           on the session channel; the band is stamped from the
                        channel, never from the caller.
    4. authorize        the gate's conjunct chain.
    5. execute          **only** if step 4 allowed it.
    6. audit            every step, allowed or refused, hash-chained.

    The function is invoked at step 5 and nowhere else. That is the single
    property this module exists to provide, and `test_runtime_composition`
    attacks it directly.

WHAT IT DOES NOT DO
    - It does not sandbox `fn`. A tool that ignores its arguments and does
      something else is outside every boundary here.
    - It does not tag arguments for you — ingestion must. But where a grant
      declares `min_band`, an UNTAGGED argument is now REFUSED rather than
      treated as trusted. The lattice keeps its permissive default (see
      `taint.taint_of`); the demand for provenance is enforced where the demand
      is made. Found by attacking this surface: a plain string passed as an
      injected payee was allowed straight through.
    - It does not survive a caller who reaches past it into `Gate` directly.
      The desync guard in `Issuer` catches the policy case; nothing catches a
      caller who mints and authorises by hand. The surface is a convenience for
      the honest path, not a sandbox around the components.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from trustband.gate import Band, Cap, Channel, Decision, Gate
from trustband.issuance import Issuer
from trustband.shadow import ShadowRecorder
from trustband.taint import Tainted, combine, combine_readers, taint_of


@dataclass
class CallResult:
    """What happened. `ran` is the fact that matters.

    `value` is TAINTED. A tool's output is derived from its arguments, so an
    output computed from tool-derived input is itself tool-derived — and
    returning it bare dropped that on the floor. Found by attacking the pair:
    the band was computed, reported, and then discarded at the boundary, so
    feeding a result into the next call laundered it.

    The untagged-argument guard in `issuance` happened to catch the specific
    case, but only where a grant declares `min_band`. Relying on that would be
    depending on a guard to cover a propagation break, so the propagation is
    fixed instead. `plain` is the raw value for callers who want it, and taking
    it is an explicit choice to drop provenance rather than the default.
    """

    allowed: bool
    ran: bool
    value: Any = None
    reason: str = ""
    conjunct: Optional[str] = None
    stage: str = ""
    result_band: Optional[Band] = None

    def __bool__(self) -> bool:
        return self.allowed and self.ran

    @property
    def plain(self) -> Any:
        """The untainted value. Taking this DROPS provenance -- deliberate and
        explicit, rather than the default."""
        return self.value.value if isinstance(self.value, Tainted) else self.value


def _arg_bands(args: Dict[str, Any]) -> Dict[str, str]:
    """Argument NAMES and their bands, for the audit entry.

    Names and bands, never values. A refusal reason already quotes the
    deciding value because a human reading a denial needs to see it, but the
    structured record is deliberately provenance-only: an audit log that
    accumulated every payee and amount would become a store of exactly the
    data it exists to protect, and it is retained longer than any of it.

    This is what makes the confirmation surface a read path. The same fact --
    which argument came from where -- is then available at the moment of
    approval, on demand during operation, and in the sealed log afterwards,
    without being derived three different ways.
    """
    return {k: taint_of(v).value for k, v in args.items()}


class Runtime:
    """Policy in, guarded calls out."""

    def __init__(self, policy: Any, budget: int = 64,
                 gate: Optional[Gate] = None, shadow: bool = False) -> None:
        """`shadow=True` runs the full decision path and executes ANYWAY.

        Not protection -- measurement. Every call runs; the recorder collects
        what would have been refused, and `shadow_report()` / `infer_policy()`
        turn that into the false-refusal rate and a draft policy. A deployment
        left in shadow is unguarded, and every report line says so.
        """
        self.shadow = shadow
        self.recorder = ShadowRecorder() if shadow else None
        self.gate = gate if gate is not None else Gate(budget=budget)
        self.issuer = Issuer(self.gate)
        self.issuer.adopt(policy)
        # NONCES MUST BE UNIQUE PER GATE, NOT PER RUNTIME.
        #
        # Two Runtimes sharing one Gate both started at 0, so the second minted
        # a capability identical to the first and was refused as a duplicate --
        # fail-closed, but a legitimate second runtime silently could not work.
        # Found in the sweep. A random high-entropy base makes collision between
        # independent runtimes negligible without needing them to coordinate.
        self._nonce = secrets.randbits(48) << 16
        self.calls: int = 0
        #: Phase 7. Same key store as the gate, so an identity and a capability
        #: are under one custody claim.
        from trustband.identity import AgentRegistry
        self.agents = AgentRegistry(self.gate.keys,
                                    epoch_of=lambda: self.gate.gov_epoch)

    # -- entries the action targets ---------------------------------------
    def register(self, eid: int, tier: int = 2) -> Decision:
        """The store entry an elevation targets. Separate from policy: the
        policy says who may act, this says what exists to act on."""
        return self.gate.write(tier, eid)

    def adopt(self, policy: Any) -> Decision:
        """Change the enforced policy. Goes through the issuer so the gate's
        digest and the evaluator's rules move together — the desync that was
        found and fixed in `issuance`."""
        return self.issuer.adopt(policy)

    def revoke_all(self) -> Decision:
        """Rotate the epoch. Every outstanding capability dies at (F).

        **IT DOES NOT UNDO ELEVATIONS ALREADY GRANTED.** After `revoke_all()`,
        `gate.elev` still contains the (eid, tier) pairs those capabilities
        authorised, and `influence()` keeps returning True for them. The
        capability is dead; its effect is not.

        That is still true and is now FIXABLE rather than merely disclosed:
        `withdraw(eid, tier)` removes the effect, proved in Phase 4. Rotation
        and withdrawal remain separate operations on purpose -- wiring them
        together would answer a policy question by accident.

        That is faithful to the model rather than a drift from it —
        `authorize_elevation` is the sole writer of `elev` and nothing in the
        state machine ever removes from it — so the honest word for the property
        is that rotation stops an agent obtaining NEW elevations, not that it
        takes back the ones it has.

        Clearing `elev` here would make the implementation do something the
        proof does not cover, which is the drift this whole crate exists to
        avoid. It is recorded as a Phase 4 obligation instead: a transition that
        withdraws elevations, with the invariant and the counterexample that
        make it falsifiable.

        Per-SESSION revocation is proved (Phase 3,
        `thm_session_revocation_is_local`) and not yet in this implementation,
        so today the only granularity here is all-or-nothing.
        """
        return self.gate.govern_rotate()

    def revoke_session(self, session: int) -> Decision:
        """Revoke ONE session. Phase 3: its capabilities die at (H) and no
        other session is affected (`thm_session_revocation_is_local`)."""
        return self.gate.revoke_session(session)

    def revoke_agent(self, agent: Any) -> None:
        """Phase 7. By `AgentId`: its principal's session epoch is bumped, so
        capabilities it already holds die at (H), and its name is refused at
        the identity check before any later call reaches the gate."""
        from trustband.identity import AgentId
        if isinstance(agent, AgentId):
            self.gate.revoke_session(agent.principal)
            self.agents.revoke(agent.name)
        else:
            self.agents.revoke(str(agent))

    def withdraw(self, eid: int, tier: int) -> Decision:
        """Withdraw one elevation. Phase 4: undoes the EFFECT a capability had,
        which rotation does not. Idempotent, and strictly de-escalating."""
        return self.gate.withdraw_elevation(eid, tier)

    # NOTE ON A RAISING TOOL AND ITS MESSAGE. Only the exception TYPE is
    # recorded, because messages routinely carry arguments. This runtime owns
    # no provenance store, so the text is the CALLER's to band: whoever reads
    # `str(exc)` must remember it TOOL before the model sees it. The Guard
    # adapters do (measured, P8); a direct Runtime caller must do it too.
    #
    # NOTE ON A RAISING TOOL AND THE ELEVATION IT OBTAINED.
    #
    # If `fn` raises, the elevation the capability won at `authorize` STANDS.
    # That is deliberate: the gate authorised the action, and whether the tool
    # then succeeded is the tool's business, not the gate's. But it means a
    # failed action can leave standing authority, so `withdraw(eid, tier)` is
    # the operator's move after a tool failure, and `elevations()` below is how
    # to see what is outstanding.

    def elevations(self) -> set:
        """The elevations currently standing. Exposed because `revoke_all`
        does not clear them and a caller needs to be able to see that."""
        return set(self.gate.elev)

    def shadow_report(self) -> Any:
        """The would-have-refused rate. None outside shadow mode."""
        return self.recorder.report() if self.recorder else None

    def infer_policy(self, **kw: Any) -> Any:
        """A draft policy permitting exactly the observed traffic."""
        return self.recorder.infer_policy(**kw) if self.recorder else None

    def seal(self) -> Any:
        return self.gate.seal_audit()

    def verify_audit(self) -> Any:
        return self.gate.verify_audit()

    # -- the guarded call --------------------------------------------------
    def call(self, *, session: int, action: str, tier: int, eid: int,
             args: Dict[str, Any], fn: Callable[..., Any],
             output_band: Optional[Band] = None,
             context: Optional[Dict[str, Any]] = None,
             agent: Optional[Any] = None) -> CallResult:
        """Evaluate, mint, ingest, authorize, and only then execute.

        `output_band` declares the provenance of the RESULT for a tool whose
        output is not a pure function of its arguments. This closes a fail-open
        found in the sweep: the result band is otherwise the meet of the
        arguments, so a NO-ARGUMENT effectful tool -- `fetch_news()`,
        `read_inbox()` -- returns a value marked GOVERNANCE-clean however
        untrusted its content is, and that value then flows into a sink
        unblocked.

        The taint system cannot know a tool reached outside its arguments, so
        the caller must say. When a tool takes untrusted-world input, pass
        `output_band=Band.TOOL`. The default -- meet of the arguments -- is
        sound ONLY for a pure function of its arguments, and that condition is
        the caller's to know.
        """
        self.calls += 1
        self._nonce += 1
        nonce = self._nonce

        # PHASE 7 -- an agent's PRINCIPAL stands where the session goes.
        # The capability is then minted for the agent's verified tag, so one
        # minted for the researcher and presented by the writer dies at (C),
        # and revoking the agent kills its capabilities at (H). The identity
        # itself is checked first; nothing below runs for a forged one.
        if agent is not None:
            ok, why, conj = self.agents.verify(agent)
            if not ok:
                self.gate._record("runtime.call", Decision(False, why, conj),
                                  action=action, session=session,
                                  agent=getattr(agent, "name", None),
                                  stage="identity")
                return CallResult(False, False, reason=why, conjunct=conj,
                                  stage="identity")
            session = agent.principal

        # 1-2. policy + taint, then mint only if granted
        # In shadow the DECISION is still computed in full -- taint, policy,
        # bands -- and only the refusal is withheld. Recording a decision the
        # gate did not actually make would measure nothing.
        if self.shadow:
            would, why = self.issuer.evaluate(session, tier, action, args,
                                              context)
            assert self.recorder is not None
            self.recorder.record(session, action, tier, would, why, None, args)
            if not would:
                self.gate._record("runtime.call", Decision(
                    True, f"SHADOW: would have refused -- {why}", None),
                    action=action, session=session, stage="shadow_allow")
                plain = {k: (v.value if isinstance(v, Tainted) else v)
                         for k, v in args.items()}
                value = fn(**plain)
                band = output_band if output_band is not None else combine(*args.values())
                return CallResult(True, True, value=Tainted(value, band),
                                  reason=f"SHADOW: would have refused -- {why}",
                                  stage="shadow_allow", result_band=band)

        d_issue, cap = self.issuer.issue(session, tier, action, nonce, args,
                                         context)
        if not d_issue or cap is None:
            self.gate._record("runtime.call", Decision(
                False, d_issue.reason, d_issue.conjunct),
                action=action, session=session, stage="issue",
                arg_bands=_arg_bands(args))
            return CallResult(False, False, reason=d_issue.reason,
                              conjunct=d_issue.conjunct, stage="issue")

        # 3-4. ingest on the session channel, then the gate's conjunct chain
        presented = self.gate.ingest(Channel.SESSION_DEMUX, cap)
        d_auth = self.gate.authorize(presented, session, eid, tier)
        if not d_auth:
            self.gate._record("runtime.call", Decision(
                False, d_auth.reason, d_auth.conjunct),
                action=action, session=session, stage="authorize",
                arg_bands=_arg_bands(args))
            return CallResult(False, False, reason=d_auth.reason,
                              conjunct=d_auth.conjunct, stage="authorize")

        # 5. execute. The ONLY invocation of `fn` in this module.
        plain = {k: (v.value if isinstance(v, Tainted) else v)
                 for k, v in args.items()}
        # A RAISING TOOL MUST STILL BE RECORDED.
        #
        # Found by attacking runtime x audit: an exception from `fn` propagated
        # before the audit entry was written, so the log showed authorize
        # succeeding and then nothing. A reader could not tell whether the tool
        # ran, half-ran, or blew up -- and "we permitted it and do not know what
        # happened" is exactly the third case an audit exists to distinguish.
        #
        # The exception is re-raised, never swallowed: the caller must see it.
        # Only the TYPE is recorded, not the message, because exception text
        # routinely contains the arguments and an audit log is not the place to
        # widen the blast radius of a secret.
        try:
            value = fn(**plain)
        except BaseException as exc:
            self.gate._record("runtime.call", Decision(
                True, f"tool raised {type(exc).__name__}", None),
                action=action, session=session, stage="raised",
                error_type=type(exc).__name__)
            raise

        # The result inherits the arguments' taint: an output computed from
        # tool-derived input is itself tool-derived, whatever the tool returns.
        # A pure function of its arguments inherits their meet. An effectful
        # tool must declare its output band -- see the fail-open in the
        # docstring. combine() of no arguments is GOVERNANCE, which is exactly
        # the trap output_band exists to let the caller avoid.
        band = output_band if output_band is not None else combine(*args.values())
        # PHASE 5 -- the reader set propagates too, by INTERSECTION.
        #
        # Found by attacking pair 2 of the registered list: the band reached the
        # result and the audience did not, so a value readable only by bob came
        # back PUBLIC and could be shown to anyone. Exactly the shape of the
        # earlier taint-at-the-boundary defect, on the axis added the same day --
        # a second axis reproduces the first axis's bugs unless each propagation
        # site is fixed for both.
        #
        # `output_band` deliberately does NOT widen the audience: a tool that
        # declares its own provenance is saying where its output came from, not
        # who may see it. Narrowing is never lost by declaring a band.
        rdrs = combine_readers(*args.values())
        self.gate._record("runtime.call", Decision(True, "executed", None),
                          action=action, session=session, stage="execute",
                          arg_bands=_arg_bands(args),
                          result_band=band.value, band_declared=output_band is not None)
        return CallResult(True, True, value=Tainted(value, band, rdrs),
                          reason="executed", stage="execute", result_band=band)
