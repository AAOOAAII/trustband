"""The two hooks, and everything a host needs to plug into them.

This is the surface from `GUARD_INTERFACE.md`, which was frozen before this
file existed. Adapters depend on it; the conformance suite checks it.

WHY THE SECOND HOOK IS NOT OPTIONAL
    `before_tool_call` is what every competitor has. `after_tool_result` --
    band the result by where it arrived from -- is the one a params-only engine
    has no equivalent of, and it is why a policy over provenance halves attacks
    on free-text tools where an allowlist does nothing.

    An adapter that implements only the first hook has shipped a policy engine,
    not this. `conformance.py` fails it.

SESSIONS ARE A SECURITY BOUNDARY, NOT BOOKKEEPING
    Provenance is scoped per session. A value remembered while serving one
    conversation must never be recalled while serving another, or one user's
    tool output silently taints another user's arguments. A host that cannot
    supply a stable session identity should refuse to start rather than share
    one store, and `Guard` refuses on its behalf.
"""
from __future__ import annotations

import hashlib
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from trustband.audit import AuditLog
from trustband.confirm import ConfirmationLedger, ConfirmationRequest
from trustband.gate import Band, Gate
from trustband.identity import AgentId, AgentRegistry, FileEpochKeys
from trustband.lock import (Lockfile, LockError, key_of as _lock_key,
                            read_pending as _lock_pending, write_pending as _lock_write_pending)
from trustband.issuance import Issuer
from trustband.provenance import ProvenanceStore
from trustband.redact import Redactor, from_config as redact_from_config
from trustband.taint import Tainted


class GuardConfigError(Exception):
    """A configuration that cannot be honoured. Stops the adapter."""


@dataclass(frozen=True)
class ToolCall:
    session: str
    tool: str
    args: Mapping[str, Any]
    tier: int = 2
    context: Mapping[str, Any] = field(default_factory=dict)
    #: Who is calling, when the adapter can say. Checked before policy: a
    #: forged, stale, revoked or wrong-session identity refuses on its own.
    agent: Optional[AgentId] = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    conjunct: Optional[str] = None
    confirmable: bool = False
    request: Optional[ConfirmationRequest] = None

    def __bool__(self) -> bool:
        return self.allowed


class Guard:
    """Authorize a tool call, and remember where its result came from."""

    def __init__(self, policy: Dict[str, Any], *, mode: str = "shadow",
                 provenance_max_entries: int = 4096,
                 gate: Optional[Gate] = None,
                 detectors: Optional[list] = None,
                 audit_path: Optional[Any] = None,
                 redactor: Optional["Redactor"] = None,
                 key_path: Optional[Any] = None) -> None:
        if mode not in ("shadow", "enforce"):
            raise GuardConfigError(
                f"mode must be 'shadow' or 'enforce', not {mode!r}")
        self.mode = mode
        #: Phase 8b. The lockfile's digest is a field of the policy, so it is
        #: in the policy digest, so it is in every capability's MAC -- and a
        #: capability minted under manifest v1 dies under v2 at (G). The
        #: binding is the proved part; the pinning below is conformance-held.
        self._home: Optional[Path] = Path(audit_path).parent if audit_path else None
        self.lock: Optional[Lockfile] = None
        self.lock_error: Optional[str] = None
        if self._home is not None:
            try:
                self.lock = Lockfile(self._home / "trustband.lock")
            except LockError as e:
                self.lock_error = str(e)
        policy = dict(policy)
        if self.lock is not None and self.lock.exists:
            policy["lock"] = {"digest": self.lock.digest}
        else:
            policy.pop("lock", None)
        self.policy = policy
        #: session -> item keys seen drifted; refused under enforce until accepted
        self._drifted: Dict[str, set] = {}
        #: bring-your-own detectors. Each may only lower a band, so a broken or
        #: hostile one over-refuses and never opens a bypass. Empty by default.
        self.detectors = detectors or []
        self._max_entries = provenance_max_entries
        #: A key file makes the epoch key shared between processes, which is
        #: what lets a swarm split across processes share one identity space.
        #: Without one the key is in-process and random per process, so an
        #: identity minted here verifies nowhere else -- true of every
        #: subprocess-per-call adapter, and the reason `from_file` defaults to
        #: a file beside the config.
        if gate is None:
            gate = Gate(budget=1 << 30,
                        keys=FileEpochKeys(key_path) if key_path else None)
        self.gate = gate
        self.issuer = Issuer(self.gate)
        try:
            adopted = self.issuer.adopt(policy)
        except Exception as e:
            # validate() raises PolicySchemaError, not GuardConfigError, so a
            # caller catching only the latter got a bare traceback -- and in a
            # hook that means a crash with no answer, which is worse than a
            # refusal. Every policy rejection leaves here as one error type.
            raise GuardConfigError(f"policy rejected: {e}") from None
        if not adopted:
            raise GuardConfigError(f"policy rejected: {adopted.reason}")
        self.ledger = ConfirmationLedger()
        #: session -> provenance. Never shared; see the module docstring.
        self._stores: Dict[str, ProvenanceStore] = {}
        self.shadow_log: list = []
        #: The durable decision record. None means nothing is written, which is
        #: what every install did before 2026-09-02 while three documents said
        #: otherwise. Adapters pass a path; the chain resumes from it, because a
        #: subprocess that exits after one decision cannot hold a chain in RAM.
        self.audit = AuditLog(Path(audit_path)) if audit_path else None
        #: Per-session call cap. `gov_budget` is the capability-MINTING budget
        #: from the proof model and is a different thing entirely; this counts
        #: tool calls, which is what a person means by "runaway".
        #: Applied to argument values on the way INTO the record, never at
        #: render: redacting in the viewer would leave the secret on disk while
        #: looking like protection.
        self.redactor = redactor if redactor is not None else Redactor()
        sess_cfg = policy.get("session") or {}
        self.max_calls: Optional[int] = sess_cfg.get("max_calls")
        #: Tokens, not spend. Tokens are what actually run out -- the context
        #: window is a hard wall -- and a token cap means something on a local
        #: model where spend does not. Reconciled from the host's transcript by
        #: `trustband report`, never derived through a rate table.
        self.max_tokens: Optional[int] = sess_cfg.get("max_tokens")
        #: Set by a caller that has reconciled usage. None means unknown, and
        #: an unknown budget never refuses: a cap that fires on a number we do
        #: not have is worse than no cap.
        self.tokens_used: Dict[str, int] = {}
        #: session -> (allowed actions, allowed destination values, trusted?)
        #: A plan is a per-TASK constraint, where an allowlist is per-deployment
        #: -- which is why it covers the open-ended agent an allowlist cannot.
        self._plans: Dict[str, Dict[str, Any]] = {}
        #: What a confirmable refusal means when nobody can answer it.
        #: `confirm.py` assumes a person exists; cron jobs, webhooks and CI
        #: have none, and they are disproportionately the paying customer.
        #: Default deny: a silent allow is the one outcome that must be
        #: impossible when the operator has not chosen.
        un = (policy.get("unattended") or {})
        self.on_confirmable: str = str(un.get("on_confirmable", "deny")).lower()
        if self.on_confirmable not in ("deny", "allow"):
            raise GuardConfigError(
                f"unattended.on_confirmable must be 'deny' or 'allow', not "
                f"{self.on_confirmable!r}. 'queue' needs hosted routing.")
        self.notify_cmd: Optional[str] = un.get("notify")
        #: Record what a tool RETURNED, not only that it returned something.
        #: Off by default because tool outputs are large and this is the log a
        #: user reads. Replay needs it: without it a replay answers from an
        #: empty provenance store, every taint refusal vanishes, and the
        #: candidate policy looks permissive and safe -- measured at 1/2
        #: reproduced before this existed.
        #: Rules about what came back. Validated at adoption like any policy
        #: error: a malformed contract is a bug, not a refusal.
        from trustband.contracts import validate as _cval
        try:
            _cval(policy.get("contracts"))
        except Exception as e:
            raise GuardConfigError(f"policy rejected: {e}") from None
        self.contracts: list = list(policy.get("contracts") or [])
        #: Blocking contract failures, for a CI caller to act on. Never used to
        #: refuse a tool call: the tool already ran.
        self.blocked_contracts: list = []
        rr = (policy.get("record_results") or {})
        self.record_results: bool = bool(rr.get("enabled", False))
        self.record_results_max: int = int(rr.get("max_chars", 4000))
        #: Counted from the record, not from memory. The adapter is a
        #: subprocess per call, so an in-memory counter counts to one forever.
        self._calls: Dict[str, int] = {}
        if self.audit is not None and self.max_calls:
            for e in self.audit.entries:
                b = e.body
                if b.get("event") == "decision" and b.get("allowed"):
                    k = b.get("session", "")
                    self._calls[k] = self._calls.get(k, 0) + 1
        #: True only if this policy came from a bundle that verified.
        self.verified_bundle: bool = False
        #: Phase 7. Identities are minted and checked against the SAME key
        #: store the gate uses, so custody is one property, not two. The
        #: revocation set lives beside the audit log when there is one, so a
        #: second process sees a revocation on its next call.
        self.agents = AgentRegistry(
            self.gate.keys, epoch_of=lambda: self.gate.gov_epoch,
            revocations_path=(Path(audit_path).parent / "revoked_agents.json"
                              if audit_path else None))
        #: Phase 8a. Free alerts: a webhook per event class, validated at
        #: adoption like any policy error, fired from the recorded entry,
        #: detached. See alerts.py for why each of those words is there.
        from trustband.alerts import Alerter, validate as _aval
        try:
            _urls = _aval(policy.get("alerts"))
        except Exception as e:
            raise GuardConfigError(f"policy rejected: {e}") from None
        self.alerts = Alerter(_urls, mode=mode,
                              home=Path(audit_path).parent if audit_path else None)
        # Whatever an earlier process spooled and did not live to deliver
        # goes out now, from the daemon thread, off the decision path.
        if _urls and self.alerts.home is not None:
            self.alerts._ensure_thread()
            self.alerts._wake.set()
        # A chain that was already broken when this process resumed it is an
        # event too -- the one class that can only be seen at load.
        if self.audit is not None and self.audit.entries:
            from trustband.audit import entry_digest as _ed
            _prev = None
            for _e in self.audit.entries:
                if _e.digest != _ed(_e.seq, _e.prev, _e.body) or \
                        (_prev is not None and _e.prev != _prev):
                    self.alerts.fire("chain_break", {"event": "chain_break",
                                                     "seq": _e.seq})
                    break
                _prev = _e.digest
        #: `identity.required`: a call carrying no identity is refused. Off by
        #: default, because every 0.2.x adapter sends none.
        self.identity_required: bool = bool(
            (policy.get("identity") or {}).get("required", False))

    # -- construction ------------------------------------------------------
    @classmethod
    def from_file(cls, config_path: Any) -> "Guard":
        """Load from the one config file an adapter points at."""
        p = Path(config_path)
        if not p.exists():
            raise GuardConfigError(f"no config at {p}")
        cfg = json.loads(p.read_text(encoding="utf-8"))
        pol_ref = cfg.get("policy")
        if pol_ref is None:
            raise GuardConfigError("config has no 'policy'")
        policy = (json.loads((p.parent / pol_ref).read_text(encoding="utf-8"))
                  if isinstance(pol_ref, str) else pol_ref)
        policy.pop("_inferred", None)
        detectors = _load_detectors(cfg.get("detectors", []))
        return cls(policy,
                   mode=cfg.get("mode", "shadow"),
                   provenance_max_entries=cfg.get("provenance_max_entries",
                                                  4096),
                   detectors=detectors,
                   # Beside the config, so every adapter loading a config gets
                   # the log without having to know to ask for it.
                   audit_path=cfg.get("audit_path", p.parent / "audit.jsonl"),
                   redactor=redact_from_config(cfg),
                   # Beside the config too. Opt out with "keys": "in_process".
                   key_path=(None if cfg.get("keys") == "in_process"
                             else cfg.get("key_path", p.parent / "keys.json")))

    @classmethod
    def from_bundle(cls, bundle_path: Any, key: Optional[bytes] = None,
                    *, mode: str = "shadow", min_version: Optional[int] = None,
                    **kw: Any) -> "Guard":
        """Load a policy from a signed bundle.

        With a key the bundle is verified -- digest, signature, and version
        floor -- and a failure raises rather than loading. With no key the
        policy loads and `verified_bundle` is False, so a caller is never left
        assuming a verification that did not happen.
        """
        from trustband.bundle import load_bundle_file
        policy, verified = load_bundle_file(bundle_path, key, min_version)
        g = cls(policy, mode=mode, **kw)
        g.verified_bundle = verified
        return g

    # -- the store, per session -------------------------------------------
    def _store(self, session: str) -> ProvenanceStore:
        if not session:
            raise GuardConfigError(
                "a session identity is required: provenance is scoped to it, "
                "and sharing one store across sessions lets one user's tool "
                "output taint another user's arguments")
        st = self._stores.get(session)
        if st is None:
            st = ProvenanceStore(max_entries=self._max_entries)
            self._stores[session] = st
        return st

    def set_plan(self, session: str, actions: Any = (),
                 destinations: Any = ()) -> bool:
        """Fix what this task may do, before it reads anything untrusted.

        WHY THE TIMING IS THE WHOLE MECHANISM
            Plan-then-execute is only a defence if the plan was authored before
            untrusted content could influence it. Everyone can assert that;
            almost nobody can CHECK it, because checking requires knowing
            whether tool output had already entered the session.

            Provenance knows. If this session's store already holds
            TOOL-banded content, the plan may itself be the injection, and a
            plan the attacker could have written is worse than none -- it looks
            like a control. So such a plan is recorded as UNTRUSTED and every
            later check against it refuses.

        Returns True if the plan is trusted, False if the session was already
        contaminated. The caller is told rather than silently given a plan that
        does nothing.
        """
        from trustband.provenance import TRUST_RANK
        store = self._stores.get(session)
        # "Contaminated" means anything at TOOL trust or below has been
        # remembered for this session. Higher rank is less trusted.
        contaminated = bool(store) and any(
            TRUST_RANK[b] >= TRUST_RANK[Band.TOOL]
            for b in store._entries.values())
        self._plans[session] = {
            "actions": {str(a) for a in actions},
            "destinations": {str(d) for d in destinations},
            "trusted": not contaminated,
        }
        return not contaminated

    # -- the lockfile ------------------------------------------------------
    def observe_catalog(self, session: str, kind: str, observed: list,
                        full: bool = False) -> list:
        """An adapter saw a catalog. Pin-check it; band it; record any drift.

        With no lockfile, nothing is refused and the observation is written
        to `lock_pending.json` for `trustband lock accept` -- pair 10. With
        one, every item that is new or changed is refused under enforce and
        flagged under shadow until a person accepts the diff, and each drift
        is one entry in the sealed log, redacted, alerted.
        """
        store = self._store(session)
        for o in observed:
            # A description is text the model reads as instruction. Remembered
            # TOOL, so an argument lifted from it is TOOL -- pair 4.
            desc = (o.get("summary") or {}).get("description") or ""
            if desc:
                store.remember(desc, Band.TOOL)
        if self._home is None:
            return []
        if self.lock is None or not self.lock.exists:
            _lock_write_pending(self._home, observed)
            return []
        drifts = self.lock.check(observed, kind=kind, full=full)
        if drifts:
            _lock_write_pending(self._home, observed)
        for d in drifts:
            if d["change"] != "removed":
                self._drifted.setdefault(session, set()).add(d["item"])
            if self.audit is not None:
                try:
                    self.audit.append({
                        "ts": time.time(), "session": session, "event": "lock_drift",
                        "item": d["item"], "change": d["change"], "kind": kind,
                        "from": d["from"], "to": d["to"],
                        "before": self.redactor.value("description",
                                                      json.dumps(d["before"])) if d["before"] else None,
                        "after": self.redactor.value("description",
                                                     json.dumps(d["after"])) if d["after"] else None,
                        "mode": self.mode,
                    })
                    self.alerts.consider(self.audit.entries[-1].body)
                except Exception:
                    pass
        return drifts

    def accept_lock(self) -> int:
        """Re-pin from the pending file. A PERSON calls this, after the diff.

        Goes through `Issuer.adopt`, so the evaluator and the gate move
        together -- pair 2 -- and every capability minted under the old
        manifest is dead at (G) from here.
        """
        if self._home is None:
            raise GuardConfigError("accept_lock needs a home (an audit_path)")
        pending = _lock_pending(self._home)
        if self.lock is None:
            self.lock = Lockfile(self._home / "trustband.lock")
        removed = [k for k in self.lock.items
                   if k not in pending and any(
                       d["item"] == k and d["change"] == "removed"
                       for d in self.lock.check(list(pending.values()), full=False))]
        self.lock.accept(list(pending.values()))
        self.lock_error = None
        try:
            (self._home / "lock_pending.json").unlink()
        except FileNotFoundError:
            pass
        self.policy["lock"] = {"digest": self.lock.digest}
        adopted = self.issuer.adopt(self.policy)
        if not adopted:
            raise GuardConfigError(f"policy rejected after lock accept: {adopted.reason}")
        self._drifted.clear()
        if self.audit is not None:
            try:
                self.audit.append({"ts": time.time(), "event": "lock_accept",
                                   "items": len(self.lock.items),
                                   "digest": self.lock.digest, "mode": self.mode})
            except Exception:
                pass
        return len(pending)

    def _check_lock(self, call: "ToolCall") -> Optional[str]:
        """A reason if this call is refused by the lockfile, else None."""
        if self.lock_error is not None:
            return (f"the lockfile is unreadable, so nothing can be told from "
                    f"drift: {self.lock_error}")
        drifted = self._drifted.get(call.session)
        if not drifted:
            return None
        if _lock_key("tool", call.tool) in drifted:
            return (f"{call.tool!r} changed since it was pinned; run "
                    f"`trustband lock diff`, then `trustband lock accept` if it is right")
        # an MCP server entry that changed: every tool it fronts is refused
        if call.tool.startswith("mcp__"):
            server = call.tool.split("__")[1] if call.tool.count("__") >= 2 else ""
            if server and _lock_key("server", server) in drifted:
                return (f"MCP server {server!r} changed since it was pinned; run "
                        f"`trustband lock diff`, then `trustband lock accept`")
        return None

    # -- identity ----------------------------------------------------------
    def mint_agent(self, name: str, role: str, session: str) -> AgentId:
        """A named agent for `session`, tagged under the current epoch key.
        Deterministic: the same (name, role, session) under the same key is
        the same tag, which is what lets a subprocess-per-call adapter re-mint
        rather than persist -- pair 7."""
        return self.agents.mint(name, role, session)

    def revoke_agent(self, agent: Any) -> None:
        """Refuse every later call by this agent. Structural, shared through
        the revocation file when there is one, and local to the name: no
        other agent is affected. Shape of conjunct (H).

        Given the `AgentId` rather than a name, the gate's own session epoch
        for its principal is bumped too, so a capability minted for it before
        the revocation dies at the gate's (H) as well -- not only at the
        identity check in front of it.
        """
        if isinstance(agent, AgentId):
            self.gate.revoke_session(agent.principal)
            self.agents.revoke(agent.name)
        else:
            self.agents.revoke(str(agent))

    def _check_identity(self, call: "ToolCall") -> Optional[Tuple[str, str]]:
        """(reason, conjunct) if the identity refuses, else None."""
        if call.agent is None:
            if self.identity_required:
                return ("this policy requires an agent identity and the call "
                        "carries none", "identity")
            return None
        ok, why, conj = self.agents.verify(call.agent)
        if not ok:
            return (why, conj or "identity")
        if call.agent.session != call.session:
            return (f"identity minted for session {call.agent.session!r} "
                    f"presented in session {call.session!r}", "C")
        return None

    def handoff(self, to_session: str, message: Any,
                from_session: Optional[str] = None,
                from_agent: Optional[AgentId] = None,
                to_agent: Optional[AgentId] = None) -> None:
        """Pass work from one agent to another without laundering the taint.

        THE HOLE THIS CLOSES, MEASURED
            Agent A reads a poisoned page, hands a verbatim payload to agent B,
            B acts. With A and B on one session the payload is caught. With
            separate sessions it is PERMITTED -- B's store is empty, so the
            argument is SESSION-banded and looks like something B's user typed.

            Provenance is scoped per session precisely so one user's tool
            output cannot taint another's, and that same scoping is what lets a
            handoff cross the boundary clean. Merging the sessions would fix it
            and destroy the property the scoping exists for.

        SO THE MESSAGE IS BANDED, NOT THE SESSIONS MERGED
            From B's point of view a handoff IS a tool result: text B did not
            author, arriving from elsewhere. Ingesting it as TOOL-banded closes
            the hole while A and B keep separate stores -- measured, and
            measured not to deny B's ordinary work.

        WHAT IT DOES NOT CLOSE
            Paraphrase. If A or B rewrites the payload in its own words it
            launders under every arrangement, shared or separate, banded or
            not. That is the authorship gap, not a boundary problem, and
            calling this method does not touch it.
        """
        if not to_session:
            raise GuardConfigError(
                "a handoff needs the receiving session's identity; without it "
                "the message cannot be banded into any store")
        # Names cross with the message; the store still does not. The record
        # on B's side says which agent the taint came from -- pair 8.
        self.after_tool_result(
            ToolCall(session=to_session, tool="handoff",
                     args={"from": from_session or "",
                           "from_agent": from_agent.name if from_agent else ""},
                     agent=to_agent),
            message, Band.TOOL)

    def _notify(self, call: "ToolCall", why: str, approved: bool) -> None:
        """Tell someone. Never ask them, and never let the answer matter.

        WHY AN ALERT MAY NOT TRIGGER AN APPROVAL
            `confirm.py` already states it: an escape hatch that lets anything
            through becomes the attacker's target. An alert that could
            auto-approve would be `allow` with extra machinery and a false
            sense of oversight -- worse than choosing `allow` honestly, because
            it adds a mechanism to aim at.

            So the exit code is ignored, the output is not read, and a hang or
            crash changes nothing. Same principle as an audit write failure: a
            decision does not depend on a side channel.

        WHAT IT SEES
            The redacted record, never raw argument values. F5 runs first.

        SHADOW DOES NOT NOTIFY. Nothing was refused there, and a notifier that
        fired on hypothetical refusals would train people to ignore it.
        """
        if not self.notify_cmd or self.mode != "enforce":
            return
        import subprocess
        payload = json.dumps({
            "session": call.session, "tool": call.tool,
            "reason": self.redactor.value("reason", why),
            "approved": approved,
            "args": self.redactor.args(
                {k: _plain(v) for k, v in call.args.items()}),
        })
        try:
            # FIRE AND FORGET, NOT "WAIT WITH A TIMEOUT".
            # A blocking call with a 5s timeout still stalled every refused
            # call by 5s when the notifier hung -- measured. The outcome was
            # unchanged and the agent was not: a notifier that can delay every
            # refusal is a denial-of-service surface wearing a helpful face.
            # Nothing is waited on, no output is read, and the exit code is
            # never seen, which is also what makes an alert unable to approve.
            proc = subprocess.Popen(
                self.notify_cmd, shell=True, stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            try:
                proc.stdin.write(payload)      # small; well under a pipe buffer
                proc.stdin.close()
            except Exception:
                pass
        except Exception:
            # A notifier that fails is a notifier that failed. It is not a
            # decision, and it is not this call's problem.
            pass

    def _record(self, call: "ToolCall", banded: Dict[str, Any], allowed: bool,
                why: str, confirmable: bool, ms: float) -> None:
        """One hash-chained entry per decision, in every mode.

        THE LOG IS THE PRODUCT, AND UNTIL NOW IT WAS NOT WRITTEN.
            `AuditLog` implemented the chain and nothing ever gave it a path,
            so the adapter -- a subprocess per tool call -- never reached a
            second entry while three documents claimed a tamper-evident log.

        WHAT GOES IN, AND WHY THIS SHAPE
            Everything the read paths need, because a field that is computed
            and not written is a feature that is dead in production while its
            tests pass. `trace`, `replay`, cost reporting and OTel export all
            read this record and nothing else.

            Argument VALUES are recorded, since a trace that cannot show what
            was refused explains nothing -- and they are the reason redaction
            is a gate on this record rather than an afterthought.

        A WRITE FAILURE NEVER CHANGES A DECISION. `AuditLog.append` records
        the error and returns; the caller does not branch on it.
        """
        if self.audit is None:
            return
        try:
            self.audit.append({
                "ts": time.time(),
                "session": call.session,
                "tool": call.tool,
                "event": "decision",
                "tier": call.tier,
                "allowed": bool(allowed),
                "mode": self.mode,
                # THE REASON QUOTES VALUES, AND F5 ONLY REDACTED ARGS.
                # `predicate: token 'sk-proj-…' is not in the allowlist` put a
                # credential in the log with args already redacted beside it,
                # and would have shipped it to a third-party collector. F5
                # passed its gates because they tested argument values and
                # never the sentence describing them.
                "reason": self.redactor.value("reason", why),
                "confirmable": bool(confirmable),
                # WHICH rule decided, not only what it said. Replay groups by
                # rule; prose is a message, not an identity. None means no
                # grant matched at all, which is different from grant 0.
                "grant": getattr(self.issuer, "deciding_grant", None),
                # WHO. Read by trace, so a swarm's record names the agent
                # rather than a session -- P-P7.1 asserts this from the file.
                "agent": call.agent.name if call.agent else None,
                "agent_role": call.agent.role if call.agent else None,
                "bands": {k: _band_of(v).value for k, v in banded.items()},
                # P-F5.3: on the way in. The gate above already decided on
                # the real values; only the record is redacted.
                "args": self.redactor.args(
                    {k: _plain(v) for k, v in call.args.items()}),
                "ms": round(ms, 4),
            })
            # FROM THE RECORD. The alert reads the entry just written; if it
            # is not in the log it is not alerted -- pair 5.
            self.alerts.consider(self.audit.entries[-1].body)
        except Exception:
            # Belt and braces. Nothing about auditing may reach the decision.
            pass

    # -- hook 1: authorize -------------------------------------------------
    def before_tool_call(self, call: ToolCall) -> Decision:
        t0 = time.perf_counter()
        store = self._store(call.session)
        banded = {k: self._band(v, store) for k, v in call.args.items()}
        sess = _session_int(call.session)

        # IDENTITY FIRST. A forged, stale, revoked or wrong-session identity
        # refuses before any rule is consulted, so no policy can be argued
        # with by an agent that is not who it says. Obeys shadow like every
        # other check here -- pair 9.
        ident = self._check_identity(call)
        if ident is not None:
            why, conj = ident
            self._record(call, banded, False, why, False,
                         (time.perf_counter() - t0) * 1000.0)
            if self.mode == "shadow":
                self.shadow_log.append(
                    {"session": call.session, "tool": call.tool,
                     "agent": call.agent.name if call.agent else None,
                     "would_allow": False, "reason": why,
                     "confirmable": False,
                     "bands": {k: _band_of(v).value for k, v in banded.items()}})
                return Decision(True, f"SHADOW: would have refused — {why}",
                                None, False, None)
            return Decision(False, why, conj, False, None)

        why_lock = self._check_lock(call)
        if why_lock is not None:
            self._record(call, banded, False, why_lock, False,
                         (time.perf_counter() - t0) * 1000.0)
            if self.mode == "shadow":
                self.shadow_log.append(
                    {"session": call.session, "tool": call.tool,
                     "agent": call.agent.name if call.agent else None,
                     "would_allow": False, "reason": why_lock, "confirmable": False,
                     "bands": {k: _band_of(v).value for k, v in banded.items()}})
                return Decision(True, f"SHADOW: would have refused — {why_lock}",
                                None, False, None)
            return Decision(False, why_lock, "lock", False, None)

        plan = self._plans.get(call.session)
        if plan is not None:
            why = None
            if not plan["trusted"]:
                why = ("the plan for this session was fixed after tool output "
                       "had already been read, so it may itself be injected "
                       "and is not trusted. Fix the plan before the first read.")
            elif plan["actions"] and call.tool not in plan["actions"]:
                why = (f"{call.tool!r} is not in this task's plan "
                       f"({len(plan['actions'])} action(s) planned)")
            elif plan["destinations"]:
                vals = {str(_plain(v)) for v in call.args.values()}
                unplanned = [v for v in vals
                             if v and not any(d in v for d in plan["destinations"])]
                if unplanned and len(unplanned) == len(vals):
                    why = (f"no argument of this call matches a planned "
                           f"destination ({len(plan['destinations'])} planned)")
            if why:
                self._record(call, banded, False, why, False,
                             (time.perf_counter() - t0) * 1000.0)
                if self.mode == "shadow":
                    self.shadow_log.append(
                        {"session": call.session, "tool": call.tool,
                         "would_allow": False, "reason": why,
                         "confirmable": False,
                         "bands": {k: _band_of(v).value
                                   for k, v in banded.items()}})
                    return Decision(True, f"SHADOW: would have refused — {why}",
                                    None, False, None)
                return Decision(False, why, "plan", False, None)

        tok = self.tokens_used.get(call.session)
        if self.max_tokens is not None and tok is not None and tok >= self.max_tokens:
            why = (f"session token cap reached: {tok:,}/{self.max_tokens:,} "
                   f"tokens. Raise session.max_tokens or start a new session.")
            self._record(call, banded, False, why, False,
                         (time.perf_counter() - t0) * 1000.0)
            if self.mode == "shadow":
                self.shadow_log.append(
                    {"session": call.session, "tool": call.tool,
                     "would_allow": False, "reason": why, "confirmable": False,
                     "bands": {k: _band_of(v).value for k, v in banded.items()}})
                return Decision(True, f"SHADOW: would have refused — {why}",
                                None, False, None)
            return Decision(False, why, "cap", False, None)

        used = self._calls.get(call.session, 0)
        if self.max_calls is not None and used >= self.max_calls:
            # A CAP IS NOT A PROVENANCE REFUSAL, and must not read like one.
            # Every other refusal here is a claim about where a value came
            # from, which a user has to be persuaded of. This is a limit they
            # set themselves, so the reason names the cap and the count and
            # nothing else.
            why = (f"session call cap reached: {used}/{self.max_calls} calls. "
                   f"Raise session.max_calls or start a new session.")
            self._record(call, banded, False, why, False,
                         (time.perf_counter() - t0) * 1000.0)
            # SHADOW REFUSES NOTHING -- INCLUDING THIS.
            # The cap is the first refusal a new user is likely to meet, which
            # makes it the most tempting one to let through the shadow gate
            # "because they asked for it". They did not: they asked for a
            # limit once enforcement is on. A shadow install that blocks is
            # not shadow, and it breaks the one promise that gets this tool
            # kept -- it starts by refusing nothing.
            if self.mode == "shadow":
                self.shadow_log.append(
                    {"session": call.session, "tool": call.tool,
                     "would_allow": False, "reason": why,
                     "confirmable": False,
                     "bands": {k: _band_of(v).value for k, v in banded.items()}})
                return Decision(True, f"SHADOW: would have refused — {why}",
                                None, False, None)
            return Decision(False, why, "cap", False, None)

        ok, why = self.issuer.evaluate(sess, call.tier, call.tool, banded,
                                       dict(call.context))
        failures = getattr(self.issuer, "confirmable_failures", [])
        confirmable = ConfirmationLedger.is_confirmable(failures)
        if ok:
            self._calls[call.session] = used + 1
        self._record(call, banded, ok, why, confirmable,
                     (time.perf_counter() - t0) * 1000.0)

        if self.mode == "shadow":
            # Records what it WOULD have done and permits everything. A
            # deployment left here is unguarded, which is why the decision is
            # logged with that word in it.
            self.shadow_log.append(
                {"session": call.session, "tool": call.tool,
                 "agent": call.agent.name if call.agent else None,
                 "would_allow": ok, "reason": why,
                 # Whether a person could have approved this refusal. Computed
                 # above and, until 2026-09-01, thrown away here -- so every
                 # consumer of the shadow log saw an install where no refusal
                 # was ever confirmable. Same shape as the P-HARD5/6 defect:
                 # the field the feature keys on was never written down, and
                 # unit tests passed because they supplied it themselves.
                 "confirmable": bool(confirmable),
                 "bands": {k: _band_of(v).value for k, v in banded.items()}})
            return Decision(True, f"SHADOW: would have {'allowed' if ok else 'refused'} — {why}",
                            None, confirmable, None)

        if ok:
            return Decision(True, why)

        if confirmable and self.on_confirmable == "allow":
            # RECORDED AS "NOBODY APPROVED", NEVER AS AN APPROVAL.
            # Writing this as a confirmation would forge one, which is the
            # worst thing this module could do. The operator chose to let
            # unanswerable refusals through; the record says exactly that.
            why_un = (f"unattended policy allowed this without approval — "
                      f"nobody was asked. Original refusal: {why}")
            self._record(call, banded, True, why_un, True,
                         (time.perf_counter() - t0) * 1000.0)
            self._notify(call, why_un, approved=False)
            return Decision(True, why_un, None, True, None)

        request = None
        if confirmable:
            arg = next((f.get("arg") for f in failures
                        if f.get("arg") in call.args), None)
            if arg is not None:
                request = self.ledger.ask(
                    session=sess, action=call.tool, arg=arg,
                    value=_plain(call.args[arg]), reason=why,
                    arg_bands={k: _band_of(v).value for k, v in banded.items()},
                    epoch=self.gate.gov_epoch)
        if confirmable:
            self._notify(call, why, approved=False)
        return Decision(False, why, "policy", confirmable, request)

    # -- ingestion: extract a document into banded, source-verified values --
    def ingest_document(self, session: str, source: str, schema: list,
                        client: Any = None, model: str = "") -> dict:
        """Extract fields from an untrusted document, each verified to be a
        literal substring of it and banded TOOL, and remember them.

        This is the STRONGEST ingestion boundary: instead of trusting the model
        to carry provenance, a value is admitted only if it is found in the
        source, so a fabricated or injected value has no span and never enters.
        Every admitted value is remembered in the session store, so a later
        argument equal to it is recognised as document-derived.

        Returns {field: value}. Requires an OpenAI-compatible client and model;
        without one it raises, because there is no safe way to extract without
        actually reading the document.
        """
        if client is None or not model:
            raise GuardConfigError(
                "ingest_document needs an extractor client and model")
        from trustband.extractor import extract_verified
        store = self._store(session)
        values, missing, _ = extract_verified(client, model, source, schema,
                                               band=Band.TOOL)
        out = {}
        for name, tainted in values.items():
            store.remember(tainted.value, Band.TOOL)
            out[name] = tainted.value
        return out

    # -- hook 2: provenance ------------------------------------------------
    def after_tool_result(self, call: ToolCall, result: Any,
                          band: Band = Band.TOOL) -> None:
        """Remember what this tool returned, so a later argument built from it
        is not mistaken for something the user said.

        Must be called for EVERY result, including errors and results the agent
        discards. A missed call is a hole in provenance: the value is later
        treated as model-authored, which is the laundering case.
        """
        store = self._store(call.session)
        n = 0
        for text in _strings(result):
            store.remember(text, band)
            n += 1
        # The other half of the record. Without it the log has calls and no
        # results, so a trace cannot say what a tool returned and a replay
        # cannot rebuild the provenance the next decision depended on -- it
        # would answer confidently from a store it never populated.
        # CONTRACTS RUN HERE, ON THE RESULT, AFTER THE TOOL RAN.
        # They cannot refuse the call -- it already happened -- and they must
        # not touch provenance or a later authorization. What they produce is
        # a verdict in the same record, which is the whole reason this lives
        # here rather than in a second policy engine beside it.
        contract_results = []
        if self.contracts:
            from trustband.contracts import evaluate as _ceval
            try:
                contract_results = _ceval(self.contracts, call.tool,
                                          _plain(result))
            except Exception:
                contract_results = []
            for cr in contract_results:
                if not cr["held"] and cr["blocking"] and self.mode == "enforce":
                    self.blocked_contracts.append(cr)

        if self.audit is not None:
            try:
                self.audit.append({
                    "ts": time.time(),
                    "session": call.session,
                    "tool": call.tool,
                    "event": "result",
                    "contracts": contract_results or None,
                    "band": band.value,
                    "strings_remembered": n,
                    "text": (self.redactor.value("result", _plain(result))
                             [:self.record_results_max]
                             if self.record_results and isinstance(_plain(result), str)
                             else (json.dumps(_plain(result))[:self.record_results_max]
                                   if self.record_results else None)),
                    # Who this came from, when it came from another agent. The
                    # name crosses; the store does not — B's record says the
                    # taint originated with A without giving B access to A.
                    "from": str(call.args.get("from") or "") or None,
                    "from_agent": str(call.args.get("from_agent") or "") or None,
                    "agent": call.agent.name if call.agent else None,
                })
                self.alerts.consider(self.audit.entries[-1].body)
            except Exception:
                pass

    # -- helpers -----------------------------------------------------------
    def _band(self, value: Any, store: ProvenanceStore) -> Any:
        if isinstance(value, Tainted):
            return value
        if isinstance(value, str):
            band = store.recall(value) or Band.SESSION
            # A detector may LOWER the band -- catch a laundered value that
            # provenance trusted -- never raise it. run_detectors clamps, so a
            # broken or hostile plugin only over-refuses.
            if self.detectors:
                from trustband.detector import run_detectors
                band = run_detectors(self.detectors, value, band)
            return Tainted(value, band)
        if isinstance(value, (int, float, bool)) or value is None:
            return Tainted(value, Band.SESSION)
        return value


def _load_detectors(specs: list) -> list:
    """Load detectors named in config, defensively.

    "trustband.detector:MarkerDetector" or a builtin shorthand "marker". A
    name that will not import is skipped with no failure: a missing detector
    should not stop the gate, because a detector can only ever have made the
    gate stricter, so its absence is the safe direction.
    """
    out = []
    for spec in specs or []:
        try:
            if spec == "marker":
                from trustband.detector import MarkerDetector
                out.append(MarkerDetector())
                continue
            mod, _, cls = spec.partition(":")
            import importlib
            obj = getattr(importlib.import_module(mod), cls)
            out.append(obj() if isinstance(obj, type) else obj)
        except Exception:
            continue
    return out


def _plain(v: Any) -> Any:
    while isinstance(v, Tainted):
        v = v.value
    return v


def _band_of(v: Any) -> Band:
    return v.band if isinstance(v, Tainted) else Band.GOVERNANCE


def _session_int(session: str) -> int:
    """The gate's sessions are integers; a host's are strings.

    Stable and collision-resistant enough that two conversations do not share
    a capability. Provenance is keyed by the ORIGINAL string, so a collision
    here cannot merge two sessions' stores.
    """
    if isinstance(session, int):
        return session
    # sha256, not the raw bytes. Padding a short string to eight bytes puts the
    # zeros in the LOW bits, and the modulo keeps only those -- so "s1", "s2",
    # "a" and "b" all mapped to 0 and would have shared gate sessions and
    # capabilities. Provenance was unaffected, because its store is keyed by
    # the original string, which is why a conformance check on cross-session
    # leakage passed while policy identity was collapsing.
    digest = hashlib.sha256(session.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % (2 ** 31)


def _strings(value: Any, depth: int = 0):
    """Every string reachable in a tool result, containers included.

    A list of emails banded only at the top is useless: the agent reads
    `emails[0].body`, gets a bare string, and the provenance is gone before it
    reaches an argument.
    """
    if depth > 12:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v, depth + 1)
    elif hasattr(value, "model_dump"):          # pydantic, as AgentDojo uses
        try:
            yield from _strings(value.model_dump(), depth + 1)
        except Exception:
            yield str(value)
    elif value is not None and not isinstance(value, (int, float, bool)):
        yield str(value)
