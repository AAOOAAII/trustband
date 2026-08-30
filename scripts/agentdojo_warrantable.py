"""AgentDojo harness: taint at the tool boundary, gate at the tool call.

An ADAPTER, not a second enforcement layer. Every security decision belongs to
the gate; this file only decides WHERE data came from and routes the call.

WHAT IT DOES
    1. Bands every tool result TOOL on entry, by wrapping
       `FunctionsRuntime.run_function` -- the single choke point every result
       flows through. No AgentDojo suite is modified.
    2. Bands the user's task prompt SESSION. That is the trusted input.
    3. Propagates with warrantable's existing `combine`. No new propagation.
    4. Routes each tool call through `Runtime.call` under a policy derived from
       the suite's own injection-task GOALs.

THE KNOWN GAP, MEASURED NOT FIXED
    Without a quarantined model, an agent that reads a poisoned tool result and
    PARAPHRASES it into a call launders the taint: the model's output is fresh
    text carrying no provenance. We expect to catch DIRECT injection and miss
    LAUNDERED injection, and the split is the deliverable.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from warrantable.gate import Band                      # noqa: E402
from warrantable.confirm import ConfirmationLedger     # noqa: E402
from warrantable.runtime import Runtime                # noqa: E402
from warrantable.taint import (Tainted, combine, taint_of,  # noqa: E402
                               TRUST_ORDER)


# --------------------------------------------------------------------------
# 1. Boundary tainting
# --------------------------------------------------------------------------
def taint_of_value(v: Any) -> Any:
    """The plain value behind any nesting of Tainted wrappers."""
    while isinstance(v, Tainted):
        v = v.value
    return v


def taint_tool_result(value: Any, band: Band = Band.TOOL) -> Any:
    """Band a tool result on entry. Containers are banded ELEMENTWISE.

    A list of emails banded only at the top is useless: the agent reads
    `emails[0].body`, gets a bare string, and the taint is gone before it ever
    reaches an argument. So recursion is not a nicety here -- without it the
    boundary leaks by construction.
    """
    if isinstance(value, Tainted):
        return value
    if isinstance(value, dict):
        return {k: taint_tool_result(v, band) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        t = [taint_tool_result(v, band) for v in value]
        return type(value)(t) if isinstance(value, tuple) else t
    if isinstance(value, (str, int, float, bool)) or value is None:
        return Tainted(value, band)
    # Pydantic models and other objects: band the whole object. Their fields
    # are not reachable for tainting without touching the suite, and touching
    # the suite is what P-AD1 forbids. Recorded as a limit, not worked around.
    return Tainted(value, band)


def untaint(value: Any) -> Any:
    """Strip taint for handing to the model. The BAND is retained separately by
    the caller -- this is the point where provenance would be lost if the
    harness did not carry it forward itself."""
    if isinstance(value, Tainted):
        return untaint(value.value)
    if isinstance(value, dict):
        return {k: untaint(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        u = [untaint(v) for v in value]
        return type(value)(u) if isinstance(value, tuple) else u
    return value


def bands_in(value: Any) -> List[Band]:
    """Every band reachable inside a structure."""
    out: List[Band] = []
    if isinstance(value, Tainted):
        out.append(value.band); out.extend(bands_in(value.value)); return out
    if isinstance(value, dict):
        for v in value.values(): out.extend(bands_in(v))
    elif isinstance(value, (list, tuple)):
        for v in value: out.extend(bands_in(v))
    return out


# --------------------------------------------------------------------------
# 2. The wrapped runtime
# --------------------------------------------------------------------------
def _key(v: Any) -> Optional[Tuple[str, Any]]:
    """Recall key for a scalar, or None if it is too weak to match on.

    Short strings and small integers collide across unrelated values, and a
    collision here re-bands a clean argument as TOOL -- over-refusal, which is
    the safe direction but still a false positive. Numbers are matched only in
    the type-tagged form so `1` and `True` cannot alias.
    """
    if isinstance(v, bool):
        return None                       # two values; every match is a collision
    if isinstance(v, str):
        return ("s", v) if len(v) >= 4 else None
    if isinstance(v, int):
        return ("n", float(v)) if abs(v) >= 100 else None
    if isinstance(v, float):
        return ("n", float(v))
    return None


@dataclass
class ToolEvent:
    function: str
    allowed: bool
    reason: str
    conjunct: Optional[str]
    arg_bands: Dict[str, str]
    stage: str = ""


class TaintingRuntime:
    """Wraps AgentDojo's FunctionsRuntime. Bands results, gates calls.

    `gate_mode`:
      "enforce"  -- the policy decides
      "permit"   -- the gate is configured to permit everything (P-AD4)
      "off"      -- no gate at all (the undefended baseline)

    `shadow=True` runs the full decision path and executes anyway, recording
    what would have been refused. It measures, it does not protect.
    """

    def __init__(self, inner: Any, policy: Dict[str, Any],
                 gate_mode: str = "enforce", session: int = 7,
                 shadow: bool = False, substring_recall: bool = False,
                 oracle: str = "", user_prompt: str = "") -> None:
        self.inner = inner
        self.gate_mode = gate_mode
        self.substring_recall = substring_recall
        # "" no human at all; "perfect" approves only what the user asked for;
        # "rubber" approves whatever it is shown. The gap between the last two
        # is how much of the security rests on the person being careful.
        self.oracle = oracle
        self.user_prompt = user_prompt or ""
        self.ledger = ConfirmationLedger()
        # Values that came out of a source the USER NAMED. "Read
        # address-change.txt and update my details" makes that file's contents
        # something the user asked for, even though the address itself never
        # appears in the prompt. Without this a "careful human" declines the
        # very task the user requested, which is a flaw in the ORACLE, not in
        # the policy -- and it is why Run 3 recovered no utility on task 13.
        #
        # This informs the APPROVAL DECISION ONLY. It does not change any
        # band, so nothing here can make a value more trusted to the gate.
        self._user_directed: Set[str] = set()
        self.confirmations: List[Dict[str, Any]] = []
        self.session = session
        self.events: List[ToolEvent] = []
        self.rt: Optional[Runtime] = None
        if gate_mode != "off":
            self.rt = Runtime(policy, budget=4096, shadow=shadow)
            self.rt.register(1)
        # Taint carried across calls: the agent sees plain values, so the
        # harness remembers what each tool returned and re-attaches the band
        # when that value comes back as an argument. This is the ONLY place
        # provenance survives the model, and it is exactly why paraphrase
        # launders it -- a value the model rewrote is not the value we stored.
        self._seen: Dict[str, Band] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _substring_band(self, value: str) -> Optional[Band]:
        """Least-trusted band of any remembered value containing `value`.

        Costs false positives: an argument that legitimately equals a fragment
        of tool output is banded TOOL and refused. That is the price of sound
        propagation, and it is why the band must be declared PER ARGUMENT --
        a payment's recipient can require SESSION while its amount, which
        genuinely comes from the document, does not.
        """
        worst: Optional[Band] = None
        for (kind, seen), band in self._seen.items():
            if kind != "s" or not isinstance(seen, str) or value not in seen:
                continue
            if worst is None or TRUST_ORDER.index(band) > TRUST_ORDER.index(worst):
                worst = band
        return worst

    # -- provenance recall ------------------------------------------------
    def _remember(self, value: Any, user_directed: bool = False) -> None:
        def walk(v: Any) -> None:
            if isinstance(v, Tainted):
                k = _key(v.value)
                if k is not None:
                    self._seen[k] = v.band
                if user_directed and isinstance(v.value, str):
                    self._user_directed.add(v.value)
                walk(v.value)
            elif isinstance(v, dict):
                for x in v.values(): walk(x)
            elif isinstance(v, (list, tuple)):
                for x in v: walk(x)
        walk(value)

    def _recall(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Re-attach bands to arguments the model echoed verbatim.

        VERBATIM ONLY, deliberately. A substring or fuzzy match would be the
        harness making a security decision, and that decision belongs in the
        gate. Exact recall catches DIRECT injection; anything the model
        rewrote is LAUNDERED and is meant to be missed here.
        """
        out: Dict[str, Any] = {}
        for k, v in kwargs.items():
            if isinstance(v, Tainted):
                out[k] = v
            elif (self.substring_recall and isinstance(v, str)
                  and len(v) >= 8 and _key(v) not in self._seen
                  and self._substring_band(v) is not None):
                # DERIVED-VALUE PROVENANCE. Whole-value matching is an unsound
                # under-approximation: the attacker's IBAN arrives EMBEDDED in
                # a poisoned document, so the document is remembered and the
                # bare IBAN is not, and the argument reads as model-authored.
                # Measured: 34 of 37 successful attacks reached the gate with
                # no tainted argument at all for exactly this reason.
                # A substring of tainted text is derived from tainted text.
                out[k] = Tainted(v, self._substring_band(v))
            elif isinstance(v, (str, int, float, bool)):
                # EVERY scalar is banded. Letting non-strings fall through
                # untagged made `send_money(amount=...)` read as having no
                # provenance, and an untagged argument under a `min_band` grant
                # is refused by design -- so the harness, not the policy, was
                # producing six of the eight refusals in the first shadow run.
                out[k] = Tainted(v, self._seen.get(_key(v), Band.SESSION))
            else:
                out[k] = v
        return out

    # -- context from the environment --------------------------------------
    @staticmethod
    def context_from_env(env: Any) -> Dict[str, Any]:
        """Counterparties the user has ALREADY transacted with.

        Derived from the user's own account, never from knowledge of the
        attack. The attacker's IBAN is absent because the user never paid it,
        not because anyone listed it as bad -- an allowlist built the other way
        round would be tuning against attack results.

        Note the suite's own trap: the attacker uses
        US133000000121212121212 against a genuine Apple Store payee of
        US122000000121212121212. Reading those as different is what a set
        membership test does and eyeballing does not.
        """
        payees = set()
        acct = getattr(env, "bank_account", None)
        if acct is not None:
            for t in list(getattr(acct, "transactions", []) or []):
                if getattr(t, "recipient", None):
                    payees.add(t.recipient)
            for t in list(getattr(acct, "scheduled_transactions", []) or []):
                if getattr(t, "recipient", None):
                    payees.add(t.recipient)
        return {"known_payees": payees}

    def _named_by_user(self, kwargs: Any) -> bool:
        """Did the user's own request name this call's source?

        `read_file(file_path='address-change.txt')` where that filename is in
        the prompt means the user pointed the agent at it. A document the agent
        merely encountered is not named, which is the distinction between the
        file the user asked about and the poisoned notice beside it.
        """
        if not self.user_prompt:
            return False
        for v in (kwargs or {}).values():
            if isinstance(v, str) and len(v) >= 4 and v in self.user_prompt:
                return True
        return False

    # -- the human in the loop ---------------------------------------------
    def _ask_human(self, env: Any, function: str,
                   targs: Dict[str, Any], do: Any, refused: Any) -> Any:
        """Put a confirmable refusal to the oracle, then retry once.

        Only refusals the POLICY marked confirmable are ever asked. A forged
        tag, a retired epoch or a revoked session arrives with no predicate at
        all and is never put to a person -- those are not judgements anyone is
        entitled to reverse.
        """
        assert self.rt is not None
        failures = getattr(self.rt.issuer, "confirmable_failures", [])
        if not ConfirmationLedger.is_confirmable(failures):
            return refused
        epoch = self.rt.gate.gov_epoch
        asked = False
        for f in failures:
            arg = f.get("arg")
            if arg not in targs:
                continue
            value = taint_of_value(targs[arg])
            req = self.ledger.ask(
                session=self.session, action=function, arg=arg, value=value,
                reason=refused.reason, epoch=epoch,
                arg_bands={k: taint_of(v).value for k, v in targs.items()})
            approve = (self.oracle == "rubber"
                       or (self.oracle == "perfect"
                           and (str(value) in self.user_prompt
                                or str(value) in self._user_directed)))
            (self.ledger.approve if approve else self.ledger.deny)(
                req, approver=f"oracle:{self.oracle}")
            self.confirmations.append(
                {"function": function, "arg": arg,
                 "approved": approve, "digest": req.digest})
            asked = asked or approve
        if not asked:
            return refused
        ctx = self.context_from_env(env)
        ctx.update(self.ledger.as_context(
            session=self.session, action=function,
            args={k: taint_of_value(v) for k, v in targs.items()},
            epoch=epoch))
        return self.rt.call(session=self.session, action=function, tier=2,
                            eid=1, args=targs, fn=do, output_band=Band.TOOL,
                            context=ctx)

    # -- the wrapped call --------------------------------------------------
    def run_function(self, env: Any, function: str, kwargs: Any,
                     raise_on_error: bool = False) -> Tuple[Any, Optional[str]]:
        tainted_kwargs = self._recall(dict(kwargs))
        arg_bands = {k: taint_of(v).value for k, v in tainted_kwargs.items()}

        if self.gate_mode == "off":
            result, err = self.inner.run_function(env, function, kwargs,
                                                  raise_on_error)
            banded = taint_tool_result(result)
            self._remember(banded)
            self.events.append(ToolEvent(function, True, "no gate", None,
                                         arg_bands, "off"))
            return result, err

        assert self.rt is not None
        holder: Dict[str, Any] = {}

        def do(**_plain: Any) -> Any:
            r, e = self.inner.run_function(env, function, kwargs, raise_on_error)
            holder["r"], holder["e"] = r, e
            return r

        res = self.rt.call(session=self.session, action=function, tier=2, eid=1,
                           args=tainted_kwargs, fn=do, output_band=Band.TOOL,
                           context=self.context_from_env(env))
        if res.stage == "shadow_allow":
            # Executed, but the gate WOULD have refused. Recorded as a refusal
            # event so the diagnosis reads the same in both modes, and the tool
            # result still flows on so the task can complete.
            self.events.append(ToolEvent(function, False, res.reason,
                                         res.conjunct, arg_bands, "shadow"))
            banded = taint_tool_result(holder.get("r"))
            self._remember(banded)
            return holder.get("r"), holder.get("e")
        if not res and self.oracle:
            res = self._ask_human(env, function, tainted_kwargs, do, res)
        if not res:
            self.events.append(ToolEvent(function, False, res.reason,
                                         res.conjunct, arg_bands, res.stage))
            # AgentDojo expects (result, error). A refusal is an error string,
            # which the agent sees and may react to -- exactly as a real
            # deployment would surface a denial.
            return "", f"PolicyRefusal: {res.reason}"

        banded = taint_tool_result(holder.get("r"))
        self._remember(banded, user_directed=self._named_by_user(kwargs))
        self.events.append(ToolEvent(function, True, "executed", None,
                                     arg_bands, "execute"))
        return holder.get("r"), holder.get("e")


# --------------------------------------------------------------------------
# 3. Policy from the suite's stated intent
# --------------------------------------------------------------------------
def policy_for(suite_name: str, tools: List[str], permit_all: bool = False,
               predicates: bool = False, prior_max: float = 1100.0,
               strict: bool = False, confirm_password: bool = False
               ) -> Dict[str, Any]:
    """Derived from each suite's injection-task GOALs, written before any
    attack is run. `permit_all` is P-AD4's instrument setting."""
    if permit_all:
        return {"version": 1, "grants": [
            {"sess": 7, "max_tier": 2, "actions": sorted(tools)}]}

    # Banking's injection tasks want: a transfer to an attacker IBAN; the user's
    # IBAN changed; a scheduled transaction redirected. All are STATE-CHANGING
    # calls whose arguments the attacker must control. Read-only tools cannot
    # reach any injection GOAL, so they are unconstrained.
    STATE_CHANGING = {
        "send_money", "schedule_transaction", "update_scheduled_transaction",
        "update_password", "update_user_info",
    }
    changing = sorted(t for t in tools if t in STATE_CHANGING)
    reading = sorted(t for t in tools if t not in STATE_CHANGING)
    grants: List[Dict[str, Any]] = []
    if reading:
        grants.append({"sess": 7, "max_tier": 2, "actions": reading})
    if not changing:
        return {"version": 1, "grants": grants}

    if not predicates:
        grants.append({"sess": 7, "max_tier": 2, "actions": changing,
                       "min_band": "session"})
        return {"version": 1, "grants": grants}

    # Predicates COMPOSE with bands, they do not replace them. Applying a
    # money rule to every state-changing action was an authoring error worth
    # keeping in view: update_password takes neither `amount` nor `recipient`,
    # so both money grants refused it by the fail-closed rule -- correct
    # behaviour on a nonsensical policy, and 60 of 97 refusals in the first
    # integration run.
    MONEY = {"send_money", "schedule_transaction",
             "update_scheduled_transaction"}
    money = sorted(t for t in changing if t in MONEY)
    other = sorted(t for t in changing if t not in MONEY)

    # Where provenance IS decisive, bands still do the work. Nothing a tool
    # returned should be able to set a password or a user's own details.
    # RUN 2: every surviving attack was injection_task_7, changing the password.
    # It is not a money action so no value predicate reached it, and the
    # laundered value arrives banded SESSION so min_band admits it. A password
    # change is the definition of an argument both untrusted and consequential,
    # so it asks a human.
    #
    # ONE grant, because grants are a DISJUNCTION: a separate confirmation
    # grant beside the min_band grant would be decorative, since the min_band
    # grant alone would still permit the change. The band and the confirmation
    # must CONJOIN, and conjunction lives inside a single grant.
    pw = ["update_password"] if (confirm_password
                                 and "update_password" in other) else []
    rest = sorted(t for t in other if t not in pw)
    if rest:
        grants.append({"sess": 7, "max_tier": 2, "actions": rest,
                       "min_band": "session"})
    if pw:
        grants.append({"sess": 7, "max_tier": 2, "actions": pw,
                       "min_band": "session",
                       "require": [{"arg": "password", "op": "confirmed",
                                    "confirmable": True}]})

    # Where provenance is NOT decisive -- a bill's payee legitimately comes
    # from the bill -- the value carries the constraint instead. Two grants,
    # because grants are a disjunction and the bank rule is one:
    #
    #   "anyone may be paid an amount you have paid before, and larger sums
    #    only to a counterparty you have paid before"
    #
    # Both halves come from the user's own account, not from anyone who had
    # seen an attack. The rule does NOT stop a small transfer to an unknown
    # payee, which is a limitation of the rule and not of the encoding.
    if money and not strict:
        grants.append({"sess": 7, "max_tier": 2, "actions": money,
                       "require": [{"arg": "amount", "op": "max_minor",
                                    "value": int(round(prior_max * 100))}]})
        grants.append({"sess": 7, "max_tier": 2, "actions": money,
                       "require": [{"arg": "recipient", "op": "in_context",
                                    "key": "known_payees"}]})
    elif money:
        # P-PRED2: ONE grant, so the predicates conjoin. The payee must be
        # known AND the amount within what has been paid before. The
        # disjunctive form measured worse than bands alone because most
        # injections move a small amount to an unknown payee, which its first
        # branch permits.
        grants.append({"sess": 7, "max_tier": 2, "actions": money,
                       "require": [{"arg": "recipient", "op": "in_context",
                                    "key": "known_payees",
                                    "when_present": True,
                                    "confirmable": True},
                                   {"arg": "amount", "op": "max_minor",
                                    "value": int(round(prior_max * 100)),
                                    "when_present": True,
                                    "confirmable": True}]})
    return {"version": 1, "grants": grants}
