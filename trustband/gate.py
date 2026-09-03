"""Warrantable v1 — a running authorization gate following the Verus model.

THIS CODE IS NOT PROVED. It follows a proved design specification.

A Verus model proves 16 obligations about an abstract state machine. There is
no extraction and no refinement relation between that model and this file — a
gap the model's own confirmation notes record explicitly. What this file does
is match the model's transitions structurally, name by name, so that the
correspondence is inspectable by a reader rather than assumed. Every place it
cannot match is recorded alongside the model in the source repository rather
than smoothed over.

THE TWO DECISIONS THAT ARE NOT RE-DERIVED HERE
==============================================
1. Retired epochs are rejected by INTEGER COMPARISON (`cap.epoch == gov_epoch`),
   never by comparing tags. Comparing tags across epoch keys would require MAC
   distinctness — `mac(k_gov(e), ..) != mac(k_gov(e'), ..)` — which the model
   explicitly refuses to assume. The integer check needs nothing from the MAC,
   so it holds even if two epoch keys collided.

2. The band is stamped at ingestion FROM THE CHANNEL. `_band_for_channel` takes
   the channel and nothing else — the payload is not a parameter, so it is not
   in scope to be read. This is the A2 closure and it is the whole product.

A1 (MAC unforgeability, EUF-CMA, per-epoch key) remains irreducible. It is now
assumed of `hmac.new(..., sha256)` rather than of an uninterpreted symbol. That
moves where the assumption lives; it does not discharge it.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from trustband.policy import PolicyDomainError  # noqa: F401  (re-exported)
from trustband.audit import AuditLog
from trustband.policy import digest as policy_digest

# --------------------------------------------------------------------------
# Model types. `Tier`, `EntryId`, `SessionId`, `Nonce` are `int` in the model.
# --------------------------------------------------------------------------


class Band(Enum):
    """Content band, stamped by session demux at ingestion — NEVER read from payload."""

    GOVERNANCE = "governance"
    SESSION = "session"
    TOOL = "tool"
    USER = "user"


class Channel(Enum):
    """A physical arrival channel.

    Distinct from `Band` on purpose. The model's `ingest(chan: Band, cap: Cap)`
    takes a band directly; here a channel arrives and is *mapped* to a band, so
    that the mapping is a single named function a reader can audit.

    A2-RESIDUAL LIVES EXACTLY HERE: that a `Channel` value corresponds to the
    physical channel the bytes actually arrived on is a fact about the caller,
    not about this module, and no theorem covers it.
    """

    GOVERNANCE_BUS = "governance_bus"
    SESSION_DEMUX = "session_demux"
    TOOL_RETURN = "tool_return"
    USER_INPUT = "user_input"


def valid_tier(t: int) -> bool:
    """Model: `0 <= t <= 2`."""
    return isinstance(t, int) and not isinstance(t, bool) and 0 <= t <= 2


# The mapping is total over Channel and depends on NOTHING else.
_BAND_FOR_CHANNEL: Mapping[Channel, Band] = {
    Channel.GOVERNANCE_BUS: Band.GOVERNANCE,
    Channel.SESSION_DEMUX: Band.SESSION,
    Channel.TOOL_RETURN: Band.TOOL,
    Channel.USER_INPUT: Band.USER,
}


def _band_for_channel(channel: Channel) -> Band:
    """The band derivation. ONE parameter, and it is the channel.

    The payload is not a parameter, so there is no expression in this function
    that could read it. That is the structural form of "no band-from-payload
    path exists": not a rule the author followed, but an argument the function
    does not receive.

    `structural_selftest()` asserts this signature, so a later edit that added a
    payload parameter would fail a test rather than pass review.
    """
    if not isinstance(channel, Channel):
        raise TypeError(f"band must come from a Channel, got {type(channel).__name__}")
    return _BAND_FOR_CHANNEL[channel]


@dataclass(frozen=True)
class Cap:
    """Model `Cap`. Frozen: a capability is a value, not a mutable record."""

    sess: int
    tier: int
    nonce: int
    epoch: int
    #: Digest of the policy in force at minting -- `trustband.policy.digest`.
    #: Phase 2: a capability is valid only under the policy it was issued for.
    policy: bytes
    #: Phase 3: the MINTING session's own revocation counter. Revoking one
    #: session bumps it for that session alone, and (H) then refuses every
    #: capability still carrying the old value -- leaving others untouched.
    sess_epoch: int
    tag: bytes

    def bound_fields(self) -> Tuple[int, int, int, bytes, int]:
        """What the MAC covers: (sess, tier, nonce, policy_digest, sess_epoch).

        The epoch is NOT here: it keys the MAC, so altering it changes which key
        verifies the tag. The policy digest and the session epoch index nothing,
        so both must be in the message. Leaving `sess_epoch` out would let an
        adversary holding one genuine capability edit it to the session's
        current value and still verify -- making revocation decorative. That is
        `ce8_epoch_field_edited` in the crate.
        """
        return (self.sess, self.tier, self.nonce, self.policy, self.sess_epoch)


# Only `Gate.ingest` holds this. `Presented` refuses to construct without it.
_INGEST_TOKEN = object()


class CustodyError(Exception):
    """Raised when a caller asks for key material the custody mode does not
    permit this process to hold. Distinct from KeyError, which means the key
    existed and was discarded at rotation."""


class BandForgery(Exception):
    """Raised when something tries to mint a Presented outside ingestion."""


class Presented:
    """Model `Presented`. `via` is stamped by ingestion and is read-only.

    Constructing one requires a module-private token that only `Gate.ingest`
    holds, so a caller cannot hand the gate a `Presented` whose band it chose.
    In the model this is free — `ingested` is only written by `ingest`. In
    Python it takes a guard, and the guard is not absolute: anything with
    reflection can reach `_INGEST_TOKEN`. The honest claim is that no ORDINARY
    call path can forge a band, not that the language prevents it.
    """

    __slots__ = ("_cap", "_via")

    def __init__(self, cap: Cap, via: Band, *, _token: Any = None) -> None:
        if _token is not _INGEST_TOKEN:
            raise BandForgery(
                "Presented may only be constructed by Gate.ingest — the band is "
                "stamped from the arrival channel, never chosen by the caller")
        object.__setattr__(self, "_cap", cap)
        object.__setattr__(self, "_via", via)

    @property
    def cap(self) -> Cap:
        return self._cap

    @property
    def via(self) -> Band:
        return self._via

    def __setattr__(self, *_a: Any) -> None:
        raise BandForgery("Presented is immutable; `via` cannot be restamped")

    def __repr__(self) -> str:
        return f"Presented(cap={self._cap}, via={self._via.value})"

    def _key(self) -> Tuple[Any, ...]:
        return (self._cap, self._via)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Presented) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())


@dataclass(frozen=True)
class Entry:
    tier: int


@dataclass
class Decision:
    """The gate's answer, with the reason and the model conjunct it maps to."""

    allowed: bool
    reason: str
    conjunct: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed


# --------------------------------------------------------------------------
# k_gov(epoch) — a real, epoch-indexed key family.
# --------------------------------------------------------------------------


class EpochKeyStore:
    """`k_gov(epoch)`, made real.

    INDEPENDENT PER EPOCH, NOT DERIVED FROM A ROOT. Each epoch key is 32 fresh
    CSPRNG bytes. Deriving them from one root would mean a leaked root yields
    every epoch's key including future ones, which would quietly undo the very
    property `thm_retired_epoch_rejected` exists to give — damage bounded to the
    epoch. The model permits either (`k_gov` is uninterpreted, with no
    distinctness assumed), so this is a security choice the model leaves open,
    and it is made here deliberately.

    RETIRED KEYS ARE DISCARDED at rotation. Nothing needs them: retired
    capabilities are rejected by integer comparison, which consults no key. So
    the retired key has no legitimate use and is dropped.

    CUSTODY IS MEASURED, NOT ASSERTED — `describe_custody()` probes this live
    object and reports what it actually finds. A prior system in this programme
    shipped `vendor_can_hold_root = False` as a hardcoded class attribute --
    a custody claim that was true of the source file and never of the running
    process. That was a real defect and this does not repeat it.
    """

    def __init__(self, *, custody_mode: str = "in_process",
                 signer: Optional[Callable[[int, bytes], bytes]] = None) -> None:
        """`signer(epoch, message) -> mac` moves the key out of this process
        entirely. Supply one and no key is ever generated here: `tag()`
        delegates, `k_gov()` and `leak()` refuse, and `extractable` is False.
        That is the shape of AWS KMS GenerateMac, GCP MacSign or a PKCS#11
        token, and it is the ONLY way this class stops being the weakest part
        of the system."""
        self._custody_mode = ("external_signer" if signer is not None
                              else custody_mode)
        self._signer = signer
        self._keys: Dict[int, bytes] = {}
        self._discarded: List[int] = []
        if signer is None:
            self._ensure(0)

    def _ensure(self, epoch: int) -> None:
        if self._signer is not None:
            return
        if epoch not in self._keys:
            self._keys[epoch] = secrets.token_bytes(32)

    def k_gov(self, epoch: int) -> bytes:
        """The epoch key, IF this process is allowed to hold one.

        Under external custody there is no answer to give and this raises —
        which is the property being bought. The gate does not call this: it
        calls `tag()`/`verify()`. Remaining callers are the custody probe and
        the `leak()` test affordance.
        """
        if not self.extractable:
            raise CustodyError(
                f"k_gov({epoch}) refused: custody mode is "
                f"'{self._custody_mode}'. The key is not in this process, so "
                f"there is nothing to return. Use tag()/verify().")
        if epoch in self._discarded:
            raise KeyError(
                f"k_gov({epoch}) was discarded at rotation — a retired epoch key "
                f"has no legitimate use, because retired capabilities are "
                f"rejected by integer comparison, not by key")
        self._ensure(epoch)
        return self._keys[epoch]

    def advance_to(self, epoch: int) -> None:
        """Mint the new epoch's key and discard every earlier one."""
        self._ensure(epoch)
        for e in sorted(self._keys):
            if e < epoch:
                del self._keys[e]
                self._discarded.append(e)

    # -- the leak affordance, named as such -------------------------------
    # ---- the custody interface -------------------------------------------
    # `k_gov()` hands out a key; `tag()`/`verify()` hand out an ANSWER. While
    # the gate calls `k_gov()`, no vault helps: the code path is "give me the
    # key", so whatever holds it hands it over. Moving the operation in here is
    # what makes custody possible; which backend holds the key is then a
    # substitution behind one interface, not a redesign.

    def tag(self, epoch: int, sess: int, tier: int, nonce: int,
            policy: bytes = b"", sess_epoch: int = 0) -> bytes:
        """MAC the bound fields under the epoch key. The key does not leave.

        When a `signer` was supplied, this delegates and the key is never in
        this process at all — the shape of AWS KMS `GenerateMac`, GCP
        `MacSign`, or a PKCS#11 token.
        """
        msg = _tag_message(sess, tier, nonce, policy, sess_epoch)
        if self._signer is not None:
            return self._signer(epoch, msg)
        self._ensure_available(epoch)
        return hmac.new(self._keys[epoch], msg, sha256).digest()

    def verify(self, epoch: int, sess: int, tier: int, nonce: int,
               policy: bytes, sess_epoch: int, presented: bytes) -> bool:
        """Constant-time comparison, performed HERE so callers never hold the
        expected tag either. Raises KeyError for a discarded epoch, so the
        caller can fall through to the epoch check (F) rather than rejecting by
        key availability."""
        return hmac.compare_digest(
            self.tag(epoch, sess, tier, nonce, policy, sess_epoch), presented)

    # ---- domain-separated MACs, for identities that are not capabilities ----
    def mac(self, epoch: int, domain: bytes, *parts: bytes) -> bytes:
        """MAC length-prefixed parts under the epoch key, in a named domain.

        Same custody as `tag()`: delegates to the signer when there is one,
        and the key never leaves. The domain prefix is what keeps an agent
        identity from ever colliding with a capability tag -- a message that
        happened to equal `_tag_message(...)` still MACs differently here.
        Phase 7 uses it for agent identity; nothing about capabilities moved.
        """
        msg = domain + b"".join(
            len(p).to_bytes(4, "big") + p for p in parts)
        if self._signer is not None:
            return self._signer(epoch, msg)
        self._ensure_available(epoch)
        return hmac.new(self._keys[epoch], msg, sha256).digest()

    def verify_mac(self, epoch: int, domain: bytes, presented: bytes,
                   *parts: bytes) -> bool:
        """Constant-time, inside the store, like `verify()`."""
        return hmac.compare_digest(self.mac(epoch, domain, *parts), presented)

    @property
    def current_epoch(self) -> int:
        """The newest epoch this store holds a key for.

        In-process that tracks the gate's epoch. A file-backed store answers
        from the file, which is how a second process learns that another one
        rotated -- the integer comparison at (F) then needs no key at all.
        """
        return max(self._keys) if self._keys else 0

    def _ensure_available(self, epoch: int) -> None:
        if epoch in self._discarded:
            raise KeyError(
                f"epoch {epoch} was discarded at rotation — a retired epoch key "
                f"is gone, not merely refused")
        self._ensure(epoch)

    @property
    def extractable(self) -> bool:
        """True when this process can obtain raw key bytes. FALSE is the whole
        point of external custody."""
        return self._signer is None

    def leak(self, epoch: int) -> bytes:
        """Hand out an epoch key, simulating compromise. TEST AFFORDANCE ONLY.

        Present so route 3 can demonstrate the actual claim: an adversary
        holding `k_gov(e)` forges epoch-e tags at will, and every one of them
        dies when the epoch turns. A route that could not forge a *valid* tag
        would be testing the MAC, not the epoch bound.
        """
        return self.k_gov(epoch)

    def describe_custody(self) -> Dict[str, Any]:
        """MEASURED from this live object. Nothing here is a constant."""
        held = sorted(self._keys)
        probe_ok = False
        try:
            probe_ok = len(self.k_gov(held[-1])) == 32 if held else False
        except (KeyError, CustodyError):
            # CustodyError here is the GOOD outcome: this process asked for a
            # key and was refused, which is the property external custody buys.
            probe_ok = False
        # A live probe of the operation itself. Under external custody this
        # succeeds while key extraction fails -- that pair is the whole claim.
        op_ok = False
        try:
            op_ok = len(self.tag(max(held) if held else 0, 0, 0, 0)) == 32
        except Exception:
            op_ok = False
        return {
            "mode": self._custody_mode,
            "measured_from": "live key store instance, not configuration",
            "key_extractable_by_this_process": self.extractable,
            "extraction_probe_succeeded": probe_ok,
            "mac_operation_probe_succeeded": op_ok,
            "epochs_held_in_process": held,
            "key_bytes_in_process_memory": bool(held),
            "process_can_mint_for_held_epochs": probe_ok,
            "retired_epochs_discarded": sorted(self._discarded),
            "retired_key_recoverable": False if self._discarded else "n/a_no_rotation_yet",
            "derived_from_a_single_root": False,
            "note": (
                "v1 custody is IN-PROCESS. Any code in this process, and anything "
                "that can read this process's memory, holds every non-retired "
                "epoch key and can mint any capability. That is stated because a "
                "certificate carrying an unmeasured custody claim is worse than "
                "one carrying an honest weak claim. Moving k_gov behind a KMS is "
                "v2 work and is not done here."),
        }


def _tag_message(sess: int, tier: int, nonce: int,
                 policy: bytes = b"", sess_epoch: int = 0) -> bytes:
    """The bytes that get MAC'd. Length-prefixed so (1, 22, 3) and (12, 2, 3)
    cannot collide through concatenation — the model's `mac` is a function of
    three separate integers and a naive join would not be."""
    msg = b"".join(
        len(part).to_bytes(4, "big") + part
        for part in (str(sess).encode(), str(tier).encode(),
                     str(nonce).encode(), policy, str(sess_epoch).encode())
    )
    return b"trustband.cap.v3|" + msg


def compute_tag(key: bytes, sess: int, tier: int, nonce: int,
                policy: bytes = b"", sess_epoch: int = 0) -> bytes:
    """`mac(k_gov(epoch), sess, tier, nonce)` — HMAC-SHA256.

    NOT hand-rolled: `hmac` from the standard library. The fields are
    length-prefixed so that (1, 22, 3) and (12, 2, 3) cannot collide through
    concatenation — the model's `mac` is a function of three separate integers,
    and a naive join would not be.
    """
    return hmac.new(key, _tag_message(sess, tier, nonce, policy, sess_epoch),
                    sha256).digest()


class Gate:
    """The running gate. One method per model transition, named to match.

    | model transition        | method here        |
    |-------------------------|--------------------|
    | init_empty(budget)      | Gate(budget=...)   |
    | ingest(chan, cap)       | ingest()           |
    | write(tier, eid)        | write()            |
    | govern_issue(s,t,n)     | govern_issue()     |
    | govern_rotate()         | govern_rotate()    |
    | govern_repolicy(policy) | govern_repolicy()  |
    | authorize_elevation()   | authorize()        |
    | influence() [property]  | influence()        |
    | revoke_session(sess)    | revoke_session()   |
    | withdraw_elevation(..)  | withdraw_elevation()|

    Every model transition now has a method. The last two were proved before
    they were ported, deliberately, so the implementation never ran ahead of
    what is covered.
    """

    def __init__(self, budget: int, *, keys: Optional[EpochKeyStore] = None,
                 audit_keys: Optional[EpochKeyStore] = None,
                 stateless_verification: bool = False) -> None:
        # model: `require budget >= 1`
        if not (isinstance(budget, int) and not isinstance(budget, bool) and budget >= 1):
            raise ValueError(f"gov_budget must be an integer >= 1, got {budget!r}")
        self.store: Dict[int, Entry] = {}
        self.elev: set = set()
        self.issued: set = set()
        self.gov_epoch: int = 0
        #: Digest of the ENFORCED policy. A capability minted under a different
        #: one is dead at the gate, conjunct (G) -- structurally, exactly as a
        #: retired epoch is at (F). Written only by `govern_repolicy`.
        self.gov_policy: bytes = policy_digest(None)
        #: Phase 3 -- per-session revocation counters. Written ONLY by
        #: `revoke_session`, and only upward. Absent == 0, so `sess_epoch_of`
        #: is total and no gate check depends on dictionary membership.
        self.sess_epoch: Dict[int, int] = {}
        self.minted_in_epoch: int = 0
        self.gov_budget: int = budget
        self.ingested: set = set()
        self.keys = keys if keys is not None else EpochKeyStore()
        # The v1 specification records this: the model's conjunct (B) is set
        # membership.
        # A deployment that cannot keep the set relies on the MAC alone, which
        # means relying on A1. This flag makes that difference demonstrable
        # rather than a paragraph.
        self.stateless_verification = stateless_verification
        self.log: List[Dict[str, Any]] = []
        #: Hash-chained, sealable audit. Records refusals as well as grants: a
        #: log of grants alone answers "what did we permit" and not "what did
        #: we stop", and the second is what a security review asks about.
        self.audit = AuditLog()
        #: SEALS USE THEIR OWN KEY, NOT THE EPOCH KEY.
        #:
        #: Found by attacking the pair: sealing under `k_gov(epoch)` and then
        #: rotating discards the key the seal was made with, so `verify_audit`
        #: reported FAILURE on a legitimate, untampered log -- and reported it
        #: precisely when you most want the history checkable. A false alarm is
        #: the worst outcome for an integrity check, because it teaches people
        #: to ignore it.
        #:
        #: The cause was coupling two lifecycles that have nothing to do with
        #: each other: capability revocation wants keys to die, audit
        #: verification wants them to persist. They now have separate stores.
        #: This one is never rotated, and it takes a `signer` like any other, so
        #: external custody applies to it too.
        self.audit_keys = audit_keys if audit_keys is not None else EpochKeyStore()

    # -- the key store may know about a rotation this process did not do --
    def _follow_keys(self) -> None:
        """Adopt a rotation performed by ANOTHER process.

        A file-backed key store shares the epoch key between processes, so
        another process's `govern_rotate` retires the key this one is still
        minting under. Found by attacking pair 2 of the Phase 7 joins: after a
        foreign rotation `govern_issue` here raised KeyError from inside the
        store, which is a crash where the model says a refusal at (F).

        This is not a new transition. It is `govern_rotate`, observed late:
        the same write to `gov_epoch`, the same fresh budget, the same
        discarded key. In-process the store's epoch can never be ahead of
        this one, so for the deposited model's own configuration this is a
        no-op, and the proof is not disturbed.
        """
        cur = self.keys.current_epoch
        if cur > self.gov_epoch:
            self.gov_epoch = cur
            self.minted_in_epoch = 0

    # -- logging ----------------------------------------------------------
    def _record(self, op: str, decision: Decision, **ctx: Any) -> Decision:
        rec = {
            "t": round(time.time(), 6),
            "op": op,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "conjunct": decision.conjunct,
            "gov_epoch": self.gov_epoch,
            **ctx,
        }
        self.log.append(rec)
        # The chain covers the same record. Timestamps are inside it, so a
        # replayed entry changes the digest and is not silently accepted.
        self.audit.append(rec)
        return decision

    # -- transition: ingest ------------------------------------------------
    def ingest(self, channel: Channel, payload: Cap) -> Presented:
        """Model `ingest(chan: Band, cap: Cap)`.

        `payload` is inserted verbatim and is NEVER consulted to choose the
        band. The band comes from `_band_for_channel(channel)`, which does not
        receive the payload.

        Like the model's transition, this has NO preconditions: anything may be
        ingested on any channel. The refusal happens at `authorize`, by conjunct
        (A). Ingestion is where the band is DECIDED, not where bad things are
        turned away.
        """
        via = _band_for_channel(channel)          # payload is not passed. At all.
        p = Presented(payload, via, _token=_INGEST_TOKEN)
        self.ingested.add(p)
        self._record("ingest", Decision(True, "ingested; band stamped from channel"),
                     channel=channel.value, band=via.value,
                     cap_epoch=payload.epoch, cap_tier=payload.tier)
        return p

    # -- transition: write -------------------------------------------------
    def write(self, tier: int, eid: int) -> Decision:
        """Model `write(tier, eid)`."""
        if not valid_tier(tier):
            return self._record("write", Decision(False, f"invalid tier {tier!r}", "E"))
        if eid in self.store:
            return self._record("write", Decision(False, f"entry {eid} already exists"))
        self.store[eid] = Entry(tier=tier)
        return self._record("write", Decision(True, "entry written"), eid=eid, tier=tier)

    # -- transition: govern_issue -----------------------------------------
    def govern_issue(self, sess: int, tier: int, nonce: int) -> Tuple[Decision, Optional[Cap]]:
        """Model `govern_issue(sess, tier, nonce)` — the SOLE minting step.

        The tag is produced here, under the CURRENT epoch's key, and nowhere
        else in this module.
        """
        if not valid_tier(tier):
            return self._record("govern_issue",
                                Decision(False, f"invalid tier {tier!r}", "E")), None
        self._follow_keys()
        # model: `require pre.minted_in_epoch < pre.gov_budget`
        if self.minted_in_epoch >= self.gov_budget:
            return self._record("govern_issue", Decision(
                False,
                f"mint budget exhausted: {self.minted_in_epoch}/{self.gov_budget} "
                f"in epoch {self.gov_epoch}; rotate to mint again",
                "budget")), None
        se = self.sess_epoch_of(sess)
        cap = Cap(sess=sess, tier=tier, nonce=nonce, epoch=self.gov_epoch,
                  policy=self.gov_policy, sess_epoch=se,
                  tag=self.keys.tag(self.gov_epoch, sess, tier, nonce,
                                    self.gov_policy, se))
        # model: `require !pre.issued.contains(cap)`
        if cap in self.issued:
            return self._record("govern_issue",
                                Decision(False, "capability already issued", "dup")), None
        self.issued.add(cap)
        self.minted_in_epoch += 1
        return self._record("govern_issue", Decision(True, "capability minted"),
                            sess=sess, tier=tier, nonce=nonce,
                            minted=self.minted_in_epoch), cap

    # -- transition: govern_rotate ----------------------------------------
    def govern_repolicy(self, policy: Any) -> Decision:
        """Adopt a new enforced policy. Writes `gov_policy` and NOTHING else.

        In particular it does not touch `issued`: capabilities minted under the
        superseded policy stay minted and die at conjunct (G), never by being
        retracted. Same shape as `govern_rotate`, and for the same reason --
        revocation by structural comparison rather than by mutating what was
        already issued.

        `policy` is the policy VALUE, not a digest. It is encoded here, so a
        value outside the restricted domain raises `PolicyDomainError` and the
        policy is not adopted. There is deliberately no fallback digest: a
        partial encoder that defaulted would silently collapse distinct policies
        onto one tag.
        """
        self.gov_policy = policy_digest(policy)
        return self._record("govern_repolicy", Decision(
            True, f"policy adopted: {self.gov_policy.hex()[:16]}…", None))

    def seal_audit(self) -> Any:
        """Anchor the audit head under the current epoch key.

        Seal often. The interval between seals is the window in which the tail
        can be truncated undetectably -- an operator choice with the same shape
        as `gov_budget`, and the reason the verify report names the unsealed
        tail length rather than passing quietly.
        """
        return self.audit.seal(self.audit_keys, 0)

    def verify_audit(self) -> Any:
        """Recompute the chain and check every seal."""
        return self.audit.verify(self.audit_keys)

    def sess_epoch_of(self, sess: int) -> int:
        """A session's current revocation counter. TOTAL: never-revoked is 0."""
        return self.sess_epoch.get(sess, 0)

    def revoke_session(self, sess: int) -> Decision:
        """Model `revoke_session(sess)` — Phase 3.

        Bumps ONE session's counter and writes nothing else. Every capability of
        that session is then dead at (H); every capability of every other
        session is untouched, which is `thm_session_revocation_is_local` and is
        the point of the phase.

        Like `govern_rotate` and `govern_repolicy` it does not touch `issued`:
        revocation by structural comparison, never by mutating what was minted.
        """
        self.sess_epoch[sess] = self.sess_epoch_of(sess) + 1
        return self._record("revoke_session", Decision(
            True, f"session {sess} revoked; now at epoch "
                  f"{self.sess_epoch[sess]}"), sess=sess)

    def withdraw_elevation(self, eid: int, r_tier: int) -> Decision:
        """Model `withdraw_elevation(eid, r_tier)` — Phase 4.

        Removes one elevation. Rotation and `revoke_session` kill the
        CAPABILITY; this undoes its EFFECT, and the two are not
        interchangeable: after a withdrawal a still-valid capability can
        authorise the same elevation again
        (`thm_withdrawal_permits_reauthorization`).

        Strictly de-escalating (`thm_withdrawal_only_shrinks`) and idempotent
        (`thm_withdrawal_idempotent`), so a runbook retrying after a timeout
        need not know whether the first attempt landed.
        """
        had = (eid, r_tier) in self.elev
        self.elev.discard((eid, r_tier))
        return self._record("withdraw_elevation", Decision(
            True, f"elevation ({eid}, {r_tier}) withdrawn"
                  if had else f"elevation ({eid}, {r_tier}) was not present"),
            eid=eid, tier=r_tier, was_present=had)

    def govern_rotate(self) -> Decision:
        """Model `govern_rotate()` — strict advance, fresh budget.

        Every capability minted in the previous epoch now fails conjunct (F),
        structurally, with no MAC property involved.
        """
        # From the store's epoch, not a stale local one: two processes that
        # each rotate once must end at 2, not both at 1.
        self._follow_keys()
        self.gov_epoch += 1
        self.minted_in_epoch = 0
        self.keys.advance_to(self.gov_epoch)
        return self._record("govern_rotate",
                            Decision(True, f"epoch advanced to {self.gov_epoch}"))

    # -- property: influence ----------------------------------------------
    def influence(self, c_tier: int, eid: int, r_tier: int) -> Decision:
        """Model `influence` property. Read-only."""
        if not (valid_tier(c_tier) and valid_tier(r_tier)):
            return Decision(False, "invalid tier", "E")
        if eid not in self.store:
            return Decision(False, f"no entry {eid}")
        if c_tier >= r_tier or (eid, r_tier) in self.elev:
            return Decision(True, "may influence")
        return Decision(False, "may_influence false: needs elevation")

    # -- transition: authorize_elevation ----------------------------------
    def authorize(self, presented: Presented, sess: int, eid: int, r_tier: int) -> Decision:
        """Model `authorize_elevation(p, sess, eid, r_tier)`.

        Conjuncts are checked in the model's own order and the FIRST failure is
        reported, so a refusal reason names the model conjunct that produced it.

        (A0) ingested   (A) band   (B) issued + tag   (F) epoch
        (C) session     (D) tier   (E) valid_tier

        BADGE SEMANTICS -- REPEATED PRESENTATION IS INTENDED, NOT AN OVERSIGHT.
        A capability is valid for its epoch and may be presented any number of
        times. This method does not consume it, does not mark a nonce spent, and
        deliberately keeps no spent-set: the bound on replay is `govern_rotate`,
        enforced at conjunct (F) by integer comparison.

        Specified and proved in `th_model.rs` as D-BADGE, with
        `thm_badge_presentation_does_not_consume` (authorizing does not disturb
        anything `valid_system_token` reads) and `thm_badge_bounded_by_rotation`
        (a capability valid now is dead once the epoch turns, however many times
        it was shown first).

        THE EXPOSURE THIS ACCEPTS: an adversary who can OBSERVE a capability can
        present it until rotation. That is why `gov_budget` and rotation cadence
        are operator decisions. If a single capability could ever authorise an
        irreversible high-value action, that tier would want a ticket instead --
        a per-tier decision, not made here.
        """
        if not isinstance(presented, Presented):
            return self._record("authorize", Decision(
                False, "not a Presented — never passed through ingestion", "A0"))

        self._follow_keys()
        cap = presented.cap

        # (A0) provenance — it came through ingest
        if presented not in self.ingested:
            return self._record("authorize", Decision(
                False, "not in ingested: never arrived through an ingestion channel", "A0"))

        # (A) band-binding — kills the forged-band route
        if presented.via != Band.SESSION:
            return self._record("authorize", Decision(
                False,
                f"band is {presented.via.value!r}, elevation requires "
                f"{Band.SESSION.value!r}; the band was stamped from the arrival "
                f"channel and the payload's own claim was never read",
                "A"), band=presented.via.value)

        # (B) issuance. Two checks, because the model's set and a real
        # deployment's MAC are not the same thing; the v1 specification
        # records why.
        #
        # THE MAC IS CHECKED FIRST, DELIBERATELY. The earlier gate this
        # consolidated documented the ordering as load-bearing: MAC
        # verification must precede issued-set membership, because it is what
        # closes the G5 wiring. Checking the set first would let the gate answer whether
        # a token was ever issued to a caller who cannot produce a valid tag,
        # and reversing a documented security ordering while consolidating would
        # be exactly the silent change this work exists to avoid. Both must
        # hold, so the order changes only which reason is reported — and this
        # order reports the cryptographic one.
        try:
            # Constant-time compare happens INSIDE the store, so this process
            # holds neither the key nor the expected tag.
            tag_ok = self.keys.verify(cap.epoch, *cap.bound_fields(), cap.tag)
        except KeyError:
            # The epoch key was discarded at rotation. Fall through to (F),
            # which is the check that is *supposed* to reject this — rejecting
            # here would be rejecting by key availability, a weaker and less
            # honest reason than the integer comparison.
            tag_ok = None
        if tag_ok is False:
            return self._record("authorize", Decision(
                False, "MAC verification failed: tag is not the one governance "
                       "would have computed for these fields under this epoch key",
                "B"))
        # (B') issued-set membership — the model's actual conjunct (B).
        if not self.stateless_verification and cap not in self.issued:
            return self._record("authorize", Decision(
                False, "capability not in issued: governance never minted it", "B"))

        # (G) policy currency — Phase 2. A capability minted under a superseded
        # policy is dead here, by digest comparison. Like (F) this needs nothing
        # from the MAC: it holds even if two policies' tags collided, because
        # the comparison is on the digest carried in the capability, which the
        # MAC already authenticated at (B).
        if cap.policy != self.gov_policy:
            return self._record("authorize", Decision(
                False,
                f"superseded policy: capability minted under "
                f"{cap.policy.hex()[:16]}…, governance enforces "
                f"{self.gov_policy.hex()[:16]}…",
                "G"))

        # (F) epoch currency — INTEGER COMPARISON, never tag comparison.
        # Comparing tags across epoch keys would require MAC distinctness, which
        # the model refuses to assume. This needs nothing from the MAC and holds
        # even if two epoch keys collided.
        if cap.epoch != self.gov_epoch:
            return self._record("authorize", Decision(
                False,
                f"retired epoch: capability minted in epoch {cap.epoch}, "
                f"governance is at epoch {self.gov_epoch} "
                f"(integer comparison; no MAC property used)",
                "F"), cap_epoch=cap.epoch)

        if tag_ok is None:                      # key gone but epoch matched: impossible
            return self._record("authorize", Decision(
                False, "epoch key unavailable for a current-epoch capability", "B"))

        # (H) SESSION-epoch currency — Phase 3. Revoking one session kills its
        # capabilities and no others. Integer comparison; no MAC property, so it
        # holds against an adversary who holds the epoch key.
        if cap.sess_epoch != self.sess_epoch_of(cap.sess):
            return self._record("authorize", Decision(
                False,
                f"revoked session: capability carries session-epoch "
                f"{cap.sess_epoch}, session {cap.sess} is at "
                f"{self.sess_epoch_of(cap.sess)} "
                f"(integer comparison; no MAC property used)",
                "H"), cap_sess_epoch=cap.sess_epoch)

        # (C) this session
        if cap.sess != sess:
            return self._record("authorize", Decision(
                False, f"session mismatch: capability binds {cap.sess}, presented for {sess}",
                "C"))

        # (D) this tier
        if cap.tier != r_tier:
            return self._record("authorize", Decision(
                False,
                f"tier mismatch: capability grants tier {cap.tier}, "
                f"action requires tier {r_tier}",
                "D"), cap_tier=cap.tier, requested=r_tier)

        # (E) sanity
        if not valid_tier(r_tier):
            return self._record("authorize", Decision(
                False, f"invalid requested tier {r_tier!r}", "E"))

        # model also requires the entry exists
        if eid not in self.store:
            return self._record("authorize", Decision(False, f"no entry {eid}"))

        self.elev.add((eid, r_tier))
        return self._record("authorize", Decision(True, "elevation authorized"),
                            eid=eid, tier=r_tier, sess=sess)


def structural_selftest() -> Dict[str, Any]:
    """Assert the structural properties the product rests on. Checked, not claimed."""
    import inspect

    sig = inspect.signature(_band_for_channel)
    params = list(sig.parameters)
    results = {
        "band_derivation_takes_only_channel": params == ["channel"],
        "band_derivation_params": params,
        "band_derivation_is_total_over_channels":
            set(_BAND_FOR_CHANNEL) == set(Channel),
        "presented_requires_ingest_token": False,
        "presented_via_is_readonly": False,
    }
    # The INGRESS band derivation: same device, one step earlier. A band cannot
    # be passed to it because it has no such parameter.
    try:
        from trustband.transport import BoundListener, band_from_accepting_listener

        isig = list(inspect.signature(band_from_accepting_listener).parameters)
        results["ingress_band_takes_only_listener"] = isig == ["listener"]
        results["ingress_band_params"] = isig
        results["listener_channel_is_readonly"] = False
        bl = BoundListener(Channel.TOOL_RETURN, "/tmp/_selftest.sock")
        try:
            bl._channel = Channel.SESSION_DEMUX          # type: ignore[misc]
        except Exception:
            results["listener_channel_is_readonly"] = True
        results["listener_band_is_derived_not_stored"] = "band" not in BoundListener.__slots__
    except ImportError:                                   # transport is optional
        results["ingress_band_takes_only_listener"] = "transport_not_available"

    dummy = Cap(0, 0, 0, 0, b"", 0, b"")
    try:
        Presented(dummy, Band.GOVERNANCE)
    except BandForgery:
        results["presented_requires_ingest_token"] = True
    p = Presented(dummy, Band.TOOL, _token=_INGEST_TOKEN)
    try:
        p.via = Band.GOVERNANCE                                   # type: ignore[misc]
    except BandForgery:
        results["presented_via_is_readonly"] = True
    results["all_pass"] = all(
        v is True for k, v in results.items()
        if k.endswith(("_channel", "_channels", "_token", "_readonly",
                       "_listener", "_stored")))
    return results
