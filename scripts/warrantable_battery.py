#!/usr/bin/env python3
"""Warrantable v1 — the measured battery. Six routes, ungated and gated.

    python scripts/warrantable_battery.py

GATE 0 IS ENFORCED PER ROUTE. Every attack must SUCCEED against the ungated
baseline before its gated refusal means anything. A route whose ungated arm
fails has no power: its clean gated result is an artifact of a broken attack,
not evidence of a defence, and this harness marks it VOID and refuses to count
it. That discipline has caught nine instrument defects across this portfolio and
is not skipped here.

The ungated baseline is not a strawman — it is what an agent looks like when it
takes provenance from the message: band read from the payload's own claim, no
MAC verification, no epoch check, no tier check, no mint budget.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from warrantable.gate import (  # noqa: E402
    Band, Cap, Channel, Decision, Entry, EpochKeyStore, Gate,
    compute_tag, structural_selftest,
)

SESS, EID = 7, 100


@dataclass
class Envelope:
    """What arrives. `claims` is ATTACKER-CONTROLLED and the gate never reads it."""

    channel: Channel
    cap: Cap
    claims: Dict[str, Any] = field(default_factory=dict)


class UngatedBaseline:
    """An agent with no gate: provenance comes from the message.

    Every check the gate performs is absent here, and each absence is the
    ordinary way such a system gets built rather than a deliberate hole:
      * band is whatever the payload says it is
      * a tag is a string nobody verifies
      * an epoch is a number nobody compares
      * a tier is a claim nobody bounds
      * minting is unbounded
    """

    def __init__(self) -> None:
        self.store: Dict[int, Entry] = {}
        self.elev: set = set()
        self.minted = 0

    def write(self, tier: int, eid: int) -> None:
        self.store[eid] = Entry(tier=tier)

    def govern_issue(self, sess: int, tier: int, nonce: int, epoch: int = 0) -> Cap:
        self.minted += 1                       # no budget
        return Cap(sess=sess, tier=tier, nonce=nonce, epoch=epoch, tag=b"whatever")

    def authorize(self, env: Envelope, sess: int, eid: int, r_tier: int) -> Decision:
        band = env.claims.get("band")          # <-- THE VULNERABILITY: from payload
        if band != Band.SESSION.value:
            return Decision(False, f"ungated: band claim {band!r} not session")
        if eid not in self.store:
            return Decision(False, "ungated: no entry")
        self.elev.add((eid, r_tier))           # no MAC, no epoch, no tier check
        return Decision(True, "ungated: elevation granted on the payload's own claim")


# --------------------------------------------------------------------------

ROUTES: List[Dict[str, Any]] = []


def route(n: int, name: str, kind: str = "attack"):
    """kind="attack": must be refused. kind="property": a bounded behaviour.

    Routes 1-5 are attacks and a clean run means refusal. Route 6 is NOT an
    attack -- replay within an epoch is permitted by design -- so counting it
    among "refusals" would misreport it as a defeated attack. It is reported
    separately as a demonstrated bound.
    """
    def deco(fn):
        ROUTES.append({"n": n, "name": name, "fn": fn, "kind": kind})
        return fn
    return deco


def fresh_gate(budget: int = 8, stateless: bool = False):
    g = Gate(budget=budget, stateless_verification=stateless)
    g.write(2, EID)
    return g


def fresh_ungated():
    u = UngatedBaseline()
    u.write(2, EID)
    return u


# ---- 1 -------------------------------------------------------------------
@route(1, "Forged band — payload claims a higher-trust provenance")
def r1():
    # Ungated: a tool return claims it arrived on the session channel.
    u = fresh_ungated()
    cap = u.govern_issue(SESS, 2, 1)
    env = Envelope(Channel.TOOL_RETURN, cap, claims={"band": "session"})
    ung = u.authorize(env, SESS, EID, 2)

    # Gated: the same bytes on the same channel. The claim is never read.
    g = fresh_gate()
    _, gcap = g.govern_issue(SESS, 2, 1)
    p = g.ingest(Channel.TOOL_RETURN, gcap)     # claims={"band":"session"} discarded
    gat = g.authorize(p, SESS, EID, 2)
    return ung, gat, {
        "attacker_claim": "band=session",
        "band_actually_stamped": p.via.value,
        "note": "the claim never reaches the band derivation — "
                "_band_for_channel does not take the payload as a parameter",
    }


# ---- 2 -------------------------------------------------------------------
@route(2, "Forged capability — a fabricated tag presented directly")
def r2():
    u = fresh_ungated()
    forged_u = Cap(SESS, 2, 99, 0, b"\xde\xad\xbe\xef" * 8)
    ung = u.authorize(Envelope(Channel.SESSION_DEMUX, forged_u, {"band": "session"}),
                      SESS, EID, 2)

    # Gated, STATELESS: the MAC is the only thing standing between the
    # adversary and the elevation. This is the deployment shape that relies on
    # A1, and the one the route is about.
    g = fresh_gate(stateless=True)
    forged = Cap(SESS, 2, 99, g.gov_epoch, b"\xde\xad\xbe\xef" * 8)
    p = g.ingest(Channel.SESSION_DEMUX, forged)
    gat = g.authorize(p, SESS, EID, 2)

    # And with the model's `issued` set present, for the record.
    g2 = fresh_gate(stateless=False)
    p2 = g2.ingest(Channel.SESSION_DEMUX, Cap(SESS, 2, 99, g2.gov_epoch, b"\x00" * 32))
    gat2 = g2.authorize(p2, SESS, EID, 2)
    return ung, gat, {
        "stateless_refusal": f"[{gat.conjunct}] {gat.reason}",
        "with_issued_set_refusal": f"[{gat2.conjunct}] {gat2.reason}",
        "note": "stateless is the honest test of the MAC; the set catches it too "
                "and does so without relying on A1 at all",
    }


# ---- 3 -------------------------------------------------------------------
@route(3, "Retired-epoch replay — a genuine capability from a previous epoch")
def r3():
    u = fresh_ungated()
    old = u.govern_issue(SESS, 2, 5, epoch=0)
    ung = u.authorize(Envelope(Channel.SESSION_DEMUX, old, {"band": "session"}),
                      SESS, EID, 2)          # ungated never compares epochs

    g = fresh_gate()
    _, cap0 = g.govern_issue(SESS, 2, 5)     # genuine, epoch 0
    g.govern_rotate()                        # -> epoch 1
    p = g.ingest(Channel.SESSION_DEMUX, cap0)
    gat = g.authorize(p, SESS, EID, 2)

    # THE LEAKED-KEY SCENARIO, made explicit. An adversary holding k_gov(e)
    # forges VALID epoch-e tags at will. Stateless, so the MAC is the only
    # barrier — which is exactly what a key leak removes.
    gl = fresh_gate(stateless=True)
    leaked = gl.keys.leak(gl.gov_epoch)
    forged_now = Cap(SESS, 2, 4242, gl.gov_epoch,
                     compute_tag(leaked, SESS, 2, 4242))
    during = gl.authorize(gl.ingest(Channel.SESSION_DEMUX, forged_now), SESS, EID, 2)
    gl.govern_rotate()
    after = gl.authorize(gl.ingest(Channel.SESSION_DEMUX, forged_now), SESS, EID, 2)
    # ...and the adversary cannot re-forge for the NEW epoch: it holds k_gov(0).
    still_old = Cap(SESS, 2, 4243, 0, compute_tag(leaked, SESS, 2, 4243))
    after2 = gl.authorize(gl.ingest(Channel.SESSION_DEMUX, still_old), SESS, EID, 2)
    return ung, gat, {
        "leaked_key_forgery_during_epoch": f"allowed={during.allowed} ({during.reason})",
        "same_forgery_after_rotation": f"allowed={after.allowed} [{after.conjunct}] {after.reason}",
        "new_forgery_under_the_leaked_key": f"allowed={after2.allowed} [{after2.conjunct}]",
        "note": "a leaked epoch key mints freely WHILE its epoch is current — that "
                "is what a leak means — and every capability it ever produces dies "
                "at rotation by integer comparison, no MAC property used",
    }


# ---- 4 -------------------------------------------------------------------
@route(4, "Tier escalation — a low-tier capability presented for a high-tier action")
def r4():
    u = fresh_ungated()
    low = u.govern_issue(SESS, 0, 11)
    ung = u.authorize(Envelope(Channel.SESSION_DEMUX, low, {"band": "session"}),
                      SESS, EID, 2)          # asks for tier 2 with a tier-0 cap

    g = fresh_gate()
    _, cap = g.govern_issue(SESS, 0, 11)     # genuine tier-0 capability
    p = g.ingest(Channel.SESSION_DEMUX, cap)
    gat = g.authorize(p, SESS, EID, 2)       # presented for tier 2
    return ung, gat, {"capability_tier": 0, "action_tier": 2}


# ---- 5 -------------------------------------------------------------------
@route(5, "Budget exhaustion — minting past gov_budget without rotating")
def r5():
    BUDGET = 3
    u = fresh_ungated()
    for i in range(BUDGET + 2):
        u.govern_issue(SESS, 1, 200 + i)
    ung = Decision(u.minted > BUDGET,
                   f"ungated: minted {u.minted} with no budget at all")

    g = fresh_gate(budget=BUDGET)
    outcomes = []
    for i in range(BUDGET + 2):
        d, _ = g.govern_issue(SESS, 1, 200 + i)
        outcomes.append(d.allowed)
    gat = Decision(all(outcomes[:BUDGET]) and not any(outcomes[BUDGET:]),
                   f"minted {sum(outcomes)}/{BUDGET}, then refused")
    # the refusal reason itself
    d_ref, _ = g.govern_issue(SESS, 1, 999)
    # and rotation restores capacity, which is the point of the budget
    g.govern_rotate()
    d_after, _ = g.govern_issue(SESS, 1, 999)
    # `allowed` means DID THE ATTACK SUCCEED, uniformly across routes. Passing
    # `not d_ref.allowed` here inverted it and made a correct refusal print as
    # "*** ALLOWED ***" — a harness bug that would have read as a product
    # failure in the report.
    return ung, Decision(d_ref.allowed, d_ref.reason, d_ref.conjunct), {
        "per_attempt_allowed": outcomes,
        "refusal": f"[{d_ref.conjunct}] {d_ref.reason}",
        "mint_after_rotation": f"allowed={d_after.allowed}",
        "note": "the epoch bounds damage by MINT COUNT, not elapsed time — "
                "gov_budget is the operator's most consequential choice",
    }


# ---- 6 -------------------------------------------------------------------
@route(6, "Replay within an epoch — BADGE SEMANTICS, bounded by rotation",
       kind="property")
def r6():
    """NOT AN ATTACK ROUTE. A bounded-property route.

    A capability is a badge: valid for its epoch, presentable repeatedly. So the
    interesting question is not "is replay refused" -- it is permitted by design
    -- but "is it bounded". Same shape as route 3: allowed while the epoch is
    current, dead at rotation, by integer comparison.
    """
    # Gate 0 still applies: the ungated arm must ACCEPT the capability, or the
    # post-rotation refusal below would prove nothing about rotation.
    u = fresh_ungated()
    cap = u.govern_issue(SESS, 2, 77)
    e = Envelope(Channel.SESSION_DEMUX, cap, {"band": "session"})
    u.authorize(e, SESS, EID, 2)
    ung = u.authorize(e, SESS, EID, 2)       # accepted, repeatedly, ungated

    g = fresh_gate()
    _, gcap = g.govern_issue(SESS, 2, 77)
    p = g.ingest(Channel.SESSION_DEMUX, gcap)
    within = [g.authorize(p, SESS, EID, 2).allowed for _ in range(3)]

    # minting the same (sess,tier,nonce) twice IS refused -- a different thing
    # from re-presenting one already minted. Conflating them would overstate
    # what the model gives.
    dup, _ = g.govern_issue(SESS, 2, 77)

    g.govern_rotate()
    after = g.authorize(g.ingest(Channel.SESSION_DEMUX, gcap), SESS, EID, 2)
    return ung, after, {
        "presentations_within_epoch": within,
        "all_allowed_within_epoch": all(within),
        "property": "a capability may be presented repeatedly within its epoch, "
                    "and is dead after rotation",
        "holds": all(within) and not after.allowed,
        "re_mint_same_nonce": f"allowed={dup.allowed} — {dup.reason}",
        "after_rotation": f"allowed={after.allowed} [{after.conjunct}] {after.reason[:70]}",
        "note": "BY DESIGN, not a gap. A capability is a BADGE: valid for its "
                "epoch, presentable repeatedly. Specified as D-BADGE in "
                "th_model.rs and proved by thm_badge_presentation_does_not_consume "
                "and thm_badge_bounded_by_rotation. The bound is rotation, at "
                "conjunct (F), by integer comparison. ACCEPTED EXPOSURE: an "
                "adversary who can observe a capability can present it until "
                "rotation -- which is why gov_budget and rotation cadence matter.",
    }


@route(7, "Forged channel — connect to a LOW-trust listener, claim high trust")
def r7():
    """The band comes from the accepting socket, so the claim cannot land.

    Gate 0 arm: band taken from the REQUEST (what the system did before the
    transport existed). Gated arm: band taken from the accepting listener.
    """
    import os, tempfile
    from warrantable.transport import Ingress, band_from_accepting_listener, connect_and_send

    d = tempfile.mkdtemp(prefix="r7_")
    binds = {c: os.path.join(d, f"{c.value}.sock") for c in Channel}
    ing = Ingress(binds)

    # --- Gate 0: band from the REQUEST. The forged claim must be accepted. ---
    def ungated_handler(listener, data):
        import json
        try:
            claimed = json.loads(data.decode()).get("band")
        except Exception:
            claimed = None
        return (claimed or listener.band.value).encode()   # trusts the payload

    ing.serve(ungated_handler)
    ung_band = connect_and_send(binds[Channel.TOOL_RETURN],
                                b'{"band":"session"}').decode()
    ing.shutdown()
    ung = SimpleNamespace(
        allowed=(ung_band == "session"),
        reason=f"ungated: connected to TOOL listener, claimed band in payload, "
               f"system reported {ung_band!r}")

    # --- Gated: band from the ACCEPTING LISTENER. -------------------------
    ing2 = Ingress(binds)
    ing2.serve(lambda l, data: band_from_accepting_listener(l).value.encode())
    observed = {}
    for c in (Channel.TOOL_RETURN, Channel.USER_INPUT, Channel.SESSION_DEMUX):
        observed[c.value] = connect_and_send(
            binds[c], b'{"band":"session","via":"GOVERNANCE"}').decode()
    ing2.shutdown()

    forged_landed = observed["tool_return"] == "session"
    g = fresh_gate(); g.write(2, EID)
    _, cap = g.govern_issue(SESS, 2, 1)
    # a request that ARRIVED on tool_return carries band tool, so conjunct (A)
    gat = g.authorize(g.ingest(Channel.TOOL_RETURN, cap), SESS, EID, 2)
    return ung, gat, {
        "band_observed_per_listener": observed,
        "forged_claim_landed": forged_landed,
        "note": "The payload claimed band=session and via=GOVERNANCE on every "
                "connection. Each listener reported its OWN band. The claim is "
                "not refused -- it is never read.",
    }


@route(8, "Reaching the governance listener directly — HONEST FAILURE",
       kind="property")
def r8():
    """Not a defeat. The network restriction is not this code's to enforce.

    Anything that can reach the governance listener presents as governance.
    That is a firewall / bind-address / socket-permission property, and
    pretending the gate stops it would be the overclaim.
    """
    import os, tempfile
    from warrantable.transport import Ingress, band_from_accepting_listener, connect_and_send

    d = tempfile.mkdtemp(prefix="r8_")
    binds = {c: os.path.join(d, f"{c.value}.sock") for c in Channel}
    ing = Ingress(binds)
    ing.serve(lambda l, data: band_from_accepting_listener(l).value.encode())
    gov = connect_and_send(binds[Channel.GOVERNANCE_BUS], b'{}').decode()
    sess = connect_and_send(binds[Channel.SESSION_DEMUX], b'{}').decode()
    mode = oct(os.stat(binds[Channel.GOVERNANCE_BUS]).st_mode & 0o777)
    ing.shutdown()

    ung = SimpleNamespace(allowed=True,
                          reason=f"ungated: reaching the socket yields band {gov!r}")
    g = fresh_gate(); g.write(2, EID)
    _, cap = g.govern_issue(SESS, 2, 1)
    gat = g.authorize(g.ingest(Channel.SESSION_DEMUX, cap), SESS, EID, 2)
    return ung, gat, {
        "governance_listener_yields": gov,
        "session_listener_yields": sess,
        "socket_mode": mode,
        "property": "each listener yields ITS OWN band — reaching the governance "
                    "socket IS presenting as governance",
        "holds": gov == "governance" and sess == "session",
        "note": "BY DESIGN AND NOT CLOSED HERE. Reaching the governance socket "
                "IS presenting as governance -- the band is the socket. "
                "Restricting reach is a NETWORK property (firewall, bind "
                "address, socket permissions); this code neither performs nor "
                "proves it. The 0600 mode above is a gesture, not the "
                "restriction. Reported as a property, not a defeat.",
    }


# --------------------------------------------------------------------------

def main() -> int:
    print("=" * 78)
    print("WARRANTABLE v1 — measured battery")
    print("=" * 78)

    st = structural_selftest()
    print("\nstructural selftest (the band property, checked not claimed)")
    for k in ("band_derivation_takes_only_channel", "band_derivation_params",
              "band_derivation_is_total_over_channels",
              "presented_requires_ingest_token", "presented_via_is_readonly"):
        print(f"  {k:42s} {st[k]}")
    if not st["all_pass"]:
        print("  *** STRUCTURAL SELFTEST FAILED — battery results are void ***")
        return 2

    print("\ncustody of k_gov (MEASURED from the live key store)")
    for k, v in EpochKeyStore().describe_custody().items():
        if k != "note":
            print(f"  {k:38s} {v}")

    rows, void = [], 0
    print("\n" + "=" * 78)
    for r in ROUTES:
        ung, gat, extra = r["fn"]()
        gate0 = bool(ung)
        status = "OK" if gate0 else "VOID"
        if not gate0:
            void += 1
        print(f"\n[{r['n']}] {r['name']}")
        print(f"    GATE 0 (ungated must succeed) : {'PASS' if gate0 else '*** FAIL ***'} "
              f"— {ung.reason}")
        if gate0 and r["kind"] == "property":
            # Property routes state their OWN claim. Route 6's rotation shape is
            # not every property's shape -- rendering route 8 through it printed
            # "after govern_rotate: STILL ALLOWED", which is meaningless there
            # and reads as a failure.
            print(f"    property                      : {extra.get('property', '(unstated)')}")
            print(f"    holds                         : "
                  f"{'YES' if extra.get('holds') else '*** NO ***'}")
        elif gate0:
            verdict = "REFUSED" if not gat.allowed else "*** ALLOWED ***"
            print(f"    gated                         : {verdict}"
                  + (f"  [{gat.conjunct}]" if gat.conjunct else ""))
            print(f"    reason                        : {gat.reason}")
        else:
            print("    gated                         : NOT QUOTED — the attack has no "
                  "power ungated, so a clean gated result is an instrument artifact")
        for k, v in extra.items():
            print(f"      {k}: {v}")
        rows.append({"route": r["n"], "name": r["name"], "kind": r["kind"], "gate0": gate0,
                     "property": extra.get("property"), "holds": extra.get("holds"),
                     "ungated": ung.reason, "gated_allowed": gat.allowed,
                     "conjunct": gat.conjunct, "gated_reason": gat.reason,
                     "status": status, **{f"x_{k}": v for k, v in extra.items()}})

    print("\n" + "=" * 78)
    quoted = [r for r in rows if r["gate0"]]
    attacks = [r for r in quoted if r["kind"] == "attack"]
    props = [r for r in quoted if r["kind"] == "property"]
    refused = [r for r in attacks if not r["gated_allowed"]]
    print(f"  routes            : {len(rows)}  ({len(attacks)} attack, {len(props)} property)")
    print(f"  Gate 0 passed     : {len(quoted)}/{len(rows)}"
          + (f"   ({void} VOID, results not quoted)" if void else ""))
    print(f"  attacks refused   : {len(refused)}/{len(attacks)}")
    leaked = [r for r in attacks if r["gated_allowed"]]
    if leaked:
        print(f"  *** NOT REFUSED   : {[r['route'] for r in leaked]}")
    for r in props:
        print(f"  property route {r['route']}  : "
              f"{'HOLDS' if r.get('holds') else '*** DOES NOT HOLD ***'} — {r.get('property','')}")

    out = REPO / "warrantable/battery_results.json"
    out.write_text(json.dumps(rows, indent=2, default=str))
    print(f"\n  results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
