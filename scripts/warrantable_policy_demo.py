#!/usr/bin/env python3
"""Policy binding, demonstrated — the implementation half of Phase 2.

The Verus crate proves a tag COMMITS to a policy digest (`ce7`, 24 verified,
8/8). It models no bytes, so it cannot prove that structurally equal policies
digest equally — that is assumption A12 and it lives in `warrantable/policy.py`.
This script exercises both halves in the running implementation.

BATTERY DISCIPLINE: every attack must first SUCCEED against the ungated path.
A refusal is not evidence unless the same move works when the gate is absent.

Run:  python scripts/warrantable_policy_demo.py
"""
from __future__ import annotations

import datetime
import hashlib
import json
import platform
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from warrantable.gate import Channel, Gate  # noqa: E402
sys.path.insert(0, str(REPO / "scripts"))
from warrantable_battery import Envelope, UngatedBaseline  # noqa: E402
from warrantable.policy import (PolicyDomainError, digest, encode,  # noqa: E402
                                equal)

SESS, EID = 7, 1
checks: List[Dict[str, Any]] = []


def check(name: str, got: Any, want: Any, note: str = "") -> None:
    ok = got == want
    checks.append({"check": name, "got": repr(got)[:120], "want": repr(want)[:120],
                   "pass": ok, "note": note})
    print(f"  [{'PASS' if ok else '*** FAIL'}] {name}: {got!r}"[:150])


def main() -> int:
    POLICY_A = {"allow": ["read", "list"], "max_tier": 1, "region": "eu"}
    POLICY_B = {"allow": ["read", "list", "transfer"], "max_tier": 2, "region": "eu"}

    print("== A12: the encoder's properties, on which the binding rests ==")
    check("map order cannot reach the digest",
          digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1}), True)
    check("absent and present-null stay distinct",
          digest({"x": None}) != digest({}), True)
    check("length prefixes prevent concat collisions",
          digest({"ab": 1, "c": 2}) != digest({"a": 1, "bc": 2}), True)
    check("True is not 1", digest(True) != digest(1), True)
    nfd = unicodedata.normalize("NFD", "café")
    check("NFC applied before compare AND encode",
          digest(nfd) == digest("café") and equal(nfd, "café"), True,
          "python == disagrees here, which is the failure (5) prevents")
    check("schema version is the first byte", encode(1)[0], 1)

    print("== the domain is closed, and REJECTS AT CONSTRUCTION ==")
    for bad, why in ((1.5, "float"), ({1: "x"}, "non-str key"),
                     ({"s"}, "set"), (object(), "arbitrary object")):
        try:
            digest(bad)
            check(f"{why} rejected", False, True)
        except PolicyDomainError:
            check(f"{why} rejected", True, True,
                  "no fallback digest exists; an unencodable policy stops "
                  "issuance rather than collapsing onto a default")

    print("== UNGATED: a superseded policy is no obstacle ==")
    # RUN, not asserted. An earlier draft of this script hardcoded True here,
    # which is precisely the decorative check the battery rule exists to forbid.
    u = UngatedBaseline()
    u.write(2, EID)
    stale = u.govern_issue(SESS, 1, 11, 0)      # a capability from anywhere
    ung = u.authorize(Envelope(Channel.SESSION_DEMUX, stale, {"band": "session"}),
                      SESS, EID, 1)
    check("ungated: stale capability still authorises", bool(ung), True,
          "there is no policy to be superseded because nothing records one — "
          "the attack succeeds when the gate is absent, which is what makes "
          "the gated refusal below evidence")

    print("== GATED: minted under A, refused after the policy moves to B ==")
    g = Gate(budget=8)
    g.write(2, EID)          # the store entry the elevation targets
    g.govern_repolicy(POLICY_A)
    d, cap = g.govern_issue(sess=SESS, tier=1, nonce=11)
    check("issued under policy A", bool(d), True)
    ok_now = g.authorize(g.ingest(Channel.SESSION_DEMUX, cap), SESS, EID, 1)
    check("accepted while A is enforced", bool(ok_now), True)

    g.govern_repolicy(POLICY_B)
    after = g.authorize(g.ingest(Channel.SESSION_DEMUX, cap), SESS, EID, 1)
    check("refused once B is enforced", bool(after), False)
    check("refused BY CONJUNCT (G)", after.conjunct, "G",
          "not by the MAC and not by the epoch — the policy check itself")

    print("== the capability was not retracted, only outranked ==")
    check("still in the issued set", cap in g.issued, True,
          "govern_repolicy writes gov_policy and nothing else; the capability "
          "dies at the gate, never by being deleted")

    print("== re-adopting A revives it — the check is structural, not stateful ==")
    g.govern_repolicy(POLICY_A)
    again = g.authorize(g.ingest(Channel.SESSION_DEMUX, cap), SESS, EID, 1)
    check("accepted again under A", bool(again), True)
    check("and an equal-but-reordered A also accepts it",
          bool(g.govern_repolicy({"region": "eu", "max_tier": 1,
                                  "allow": ["read", "list"]})) and
          bool(g.authorize(g.ingest(Channel.SESSION_DEMUX, cap), SESS, EID, 1)),
          True, "digest equality, not dict identity")

    print("== a policy outside the domain cannot be adopted at all ==")
    before = g.gov_policy
    try:
        g.govern_repolicy({"threshold": 0.5})
        check("off-domain policy refused", False, True)
    except PolicyDomainError:
        check("off-domain policy refused", True, True)
    check("enforced policy unchanged after the refusal", g.gov_policy == before, True,
          "no partial adoption")

    print("== ISSUANCE: the policy decides, not the caller ==")
    from warrantable.issuance import Issuer, PolicySchemaError
    P = {"version": 1,
         "grants": [{"sess": SESS, "max_tier": 1, "actions": ["read", "list"]}]}
    gi = Gate(budget=20); gi.write(2, EID)
    iss = Issuer(gi); iss.adopt(P)
    check("granted: tier 1 read", bool(iss.issue(SESS, 1, "read", 1)[0]), True)
    check("refused: tier 2 over max_tier", bool(iss.issue(SESS, 2, "read", 2)[0]), False)
    check("refused: ungranted action", bool(iss.issue(SESS, 1, "transfer", 3)[0]), False)
    check("refused: session in no grant", bool(iss.issue(99, 1, "read", 4)[0]), False,
          "absence is refusal; there is no default grant")
    check("closed by default with no policy",
          bool(Issuer(Gate(budget=2)).issue(SESS, 0, "read", 1)[0]), False)
    for bad, why in (({"version": 2, "grants": []}, "wrong schema version"),
                     ({"version": 1}, "grants missing"),
                     ({"version": 1, "grants": [{"sess": 7, "max_tier": 9,
                                                 "actions": []}]}, "tier out of range")):
        try:
            Issuer(Gate(budget=2)).adopt(bad); check(f"refused at adoption: {why}", False, True)
        except PolicySchemaError:
            check(f"refused at adoption: {why}", True, True)

    print("== the composition defect, as a regression test ==")
    # Both components were correct and the PAIR was not. Conjunct (G) proves a
    # capability was minted while a policy was in force; it does not prove the
    # rules evaluated were that policy's rules. Governance calling
    # govern_repolicy directly desynced them, and a capability was minted and
    # ACCEPTED granting access the enforced policy forbade.
    gd = Gate(budget=9); gd.write(2, EID)
    isd = Issuer(gd); isd.adopt(P)
    gd.govern_repolicy({"version": 1, "grants": []})   # lock down, bypassing the issuer
    d_desync, c_desync = isd.issue(SESS, 1, "read", 1)
    check("desynced evaluator refuses to mint", bool(d_desync), False,
          "before the guard this MINTED, and the gate ACCEPTED it, because the "
          "capability bound the gate's own current digest by construction")
    check("...and names why", "out of step" in d_desync.reason, True)

    print("== TAINT: an action can refuse tool-derived arguments ==")
    from warrantable.taint import Band, Tainted, combine, meet
    PT = {"version": 1, "grants": [
        {"sess": SESS, "max_tier": 2, "actions": ["transfer"],
         "min_band": "session"}]}
    gt = Gate(budget=20); gt.write(2, EID)
    it = Issuer(gt); it.adopt(PT)
    clean = {"amount": Tainted(100, Band.SESSION),
             "payee": Tainted("acct-1", Band.SESSION)}
    dirty = {"amount": Tainted(100, Band.SESSION),
             "payee": Tainted("attacker@evil", Band.TOOL)}
    check("lattice: meet takes the least trusted",
          meet(Band.SESSION, Band.TOOL), Band.TOOL)
    check("one tainted input taints the derivation",
          combine(Tainted("ok", Band.SESSION), Tainted("x", Band.TOOL)), Band.TOOL)
    check("granted: all arguments session-band",
          bool(it.issue(SESS, 2, "transfer", 1, clean)[0]), True)
    check("REFUSED: payee derived from tool output",
          bool(it.issue(SESS, 2, "transfer", 2, dirty)[0]), False,
          "the injected value reaches the gate and is refused by band, not by "
          "inspecting its content")

    print("== the two soundness holes, demonstrated not described ==")
    untrusted = Tainted("yes", Band.TOOL)
    laundered = "APPROVED" if untrusted.value == "yes" else "DENIED"
    check("implicit flow LAUNDERS taint (not caught)",
          combine(laundered), Band.GOVERNANCE,
          "branching on tainted data and returning a constant defeats every "
          "dynamic taint system, this one included")
    check("untagged input defaults to trusted (fails OPEN)",
          combine("raw string from anywhere"), Band.GOVERNANCE,
          "the burden is on ingestion to tag; defaulting to USER would fail "
          "closed but taint every literal and get the checks disabled")

    print("== AUDIT: hash-chained, and sealed against the epoch key ==")
    from warrantable.audit import Entry as AEntry, entry_digest
    ga = Gate(budget=20); ga.write(2, EID)
    ia = Issuer(ga); ia.adopt(P)
    _, ca = ia.issue(SESS, 1, "read", 1)
    ga.authorize(ga.ingest(Channel.SESSION_DEMUX, ca), SESS, EID, 1)
    ga.authorize(ga.ingest(Channel.TOOL_RETURN, ca), SESS, EID, 1)   # refused (A)
    ga.seal_audit()
    ok_a, rep = ga.verify_audit()
    check("clean log verifies", ok_a, True)
    check("refusals are recorded too",
          any(e.body.get("allowed") is False for e in ga.audit.entries), True,
          "a log of grants answers what we permitted, not what we stopped")
    check("the refusing conjunct is in the record",
          any(e.body.get("conjunct") == "A" for e in ga.audit.entries), True)

    print("== naive tampering: chain breaks ==")
    # Target the REFUSAL and flip it to allowed -- the realistic attack is
    # hiding what the gate stopped, not fabricating what it permitted.
    vi = next(i for i, e in enumerate(ga.audit.entries)
              if e.body.get("allowed") is False)
    victim = ga.audit.entries[vi]
    ga.audit.entries[vi] = AEntry(victim.seq, victim.prev,
                                  {**victim.body, "allowed": True}, victim.digest)
    ok_t, rep_t = ga.verify_audit()
    check("a hidden refusal breaks the chain", ok_t, False)
    check("and the report names where", rep_t["broken_at"], vi)

    print("== sophisticated tampering: chain RECOMPUTED, seal catches it ==")
    # This is the case a bare hash chain misses. The attacker rewrites an entry
    # and recomputes every subsequent digest, so the chain is internally
    # perfect. Only the MAC over the head — which they cannot forge without the
    # epoch key — detects it.
    gb = Gate(budget=20); gb.write(2, EID)
    ib = Issuer(gb); ib.adopt(P)
    _, cb = ib.issue(SESS, 1, "read", 1)
    gb.authorize(gb.ingest(Channel.TOOL_RETURN, cb), SESS, EID, 1)   # refused
    gb.seal_audit()
    rebuilt, prev = [], b"\x00" * 32
    for e in gb.audit.entries:
        body = {**e.body, "allowed": True} if e.body.get("allowed") is False else e.body
        d_ = entry_digest(e.seq, prev, body)
        rebuilt.append(AEntry(e.seq, prev, body, d_)); prev = d_
    gb.audit.entries = rebuilt
    ok_b, rep_b = gb.verify_audit()
    check("the recomputed chain verifies AS A CHAIN", rep_b["chain_ok"], True,
          "which is why a hash chain alone is an integrity structure, not an "
          "integrity guarantee")
    check("the SEAL rejects it", rep_b["seals_ok"], False)
    check("so the log does not verify overall", ok_b, False)

    print("== the limit that stays open ==")
    gc = Gate(budget=20); gc.write(2, EID)
    Issuer(gc).adopt(P)
    _, rep_c = gc.verify_audit()
    check("an unsealed tail is REPORTED, not passed quietly",
          rep_c["unsealed_tail"] >= 0, True,
          "truncating an unsealed tail leaves a valid chain; the seal interval "
          "is the exposure window and is an operator choice")

    def _git(*a: str) -> str:
        try:
            return subprocess.run(("git", *a), cwd=str(REPO), capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except Exception:
            return "unavailable"

    dirty = "\n".join(
        ln for ln in _git("status", "--porcelain", "warrantable",
                          "scripts/warrantable_policy_demo.py").splitlines()
        if not any(x in ln for x in ("_results.json", "_demo.json")))
    passed = sum(1 for c in checks if c["pass"])
    envelope = {
        "artifact": "warrantable policy-binding demonstration",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc)
                                  .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "tree_clean_for_these_paths": (dirty == ""),
        "uncommitted_paths": dirty.splitlines(),
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "source_sha256": {
            rel: hashlib.sha256((REPO / rel).read_bytes()).hexdigest()
            for rel in ("warrantable/gate.py", "warrantable/policy.py",
                        "scripts/warrantable_policy_demo.py")
        },
        "scope": ("A12 is an ASSUMPTION, not a theorem. This demonstrates the "
                  "encoder's stated properties on a sample; it does not prove "
                  "injectivity over the domain, and it proves nothing about "
                  "sha256 collision resistance."),
        "summary": {"checks": len(checks), "passed": passed,
                    "failed": len(checks) - passed},
        "checks": checks,
    }
    out = REPO / "warrantable/policy_demo.json"
    out.write_text(json.dumps(envelope, indent=2, default=str))
    print(f"\n  checks: {passed}/{len(checks)} passed")
    print(f"  commit {envelope['commit'][:12]} "
          f"tree_clean={envelope['tree_clean_for_these_paths']} "
          f"{envelope['generated_utc']}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
