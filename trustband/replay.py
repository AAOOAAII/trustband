"""Re-run a recorded session against a candidate policy.

WHY THIS IS THE DANGEROUS ONE
    Replay answers "what would this policy have done to last week's traffic",
    and a person adopts a policy on that number. A replay reading an
    insufficient record does not fail -- it produces confident wrong answers
    and nothing about the output looks different.

    So the first thing it does is reproduce reality: replaying the RECORDED
    policy must reproduce the RECORDED decisions. `verify()` does that, and a
    caller that skips it is trusting arithmetic nobody checked.

WHY RESULT EVENTS ARE NOT OPTIONAL
    A replay that reads only decisions answers from an empty provenance store.
    Every tool-derived argument then looks session-authored, every taint
    refusal disappears, and the candidate policy looks permissive and safe.
    That failure is silent and flattering, which is the worst combination, so
    result events are replayed in order and their absence is an error rather
    than a quiet zero.

READ-ONLY
    No audit path, no notifier, no mutation of a live store. Replaying a week
    of traffic must not append an entry or alert anyone.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from trustband.audit import AuditLog
from trustband.gate import Band
from trustband.guard import Guard, ToolCall

_BAND = {b.value: b for b in Band}


@dataclass
class Change:
    seq: int
    tool: str
    was_allowed: bool
    now_allowed: bool
    was_grant: Optional[int]
    now_grant: Optional[int]
    reason: str
    args: Dict[str, Any]


def events(path: Path) -> List[Dict[str, Any]]:
    """Every recorded event, in order. Order is the whole point: provenance
    depends on what came before, so a partial or reordered read is wrong."""
    return [e.body for e in AuditLog(path).entries]


def _run(rows: List[Dict[str, Any]], policy: Dict[str, Any]
         ) -> List[Tuple[int, Dict[str, Any], Any]]:
    """Decisions this policy would make, replaying results into the store.

    Shadow mode deliberately: replay must never refuse anything for real, and
    a shadow Guard records what it would have done, which is exactly the
    question. `audit_path` is left unset so nothing is written.
    """
    g = Guard(policy, mode="shadow")          # no audit_path: read-only
    out: List[Tuple[int, Dict[str, Any], Any]] = []
    for i, b in enumerate(rows):
        session = b.get("session") or "replay"
        if b.get("event") == "result":
            # The store is rebuilt from what tools actually returned. Without
            # this the replay answers from an empty store and every taint
            # refusal silently vanishes.
            g.after_tool_result(
                ToolCall(session=session, tool=b.get("tool", "?"), args={}),
                b.get("text") or "", _BAND.get(b.get("band"), Band.TOOL))
            continue
        call = ToolCall(session=session, tool=b.get("tool", "?"),
                        args=dict(b.get("args") or {}),
                        tier=int(b.get("tier", 2)))
        d = g.before_tool_call(call)
        # In shadow the Decision is always allowed; the recorded intent is in
        # the shadow log, which is what a replay must read.
        rec = g.shadow_log[-1] if g.shadow_log else None
        allowed = True if rec is None else bool(rec.get("would_allow"))
        out.append((i, b, (allowed, getattr(g.issuer, "deciding_grant", None))))
    return out


class InsufficientRecord(Exception):
    """The log cannot support a replay, and a number from it would be wrong.

    Result events carry `text` only when `record_results` is enabled. Without
    it the provenance store is empty on replay, every tool-derived argument
    looks session-authored, and every taint refusal silently disappears --
    which makes any candidate policy look permissive and safe. Refusing is the
    only honest answer; under-reporting is the flattering one.
    """


def _require_sufficient(rows: List[Dict[str, Any]]) -> None:
    results = [b for b in rows if b.get("event") == "result"]
    if results and all(b.get("text") is None for b in results):
        raise InsufficientRecord(
            f"this log has {len(results)} result event(s) and none records what "
            f"the tool returned, so provenance cannot be rebuilt. Replay would "
            f"report fewer refusals than the truth. Set record_results.enabled "
            f"in the policy and replay a session recorded after that.")


def verify(path: Path, recorded_policy: Dict[str, Any]) -> Tuple[int, int, List[str]]:
    """P-F4.1. Replay the RECORDED policy and compare against the record.

    Returns (matched, total, mismatches). A replay that cannot reproduce what
    happened tells you nothing about what would have happened.
    """
    rows = events(path)
    _require_sufficient(rows)
    got = _run(rows, recorded_policy)
    matched = 0
    bad: List[str] = []
    for i, b, (allowed, grant) in got:
        want = bool(b.get("allowed"))
        if allowed == want:
            matched += 1
        else:
            bad.append(f"seq {i} {b.get('tool')}: recorded "
                       f"{'allow' if want else 'refuse'}, replay "
                       f"{'allow' if allowed else 'refuse'}")
    return matched, len(got), bad


def diff(path: Path, candidate: Dict[str, Any]) -> List[Change]:
    """What the candidate policy would have changed."""
    rows = events(path)
    _require_sufficient(rows)
    changes: List[Change] = []
    for i, b, (allowed, grant) in _run(rows, candidate):
        was = bool(b.get("allowed"))
        if allowed != was:
            changes.append(Change(
                seq=i, tool=b.get("tool", "?"), was_allowed=was,
                now_allowed=allowed, was_grant=b.get("grant"),
                now_grant=grant, reason=b.get("reason", ""),
                args=dict(b.get("args") or {})))
    return changes


def render(path: Path, candidate: Dict[str, Any],
           recorded_policy: Optional[Dict[str, Any]] = None) -> List[str]:
    out: List[str] = []
    rows = events(path)
    decisions = [b for b in rows if b.get("event") == "decision"]
    if not decisions:
        return [f"  no decisions recorded in {path}"]

    if recorded_policy is not None:
        m, n, bad = verify(path, recorded_policy)
        out.append(f"  self-check: the recorded policy reproduces {m}/{n} "
                   f"recorded decisions")
        if bad:
            out.append("  REPLAY CANNOT REPRODUCE THE RECORD. Nothing below "
                       "means anything until this is explained:")
            out.extend(f"    {b}" for b in bad[:5])
            return out
        out.append("")

    changes = diff(path, candidate)
    more = [c for c in changes if c.was_allowed and not c.now_allowed]
    less = [c for c in changes if not c.was_allowed and c.now_allowed]
    out.append(f"  {len(decisions)} recorded decision(s); the candidate policy "
               f"changes {len(changes)}")
    out.append(f"    {len(more)} that were allowed would be refused")
    out.append(f"    {len(less)} that were refused would be allowed")
    if changes:
        out.append("")
        for c in changes[:20]:
            arrow = "allow -> REFUSE" if not c.now_allowed else "refuse -> allow"
            out.append(f"    seq {c.seq:<4} {c.tool:<14} {arrow}"
                       f"   grant {c.was_grant} -> {c.now_grant}")
            for k, v in list(c.args.items())[:2]:
                out.append(f"          {k}={str(v)[:60]}")
        if len(changes) > 20:
            out.append(f"    … and {len(changes) - 20} more")
    return out
