"""Render a session from the decision record, and nothing else.

WHY THIS IS THE FIRST THING A NEW USER MEETS
    The honest shadow report on legitimate work is zero refusals -- measured
    twice, at 400 calls through the published package and 0.7% across 1,119
    real calls where every refusal was a tool missing from the starter policy.
    That is the zero-false-positive property working as designed, and it means
    this view carries the whole first hour. A flat list of allowed calls is
    `--verbose` and nobody keeps that installed.

    So the job is to show provenance being *informative*, not merely tracked:
    the band each argument arrived with, and where that differs from what a
    reader would assume.

IT READS THE LOG AND ONLY THE LOG
    No policy file, no live Guard, no recomputing a decision. A trace that
    derived anything could disagree with the audit precisely when the audit
    matters. If a field is not in the record, this says so rather than
    inferring it -- which is also why the deciding rule appears as the reason
    text it was recorded as, never as a rule id the record does not carry.

THE CHAIN IS CHECKED WHILE RENDERING
    A viewer that displays a tampered log as though it were intact is worse
    than no viewer, so every render ends with the chain's state and the first
    bad sequence number if there is one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from trustband.audit import AuditLog, entry_digest

#: Bands, ordered as the lattice orders them: GOVERNANCE > SESSION > TOOL > USER.
#: A reader assumes an argument is something the user or the session supplied;
#: `tool` and below is the case worth pointing at.
_NOTEWORTHY = ("tool", "user")


def _load(path: Path) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """Entries as bodies, plus the first sequence number that breaks the chain.

    Verification happens here rather than in a separate command because a
    reader should not have to opt in to being told the record was edited.
    """
    log = AuditLog(path)
    first_bad: Optional[int] = None
    for i, e in enumerate(log.entries):
        if e.digest != entry_digest(e.seq, e.prev, e.body):
            first_bad = e.seq
            break
        if i and e.prev != log.entries[i - 1].digest:
            first_bad = e.seq
            break
    return [e.body for e in log.entries], first_bad


def _short(value: Any, width: int = 58) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    s = " ".join(s.split())
    return s if len(s) <= width else s[: width - 1] + "…"


def render(path: Path, session: Optional[str] = None,
           last: Optional[int] = None) -> List[str]:
    """The trace, as lines. Returned rather than printed so it can be tested."""
    bodies, first_bad = _load(path)
    if not bodies:
        return [f"  no decisions recorded yet in {path}",
                "  run the agent with the hook installed, then look again."]

    sessions = sorted({b.get("session", "?") for b in bodies})
    if session is None and len(sessions) == 1:
        session = sessions[0]

    rows = [b for b in bodies if session is None or b.get("session") == session]
    total = len(rows)
    if last is not None and last < len(rows):
        rows = rows[-last:]

    out: List[str] = []
    head = f"  session {session or '(all)'} — {total} recorded event(s)"
    if last is not None and total > len(rows):
        head += f", showing the last {len(rows)}"
    out.append(head)
    if session is None and len(sessions) > 1:
        out.append(f"  sessions in this log: {', '.join(sessions)}")
    out.append("")

    decisions = refused = noteworthy = 0
    nonlocal_failed = [0]
    for b in rows:
        if b.get("event") == "result":
            out.append(f"  ← {b.get('tool','?'):<14} returned  "
                       f"band={b.get('band','?')}  "
                       f"{b.get('strings_remembered',0)} string(s) remembered")
            for c in (b.get("contracts") or []):
                mark = "ok " if c["held"] else "NO "
                blk = " [blocking]" if c.get("blocking") else ""
                out.append(f"        {mark} contract {c['name']}{blk}: "
                           f"{c['reason']}")
                if not c["held"]:
                    nonlocal_failed[0] += 1
            continue

        decisions += 1
        allowed = bool(b.get("allowed"))
        if not allowed:
            refused += 1
        mark = "  ok " if allowed else "  NO "
        ms = b.get("ms")
        out.append(f"{mark}→ {b.get('tool','?'):<14} "
                   f"{'allowed' if allowed else 'REFUSED'}"
                   f"{'' if ms is None else f'   {ms} ms'}")

        bands = b.get("bands") or {}
        args = b.get("args") or {}
        for name in sorted(set(bands) | set(args)):
            band = bands.get(name, "—")
            flag = "  ←" if band in _NOTEWORTHY else "   "
            if band in _NOTEWORTHY:
                noteworthy += 1
            out.append(f"        {name:<16} band={band:<11} "
                       f"{_short(args.get(name, ''))}{flag}")
        if not allowed:
            # P-F1.4: legible without the policy in hand.
            out.append(f"        why: {b.get('reason','(not recorded)')}")
            if b.get("confirmable"):
                out.append("        a person could have approved this")
        out.append("")

    out.append(f"  {decisions} decision(s), {refused} refused, "
               f"{noteworthy} argument(s) not session-authored")
    if nonlocal_failed[0]:
        out.append(f"  {nonlocal_failed[0]} contract(s) failed — these are "
                   f"claims about the WORK, not about permission; the calls "
                   f"themselves were allowed.")
    if noteworthy:
        out.append("  ← marks an argument that did not come from the session: "
                   "text a tool returned, which a policy can refuse.")
    if first_bad is None:
        out.append(f"  chain intact across {len(bodies)} entries "
                   f"(a truncated tail would not show here; sealing covers that)")
    else:
        out.append(f"  CHAIN BROKEN at seq {first_bad} — this record has been "
                   f"edited or reordered. Do not trust anything above it.")
    return out


def main(path: Path, session: Optional[str] = None,
         last: Optional[int] = None) -> int:
    for line in render(path, session, last):
        print(line)
    return 0
