"""Replay a real Claude Code session through the hooks and see what breaks.

WHY REAL TRAFFIC
    Three of the four defects found on 2026-08-31 came from running the
    product, not from its test suites. The suites stop regressions; they do not
    find first-time design errors, because a test only asks the questions its
    author already thought of.

    A transcript asks every question the session actually asked -- a thousand
    Bash commands with real arguments, in real order, with the real results
    that flowed between them.

WHAT IT LOOKS FOR
    Crashes, non-JSON output (a hook that prints anything else blocks the
    agent), the would-refuse rate on genuine work, latency per call, and
    unbounded growth. It runs IN-PROCESS rather than spawning a subprocess per
    call, because a thousand subprocesses measures process startup, not us.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def events(transcript: Path) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Tool calls and their results, in the order they happened."""
    pending: Dict[str, Dict[str, Any]] = {}
    with transcript.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            msg = rec.get("message") or {}
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for c in content:
                if not isinstance(c, dict):
                    continue
                if c.get("type") == "tool_use":
                    ev = {"tool_name": c.get("name", "?"),
                          "tool_input": c.get("input") or {}}
                    pending[c.get("id", "")] = ev
                    yield "pre", ev
                elif c.get("type") == "tool_result":
                    prior = pending.pop(c.get("tool_use_id", ""), None)
                    if prior is None:
                        continue
                    yield "post", {**prior, "tool_response": c.get("content")}


def main() -> int:
    transcript = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not transcript or not transcript.exists():
        print("usage: dogfood_replay.py <transcript.jsonl>")
        return 2

    from trustband.gate import Band
    from trustband.guard import Guard, ToolCall

    policy = {"version": 1, "grants": [{
        "sess": "*", "max_tier": 2,
        "actions": ["Bash", "Read", "Write", "Edit", "Glob", "Grep",
                    "WebFetch", "WebSearch", "Task", "ToolSearch",
                    "SendUserFile", "TodoWrite", "NotebookEdit"],
        "arg_bands": {"command": "session"},
        "bands_when_present": True, "confirmable": True}]}
    guard = Guard(policy, mode="shadow")

    session = "replay"
    lat: List[float] = []
    n_pre = n_post = crashes = 0
    unknown_tool = 0
    would_refuse: List[Dict[str, Any]] = []

    for kind, ev in events(transcript):
        call = ToolCall(session=session, tool=ev["tool_name"],
                        args=ev["tool_input"] if isinstance(
                            ev["tool_input"], dict) else {})
        try:
            if kind == "pre":
                n_pre += 1
                t0 = time.perf_counter()
                d = guard.before_tool_call(call)
                lat.append((time.perf_counter() - t0) * 1000)
                if "would have refused" in d.reason:
                    would_refuse.append(
                        {"tool": call.tool, "reason": d.reason,
                         "args": sorted(call.args)[:4]})
                if "appears in no grant" in d.reason:
                    unknown_tool += 1
            else:
                n_post += 1
                guard.after_tool_result(call, ev.get("tool_response"),
                                        Band.TOOL)
        except Exception as e:                     # a crash blocks the agent
            crashes += 1
            if crashes <= 3:
                print(f"  CRASH on {kind} {call.tool}: "
                      f"{type(e).__name__}: {e}")

    store = guard._store(session)
    lat.sort()
    print(f"\n  replayed {n_pre} calls and {n_post} results")
    print(f"  crashes                : {crashes}")
    print(f"  would have refused     : {len(would_refuse)} "
          f"({len(would_refuse) / max(n_pre, 1):.1%})")
    print(f"    of which unknown tool: {unknown_tool}")
    if lat:
        print(f"  latency p50 / p99      : {lat[len(lat)//2]:.3f} ms / "
              f"{lat[int(len(lat)*0.99)]:.3f} ms   max {lat[-1]:.1f} ms")
    print(f"  provenance entries     : {len(store)} "
          f"(evictions {store.stats['evictions']})")
    print(f"  store stats            : {store.stats}")

    real = [w for w in would_refuse if "appears in no grant" not in w["reason"]]
    if real:
        print(f"\n  refusals that are NOT just an ungranted tool: {len(real)}")
        for w in real[:6]:
            print(f"    {w['tool']:12s} args={w['args']}")
            print(f"      {w['reason'][:96]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
