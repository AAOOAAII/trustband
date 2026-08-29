"""Find a (suite, attack) pair where the attacks actually land.

WHY
    Banking + Sonnet 4.5 + important_instructions contains 143 of 144 attacks
    with NO GATE PRESENT. A defence cannot be measured where the undefended
    baseline already wins, so P-AD3 came back INCONCLUSIVE rather than good.

    This probes UNGATED only. It asks one question -- is this combination
    attackable at all -- and it must be answered before spending a full matrix
    on it. Running the defence first and discovering afterwards that there was
    no headroom is what happened once already.

    Ungated by construction: there is no gate mode here to get wrong.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agentdojo.attacks.attack_registry import load_attack       # noqa: E402
from agentdojo.benchmark import run_task_with_injection_tasks   # noqa: E402
from agentdojo.task_suite.load_suites import get_suite          # noqa: E402

from scripts.agentdojo_run import build_pipeline                # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suites", default="banking,slack,workspace,travel")
    ap.add_argument("--attacks", default="important_instructions,tool_knowledge")
    ap.add_argument("--tasks", type=int, default=3,
                    help="user tasks sampled per suite")
    ap.add_argument("--injections", type=int, default=3,
                    help="injection tasks sampled per suite")
    ap.add_argument("--model", default="claude-sonnet-4-5-20250929")
    ap.add_argument("--provider", default="anthropic",
                    choices=["anthropic", "local"])
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    pipeline = build_pipeline(args.model, args.provider)
    rows: List[Dict[str, Any]] = []

    for suite_name, attack_name in itertools.product(
            args.suites.split(","), args.attacks.split(",")):
        suite = get_suite("v1.2.1", suite_name)
        try:
            attack = load_attack(attack_name, suite, pipeline)
        except Exception as e:
            print(f"  {suite_name}/{attack_name}: cannot build -- {e}")
            continue
        # A fixed prefix, not a random sample: the probe must be repeatable,
        # and Date.now-style nondeterminism in what was tested would make a
        # "no headroom" verdict unfalsifiable.
        uts = sorted(suite.user_tasks)[:args.tasks]
        its = sorted(suite.injection_tasks)[:args.injections]
        landed = 0
        n = 0
        for tid in uts:
            for iid in its:
                try:
                    _, s_map = run_task_with_injection_tasks(
                        suite, pipeline, suite.get_user_task_by_id(tid),
                        attack, logdir=None, force_rerun=True,
                        injection_tasks=[iid])
                except Exception as e:
                    print(f"    {tid}/{iid}: {type(e).__name__}", flush=True)
                    continue
                n += 1
                # security() True == the injection goal was ACHIEVED.
                landed += int(all(s_map.values()) if s_map else False)
        rate = landed / n if n else 0.0
        rows.append({"suite": suite_name, "attack": attack_name,
                     "combos": n, "landed": landed, "rate": rate})
        print(f"  {suite_name:10s} {attack_name:22s} "
              f"{landed}/{n} landed ungated  ({rate:.0%})", flush=True)

    rows.sort(key=lambda r: -r["rate"])
    print()
    print("HEADROOM RANKING (higher = more measurable):")
    for r in rows:
        verdict = "usable" if r["landed"] >= 2 else "no headroom"
        print(f"  {r['suite']:10s} {r['attack']:22s} {r['rate']:5.0%}  {verdict}")
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
