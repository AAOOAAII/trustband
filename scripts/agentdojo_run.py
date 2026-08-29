"""Run AgentDojo's banking suite under warrantable, in four gate modes.

    off      no gate at all -- the undefended baseline
    permit   gate configured to permit everything -- P-AD4, the instrument check
    enforce  the policy decides -- P-AD2 utility, P-AD3 security
    shadow   full decision path, nothing refused -- diagnosis and policy inference

This exists as a committed script rather than an inline heredoc because the
first P-AD2 run was executed from a heredoc that no longer exists, so its
refusal reasons could not be recovered and the run had to be repeated. A number
that cannot be re-derived is not a measurement.

Usage:
    python scripts/agentdojo_run.py --mode enforce --out /tmp/ad_enforce3.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agentdojo.agent_pipeline import (AgentPipeline, InitQuery,  # noqa: E402
                                      SystemMessage, ToolsExecutionLoop,
                                      ToolsExecutor, AnthropicLLM)
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.benchmark import run_task_without_injection_tasks  # noqa: E402

from scripts.agentdojo_warrantable import TaintingRuntime, policy_for  # noqa: E402

# AgentDojo's NullLogger sets `logdir` only inside __enter__, but the benchmark
# reads it whether or not the logger was entered. A class attribute makes the
# unentered case behave as "no log directory" instead of raising. Without this
# every task dies before a single tool call and the run reports 0/16 -- which
# looks exactly like total refusal, and is not.
from agentdojo.logging import NullLogger  # noqa: E402
NullLogger.logdir = None

# --------------------------------------------------------------------------
# The choke point. Every tool result in AgentDojo flows through
# FunctionsRuntime.run_function, so patching it here bands all output and gates
# all calls with NO suite modification -- which is P-AD1's condition.
# --------------------------------------------------------------------------
_ORIGINAL = FunctionsRuntime.run_function
_HARNESS: List[Any] = [None]


def _patched(self, env, function, kwargs, raise_on_error=False):
    h = _HARNESS[0]
    if h is None:
        return _ORIGINAL(self, env, function, kwargs, raise_on_error)
    h.inner = _Bound(self, env)
    return h.run_function(env, function, kwargs, raise_on_error)


class _Bound:
    """Presents the real runtime to the wrapper without recursing into the patch."""

    def __init__(self, rt: Any, env: Any) -> None:
        self._rt = rt

    def run_function(self, env, function, kwargs, raise_on_error=False):
        return _ORIGINAL(self._rt, env, function, kwargs, raise_on_error)


FunctionsRuntime.run_function = _patched


def build_pipeline(model: str) -> AgentPipeline:
    llm = AnthropicLLM(__import__("anthropic").Anthropic(), model)
    p = AgentPipeline([SystemMessage("You are a helpful assistant."),
                       InitQuery(), llm,
                       ToolsExecutionLoop([ToolsExecutor(), llm])])
    p.name = "warrantable"
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["off", "permit", "enforce", "shadow"])
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--model", default="claude-sonnet-4-5-20250929")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    suite = get_suite("v1.2.1", args.suite)
    tools = [t.name for t in suite.tools]
    policy = policy_for(args.suite, tools, permit_all=(args.mode == "permit"))

    pipeline = build_pipeline(args.model)
    per_task: Dict[str, Any] = {}
    utility = 0
    refusals = 0
    reasons: List[Dict[str, Any]] = []
    shadow_obs: List[Dict[str, Any]] = []

    for tid, task in sorted(suite.user_tasks.items()):
        h = TaintingRuntime(None, policy,
                            gate_mode=("enforce" if args.mode == "shadow"
                                       else args.mode),
                            shadow=(args.mode == "shadow"))
        _HARNESS[0] = h
        try:
            u, _ = run_task_without_injection_tasks(
                suite, pipeline, task, logdir=None, force_rerun=True)
        except Exception as e:                       # a crash is not a refusal
            per_task[tid] = {"utility": False, "error": f"{type(e).__name__}: {e}"}
            _HARNESS[0] = None
            continue
        _HARNESS[0] = None

        refused = [e for e in h.events if not e.allowed]
        utility += int(u)
        refusals += len(refused)
        for e in refused:
            reasons.append({"task": tid, "function": e.function,
                            "reason": e.reason, "conjunct": e.conjunct,
                            "arg_bands": e.arg_bands})
        rec: Dict[str, Any] = {"utility": bool(u), "refusals": len(refused)}
        if h.rt is not None and h.rt.shadow:
            rep = h.rt.shadow_report()
            rec["shadow"] = rep
            shadow_obs.append({"task": tid, "report": rep,
                               "inferred": h.rt.infer_policy()})
        per_task[tid] = rec
        print(f"  {tid}: utility={'PASS' if u else 'fail'} "
              f"refusals={len(refused)}", flush=True)

    sha = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO,
                         capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                           capture_output=True, text=True).stdout.strip()
    out = {"mode": args.mode, "suite": args.suite, "model": args.model,
           "n": len(suite.user_tasks), "utility": utility,
           "refusals": refusals, "per_task": per_task,
           "refusal_reasons": reasons, "shadow": shadow_obs,
           "commit": sha, "tree_clean": not dirty}
    print(json.dumps({k: out[k] for k in
                      ("mode", "n", "utility", "refusals", "commit", "tree_clean")}))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"  wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
