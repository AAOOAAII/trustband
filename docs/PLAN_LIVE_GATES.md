# Plan-then-execute under a live agent — gates before the run

**Registered 2026-09-02, before the harness. Base: `5475760`.**

## The gap

Every plan result so far is at the gate: a `Guard` was handed calls and asked
what it would decide. `PLAN_RESULT.md` named the limit itself — *"untested
against a live agent. Whether a model will operate usefully under a fixed plan
is a utility question and is not measured."*

That question decides whether the mechanism is usable. A defence that refuses
the attack and also refuses the work is not a defence, it is an outage. The
AgentDojo arc already measured that trade for bands; nothing has measured it
for plans.

## Registered predictions

**P-PL1 — a planned task completes.** With a plan naming the destinations the
task needs, the agent finishes the benign task at the same rate as with no plan
at all. If a plan costs benign completions, the number is reported, not
explained.

**P-PL2 — an injected action outside the plan is refused, live.** The agent is
given a page carrying an injection to a destination the plan does not name, and
the gate refuses it in the loop rather than in a unit test.

**P-PL3 — the refusal does not derail the task.** After a plan refusal the
agent still completes the benign work. A gate that turns one refusal into a
dead session is worse than one that blocks nothing, because the operator turns
it off the same day.

**P-PL4 — utility cost stated as a number.** Runs with plan and without, same
task, same model, same seed conditions. Whatever the difference is, it is
reported. A plan that costs nothing is suspicious; a plan that costs everything
is unusable; either way the number goes in the result.

**P-PL5 — scope stated before the numbers.** Qwen2.5-7B via ollama, one task
shape, N runs. Not comparable to the 14B AgentDojo figures, and no number here
may be placed beside one.

## Out of scope

Whether a frontier model behaves the same. Multi-step plans with branching.
Plan amendment. Any claim about swarms.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
