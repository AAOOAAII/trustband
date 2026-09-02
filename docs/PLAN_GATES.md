# Plan-then-execute — gates before the code

**Registered 2026-09-02, before any implementation. Base: `host_in_set` at
`8292ebc`.**

## The gap this attacks

`host_in_set` closed scoped browser agents completely and left the other half
open, measured: a scoped allowlist refuses **4 of 5** of a general browse. An
allowlist must be written in advance, so an open-ended agent — research,
comparison, anything visiting hosts nobody enumerated — has no list to write.

The published paradigm ([Web Agents Should Adopt the Plan-Then-Execute
Paradigm](https://arxiv.org/pdf/2605.14290)) is: fix the plan before reading
untrusted content, then execute only that plan. A plan is written **per task**,
where an allowlist is written per deployment — which is exactly the case an
allowlist cannot cover.

## Why this is ours to build rather than borrow

The paradigm's security rests on the plan being authored before contamination.
Everyone can state that; almost nobody can **check** it, because checking it
requires knowing whether untrusted content had already entered the session.

Provenance knows. A plan fixed while the session holds no TOOL-banded content
is session-authored. A plan fixed afterwards may itself be the injection, and
a system without bands cannot tell the two apart.

That is the mechanism worth having, and it is not a value predicate — it is a
property of *when* the plan was set.

## Registered predictions

**P-PLAN1 — an action absent from the plan is refused**, even when its
arguments are clean and session-banded. Otherwise the plan constrains nothing.

**P-PLAN2 — an action in the plan is allowed**, so the mechanism is not simply
a deny-all wearing a plan's clothes.

**P-PLAN3 — a plan fixed after tool content entered the session is not
trusted.** This is the gate the phase exists for. Setting a plan on a
contaminated session must refuse, or mark the plan untrusted such that every
subsequent check refuses. A plan the attacker could have written is worse than
no plan, because it looks like a control.

**P-PLAN4 — it covers the case the allowlist could not.** On the general-browse
set where `host_in_set` refused 4/5 legitimate destinations, a plan naming
those destinations permits them and still refuses the injected one.

**P-PLAN5 — it composes.** Plan, bands and value predicates are independent
conjuncts; a refusal names which fired, and adding a plan weakens none of them.

**P-PLAN6 — nothing prior moves.** conformance 18/18, policy 87/87, battery
6/6, adapters, and the browser replay unchanged.

## Scope

In: fixing a plan for a session, refusing actions and destinations absent from
it, and refusing a plan fixed on an already-contaminated session.

Out, and named: generating the plan — that is the host's job, and a plan this
code invented would be a plan nobody authored; plan amendment mid-task, which
reopens exactly the hole this closes and needs its own gates; matching a plan
entry loosely, since fuzzy matching against a security control is where the
next bypass lives.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
