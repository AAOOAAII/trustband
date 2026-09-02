# F2 — runaway protection. Gates registered before the code.

**Registered 2026-09-02, before any implementation. Base: F1 at `4b87cb9`.**

## A correction to the plan

The build map says budget exhaustion already exists and this is "surfacing it
as a circuit breaker". It is not. `gov_budget` is the **capability-minting**
budget from the Verus model — how many capabilities may be issued in an epoch —
and it lives in `Gate`. It has nothing to do with how many tool calls a session
has made or what they cost.

So F2 is new mechanism at the `Guard` layer, not a new view onto an old one.
Still small, but the estimate rested on a false premise and the premise is
recorded here rather than quietly absorbed.

## Why it is worth building anyway

It is the first thing a new user meets that makes the tool feel like it is on
their side rather than in their way. Every other refusal this product issues is
about provenance, which is a claim the user has to be persuaded of. A call cap
is a thing they already wanted.

## Registered predictions

**P-F2.1 — a cap refuses at the cap, not before or after.** With
`max_calls: N`, call N is allowed and call N+1 is refused. Off-by-one here is
the difference between a circuit breaker and a nuisance.

**P-F2.2 — the counter is per session.** Two sessions under one policy each get
their own budget; exhausting one leaves the other untouched. Provenance is
already scoped this way and a shared counter would let one tenant deny another.

**P-F2.3 — it survives process boundaries.** The adapter is a subprocess per
call, so an in-memory counter counts to one forever. State is rebuilt from the
durable record, which is why F0 had to come first.

**P-F2.4 — a cap refusal is legible and distinguishable.** The reason names the
cap and the count, `trace` renders it, and it is not mistakable for a
provenance refusal. A user who hits a cap must not think their policy is wrong.

**P-F2.5 — no cap configured means no behaviour change.** Decisions are
byte-identical to F1 when the policy has no `session` section. Every existing
gate still passes: conformance 18/18, policy demo 87/87, battery 6/6.

**P-F2.6 — a cap is refusable but never silently fatal.** Hitting a cap refuses
the call with a reason a person can act on; it does not crash the hook, does not
corrupt the log, and does not change what happens on the next session.

## Scope

In: `session: {max_calls: N}` in the policy, counted from the durable record,
refusing when exceeded, surfaced in `trace`.

Out, and named: `max_spend` — deferred to F3, because spend needs token
accounting and pricing that does not exist yet, and a spend cap computed from a
price table nobody has stated would be a confidently wrong number. Not
rate limiting over time windows. Not global caps across sessions.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
