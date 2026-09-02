# F4 — replay. Gates registered before the code.

**Registered 2026-09-02, before any implementation. Base: `c98855b`.**

## Why this one is dangerous

Replay answers "what would this policy have done to last week's traffic?" —
and it answers with numbers a person will adopt a policy on. A replay reading
an insufficient record does not fail; it produces confident, wrong answers, and
nothing about the output looks different.

That is the `confirmable` defect at its worst: a field computed and never
written left a feature dead while its tests passed. Here the equivalent leaves
a feature *alive and lying*.

So the first gate is not "does it replay" but "does it reproduce reality".

## Registered predictions

**P-F4.1 — replaying the recorded policy reproduces the recorded decisions
exactly.** Same allow/refuse, same grant identity, decision for decision. **If
a replay cannot reproduce what actually happened, no number it produces about a
different policy means anything**, and the feature must not ship.

**P-F4.2 — provenance is rebuilt from the result events, in order.** A replay
that reads only decisions answers from an empty store: every tool-derived
argument looks session-authored and every taint refusal disappears. That failure
is silent and flattering — it makes any policy look permissive and safe — so it
is checked directly, by replaying a session whose refusals are all taint-based
and requiring them to reappear.

**P-F4.3 — monotonicity.** A strictly tighter policy refuses at least as much;
a strictly looser one refuses at most as much. Not a proof of correctness, but
a replay that violates it is wrong in a way arithmetic can catch.

**P-F4.4 — the diff names what changed and why.** Each changed decision reports
the tool, the argument, the old and new outcome, and the deciding grant on each
side. "17 more refusals" without which ones is not review, it is a number.

**P-F4.5 — replay is read-only.** It does not write the audit log, does not
mutate the live store, and does not fire notifiers. Replaying a week of traffic
must not alert anyone or append a single entry.

**P-F4.6 — nothing prior moves.**

## Scope

In: replaying a recorded session from `audit.jsonl` against a candidate policy,
reproducing provenance from result events, and a diff against what was
recorded.

Out, and named: replaying against a different *model* — the record holds what
the model did, not what another would do, and pretending otherwise is the
laundering case in reverse; editing history; partial replay from the middle of
a session, since provenance depends on everything before it.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
