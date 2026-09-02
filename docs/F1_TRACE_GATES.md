# F1 — `trustband trace`. Gates registered before the code.

**Registered 2026-09-02, before any trace implementation. Base: F0 at
`f867c43`, which made the record durable.**

## Why this one first

The honest shadow report on legitimate work is **0 refusals** — measured, twice:
400 calls through the published binary, and 0.7% across 1,119 real calls where
every refusal was a tool simply missing from the starter policy. That is the
zero-false-positive property working, and it means **`trace` carries the entire
first-hour experience**. Nothing else in the free tier shows a new user
anything on a day they are not attacked.

So the bar is not "renders the log". A flat list of allowed calls is `--verbose`
and nobody keeps that installed.

## The registered bar

**P-F1.1 — a first-time user can name what it tells them that `--verbose`
would not.** Concretely: for at least one line in a trace of ordinary work, the
band of an argument differs from what a reader would assume, and the trace shows
it. If a whole session renders with every argument at the same band, the trace
has shown provenance being *tracked* but never provenance being *informative*,
and F1 has not cleared this bar.

**P-F1.2 — every decision in the log appears exactly once.** Count of rendered
decisions equals count of decision entries. No silent filtering, no dedupe, no
truncation without saying so.

**P-F1.3 — the trace reads only the log.** No policy file, no live Guard, no
recomputation of a decision. If a field is absent from the record the trace says
so rather than deriving it — deriving would make the trace disagree with the
audit under exactly the conditions where the audit matters.

**P-F1.4 — refusals are legible without the policy in hand.** For a refused
call the trace shows the argument, its band, the band required, and the reason.
A user who has never opened `policy.json` can say why it was refused.

**P-F1.5 — chain state is surfaced, not assumed.** The trace states whether the
entries it rendered form a continuous chain, and names the first bad sequence
number if not. A viewer that renders a tampered log as though it were intact is
worse than no viewer.

**P-F1.6 — it stays a dependency-free stdlib tool.** No `rich`, no `textual`.
Zero dependencies is a shipped claim and a reason a security-minded reader
trusts the install.

## Scope

In: `trustband trace [--session S] [--home H] [--last N]`, a per-session tree
of result and decision events, argument bands, outcome, timing, and a chain
status line.

Out, and named so it is not assumed: cost (F3), replay against another policy
(F4), redaction (F5 — until then the trace prints argument values as recorded,
which is why F5 is not optional before anyone runs this on real traffic), OTel
(F6), colour themes, live tailing.

## The known gap this inherits

P-F0.5 is PARTIAL: the deciding rule is prose, not an identity. `trace` groups
by reason text and must not imply a rule id it does not have.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
