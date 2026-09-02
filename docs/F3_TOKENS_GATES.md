# F3 — token accounting. Gates registered before the code.

**Registered 2026-09-02, before any implementation. Base: F5 at `a6b93af`.**

## The plan said cost. It should say tokens.

The build map calls this "cost per call and per session". Three findings moved
it:

**Cost is not observable where trustband sits.** The hook is a tool-call
boundary, not a model boundary. The confirmed payload — `session_id`,
`prompt_id`, `transcript_path`, `cwd`, `permission_mode`, `effort`,
`hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, and `tool_output`
on PostToolUse — carries **no token or cost field at all**.

**Token count is the honest primitive.** It is true of every model, including a
local one where cost is zero and a price table is an insult. Cost is a
per-deployment overlay, not a property of the run.

**One rate would be wrong by 7.2×.** Measured on a real session: 97.6% of
3.84 billion tokens were cache *reads*, which price at roughly a tenth of
input, while output prices at roughly five times it. Pricing everything at one
rate overstates that session 7.2-fold. If cost is offered at all it needs four
rates per model, declared by the operator, never shipped.

## Where the numbers come from

`transcript_path` is present in both hook events and points at the session
JSONL, which carries real per-turn `input_tokens`, `output_tokens`,
`cache_creation_input_tokens`, `cache_read_input_tokens`, `model` and
`service_tier`. That is a measurement, not an estimate — and character-count
estimation is rejected outright, since it cannot see caching and would have
been ~7× wrong on the session above.

## Registered predictions

**P-F3.1 — token counts are read, never estimated.** No `len(text)/4` anywhere.
If usage is absent for a turn, the report says so rather than inventing a
number.

**P-F3.2 — the four classes are reported separately.** input, output, cache
write, cache read. Collapsing them to one total is the 7.2× error and is not
offered even as a convenience.

**P-F3.3 — transcript lag is measured, not assumed.** The docs say the
transcript is written asynchronously and may lag the live conversation. The
result document states the observed lag on real traffic and what the report
does about turns it cannot yet price.

**P-F3.4 — cost is optional and never invented.** With no rates configured the
report shows tokens and no money. An unpriced model shows tokens and says the
model is unpriced; it never borrows another model's rates. Every money figure
carries `priced_as_of` and the declared source.

**P-F3.5 — per-call attribution is a stated convention, never a measurement.**
Usage is recorded per model turn and a turn may contain several tool calls. Per
session and per turn are measured. If per-call is shown at all, the splitting
rule is named on screen.

**P-F3.6 — reading tokens never touches a decision.** The report is a read
path. Nothing in the gate consults it, and a missing or malformed transcript
changes no decision and crashes no hook.

## `max_tokens` replaces `max_spend`

F2 deferred `max_spend` and this supersedes it. Tokens are what actually run
out — the context window is a hard wall — and a token cap is meaningful for a
local model where spend is not. It reconciles from a number trustband can count
exactly rather than one derived through a rate table.

Registered with it: **P-F3.7 — a token cap obeys shadow.** Same discipline that
the call cap broke in F2: in shadow it records "would have refused" and permits.

## Scope

In: reading usage from the transcript, per-class totals per session and per
turn, optional declared-rate costing, `session.max_tokens`.

Out, and named: live gating on token spend before a call, because the
transcript lags and a cap on stale data blocks affordable work; pricing tables
in the package; estimating tokens for hosts that do not record them.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
