# Phase 8a — free local alerts. Gates before the code.

**Registered 2026-09-03, before any implementation. Base: `aeeb154` on
`phase8-surfaces`. Sequenced before the lockfile because the lockfile's
shadow phase produces drift flags, and a flag nobody sees is the
computed-but-never-recorded defect in product form.**

## What this is

A webhook URL per event class in the policy file. Their destination, their
wiring, their machine on. Nothing of ours runs, so it is free — the line the
tiers document draws, made mechanical.

Event classes: `refusal`, `runaway` (a session cap fired), `chain_break`,
`cost_threshold`, `contract_failure`, `agent_revoked`, `lock_drift`.

## Registered predictions

**P-P8a.1 — delivery never delays a decision.** Measured against an endpoint
that accepts the connection and never answers: the p50 of `before_tool_call`
with a webhook configured is within 1 ms of the p50 without one. The
notifier that blocked with a timeout stalled every refusal by the full
timeout; this ships detached or not at all.

**P-P8a.2 — delivery failure never changes a decision.** Endpoint down,
endpoint returning 500, DNS failing, URL malformed: the decision is
byte-identical to the decision with no webhook, and the failure is recorded
on the Guard, never raised.

**P-P8a.3 — the payload is the redacted record.** A webhook sees exactly
what the audit log holds — `Redactor` on the way in, F5 first — never a raw
argument and never a raw refusal reason. Asserted by planting a credential
shape in an argument and reading the delivered body.

**P-P8a.4 — it survives a subprocess-per-call adapter.** The Claude Code
hook exits after one decision. A delivery started in a thread dies with it;
a delivery started in a detached process does not. Measured: the hook
process exits, the endpoint still receives the event.

**P-P8a.5 — shadow does not alert per event.** The standing rule holds: a
notifier that fires on hypothetical refusals trains people to ignore it.
Shadow produces one `shadow_digest` event per run of `trustband
shadow-report`, or per day, carrying counts and the top reasons — so the
onboarding week still delivers *would have refused: recipient came from a
web page* to the channel, once, not four hundred times.

**P-P8a.6 — every event class fires from the record, not from a second
code path.** The webhook reads the same entry `_record` wrote. A class that
needs its own branch to fire is a class that will drift from the log.

**P-P8a.7 — nothing prior moves.** 47 tests, 22/22, 8/8, 7/7, zero
dependencies. The transport is `urllib` in a detached interpreter.

## Joins

| # | pair | what must hold |
|---|---|---|
| 1 | webhook ↔ redactor | the body is redacted; the reason line is redacted |
| 2 | webhook ↔ shadow | per-event silence in shadow; the digest fires once |
| 3 | webhook ↔ hook exit | delivery outlives the process that decided |
| 4 | webhook ↔ hung endpoint | decision latency unchanged |
| 5 | webhook ↔ audit | the delivered event equals the logged entry |
| 6 | webhook ↔ entitlement | a URL works identically under every entitlement state; there is no hosted path here to consult |

## Out of scope

Hosted delivery, queueing while the machine is off, phone approval. Those are
the add-on, and they are built when the first person asks.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
