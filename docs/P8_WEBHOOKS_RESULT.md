# Phase 8a — free local alerts. Result.

**Run 2026-09-03 on `phase8-surfaces`, against the gates registered at
`P8_WEBHOOKS_GATES.md` before any code.**

## Verdict: PASS-WITH-DRIFT

Every registered prediction holds. The drift is that the first design failed
P-P8a.1 by a factor of sixty, and the second design's race was found by the
tests rather than by the gates that were supposed to anticipate it. Three
defects, all found before shipping, all recorded.

## The numbers

| | before | after |
|---|---|---|
| tests | 49 | **61** (12 new; the alerts suite run five times alone, 5/5) |
| conformance | 22/22 | 22/22 |
| decision-path cost of an alert | — | **0.16 ms** at p50, under the 1 ms gate |
| runtime dependencies | 0 | 0 |

## What each prediction did

**P-P8a.1 — delivery never delays a decision. PASS, after two designs.**
The first design started a detached interpreter per event so the decision
would never wait on an endpoint. It did not — and it cost **67 ms** per
refusal to start the interpreter, on the decision path, against a gate of
1 ms. Replaced by a spool: `fire()` creates one small file (atomic
`O_EXCL`, 0.16 ms) and returns. A second measurement then showed the
drainer thread, woken per event, putting its filesystem work on the GIL
inside the decision loop — a 3.8 ms tail. It now polls once a second and
is never woken by a decision. Measured against an endpoint that accepts and
never answers: p50 within the gate, five runs of five.

**P-P8a.2 — delivery failure never changes a decision. PASS.** Endpoint
with nothing listening: decisions byte-identical to a Guard with no alerts;
the failure written to `alerts_failed.jsonl` beside the log by whichever
process attempted delivery. The deciding process cannot see delivery
outcomes at all, which is the honest consequence of not waiting.

**P-P8a.3 — the payload is the redacted record. PASS.** A credential shape
planted in an argument does not appear anywhere in the delivered body.

**P-P8a.4 — it survives a subprocess-per-call adapter. PASS, and this is
where the third defect was.** A process that fires and `os._exit`s at once
leaves the job in the spool; the next process delivers it. But a *normal*
exit could kill the daemon thread after it had claimed a job and before the
POST completed, orphaning the claim where no drainer looked — one run in
three. Two mechanisms now: a claim carries its PID and any claim held by a
dead process is taken back by the next drainer (at-least-once after a
crash, stated); and a normal exit joins an in-flight delivery for at most
one second. A hard exit skips the join and falls to the recovery.

**P-P8a.5 — shadow does not alert per event. PASS.** Five would-refuse
decisions in shadow: nothing dispatched. `trustband shadow-report` sends
exactly one `shadow_digest` — *3 of 10 calls would have been refused* —
with the top reasons.

**P-P8a.6 — every class fires from the record. PASS.** `classify()` reads
the entry `_record` wrote and nothing else; the delivered `event` equals the
logged body exactly. `chain_break` is the one class that can only be seen
at load, and it fires from the resumed chain.

**P-P8a.7 — nothing prior moves. PASS.**

## Joins

| # | pair | result |
|---|---|---|
| 1 | webhook ↔ redactor | planted credential absent from the delivered body |
| 2 | webhook ↔ shadow | silent per event; one digest from the CLI |
| 3 | webhook ↔ hook exit | survives `os._exit`; delivered by the next process; a normal exit flushes ≤ 1 s |
| 4 | webhook ↔ hung endpoint | decision p50 within 1 ms of no-webhook |
| 5 | webhook ↔ audit | delivered event == logged entry |
| 6 | webhook ↔ entitlement | no entitlement term in the module; nothing hosted to consult |

## What this does not show

- **Delivery is not confirmed to the decider.** By design. Failures are on
  disk, not in the decision.
- **At-least-once after a crash.** A process killed between claim and
  completion may cause one duplicate when the claim is recovered.
- **No retries.** A dead endpoint gets one attempt per event and a line in
  the failed log. Retrying is the hosted add-on's job, if anyone asks for
  it.
- **`cost_threshold` fires from `trustband report`**, not from the Guard,
  because the Guard never sees cost.

## Next

The lockfile. Its shadow phase now has somewhere to put a drift flag.
