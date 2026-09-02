# F7 — the unattended agent. Gates registered before the code.

**Registered 2026-09-02, before any implementation.**

## The gap

`ConfirmationLedger` has `ask` and `approve`, no timeout, no unattended mode
and no default disposition. `confirm.py` states its own premise: *"turning a
refusal a human may answer into a question they can answer."* Every one of its
four safety properties assumes a person exists.

Cron agents, webhook handlers, CI jobs and queue workers have no person. For
them a `confirmable` refusal has nobody to ask, and the measured result that a
careful human recovers utility means nothing.

**This lands on the paying customer.** The Pro trigger is running agents for
someone else, and those are disproportionately unattended. The gap is in the
product's economics, not only its coverage.

## The decision belongs to the operator

Three dispositions, none right in general, and today there is no way to say
which you want:

- **deny** — safe; every confirmable refusal becomes a failed job
- **allow** — the job completes, no approval happened, and the record says so
  in those words rather than recording a confirmation that did not occur
- **queue** — the call waits for an answer or a timeout, which needs the hosted
  routing that is a Pro feature

## Notification, never alert-triggered action

A `notify` command runs on a confirmable refusal. It is how `deny` stops being
"your job silently failed".

**An alert must never trigger an approval.** `confirm.py` already names why:
an escape hatch that lets anything through becomes the attacker's target. An
alert that can auto-approve is `allow` with extra machinery and a false sense
of oversight — worse than choosing `allow` honestly, because it adds a
mechanism to aim at.

An alert that can be *answered* needs identity and an auditable answer. That is
Pro approval routing, and this is its justification.

## Registered predictions

**P-F7.1 — the disposition is explicit or the default is deny.** No policy
setting means deny, and the reason says the disposition was never configured.
A silent allow is the one outcome that must be impossible.

**P-F7.2 — `allow` records that nobody approved.** The audit entry distinguishes
"a person approved this" from "the unattended policy allowed it". Recording the
second as the first would forge an approval, which is the worst thing this
module could do.

**P-F7.3 — the notifier cannot change a decision.** Its exit code is ignored,
its output is not read as an answer, and a hanging or crashing notifier neither
blocks the agent nor alters the outcome. Same principle as an audit write
failure: a decision does not depend on a side channel.

**P-F7.4 — the notifier obeys shadow.** In shadow nothing was refused, so a
notifier that fired there would train people to ignore it. It runs only where a
refusal actually happened.

**P-F7.5 — a notifier is not a leak.** It receives the same redacted record the
log holds, never raw argument values. F5 redaction applies before the notifier
sees anything, checked by asserting a known secret never reaches it.

**P-F7.6 — enforcement is unchanged when unconfigured.** Decisions byte-identical
to today with no `unattended` section. Every existing gate still passes.

## Scope

In: `unattended: {on_confirmable: deny|allow, notify: "<command>"}`, the
disposition applied where a confirmable refusal has no answer, the notifier as
a subprocess receiving the redacted record on stdin.

Out, and named: `queue`, which needs hosted routing and belongs to Pro;
delivery to email, Slack or webhooks, which is delivery infrastructure and a
dependency; retry or backoff.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
