# Hosted alert delivery — alerts ride the approvals path. Gates before the code.

**Registered 2026-09-05, before any implementation. The second half of the
Unattended add-on: the same free events, delivered by our service to the
phone that approvals already reach.**

## What this is

Phase 8a made alerts free: a webhook per event class, spooled off the
decision path, drained by whoever is alive. The destination was always the
operator's own endpoint. This adds one more destination value, `hosted`,
meaning our service. The spool, the drain, the classes, the redacted
payload and the shadow rule are unchanged; only where a job goes differs.

On the service, a hosted alert is stored for the tenant and sent to every
Telegram chat linked to the account, as a message with the one-line text
and the event beneath it. No Telegram linked: stored, and shown on the
account page under Recent alerts. Email is not used for per-event alerts
on purpose; a refusal a minute is a channel nobody keeps.

## What it is not

- **Not a change to the decision path.** `fire()` still writes one file and
  returns. Whether the file says `hosted` or an `https://` URL costs the
  gate the same.
- **Not a key in the spool.** A spooled job says `hosted`; the drainer reads
  the key from the config beside the spool at delivery time. The key never
  sits in a spool file, and the guard's source still mentions no key.
- **Not a second alert path.** Everything fires from the recorded entry, as
  8a requires; the service receives what the audit log holds and nothing it
  does not.
- **Not approvals.** An alert tells; it never asks and never waits. The
  service cannot answer one. Same principle as F7's notifier.

## Registered predictions

**P-HA.1 — the decision path is unchanged.** `fire()` p50 with `hosted` is
within noise of `fire()` p50 with a webhook URL, both under the 1 ms gate
from P-P8a.1, measured in the same run.

**P-HA.2 — no key in the spool, ever.** Over a run that spools and drains
100 hosted alerts, no spool file, claimed file or failed-log line contains
the key. Delivery reads it from `config.json` at the moment of delivery.

**P-HA.3 — delivered where the person is.** With a Telegram chat linked, an
alert arrives as a message with the class line and the redacted event.
Without one, it is stored and `GET /account/alerts` lists it, newest first,
capped at 50. Both measured end to end with a real Guard against a local
server.

**P-HA.4 — entitlement is the only service-side gate.** An add-on key and a
Pro key are accepted. A bare `free` key meets 402 naming the add-on. An
install with `hosted` in policy and no key configured: the job is written
to `alerts_failed.jsonl` with a reason naming the add-on, nothing is
retried on the decision path, and every other alert destination still
delivers.

**P-HA.5 — what leaves the machine is the record.** A named secret in an
argument arrives at the service as `[redacted:…]`, in the text and in the
event, and is absent from the stored row and from the Telegram message.

**P-HA.6 — bounded.** A tenant is accepted up to 600 alerts per rolling
hour; beyond that the service answers 429, the drainer records the refusal
in the failed log, and the spool is emptied rather than retried forever. The
service stores at most the newest 1,000 per tenant.

**P-HA.7 — shadow does not alert.** Per-event classes never fire in shadow
whatever the destination; the shadow digest fires once, through `hosted`,
and arrives on Telegram. Same as P-P8a.4.

**P-HA.8 — nothing prior moves.** Webhook destinations behave byte-for-byte
as 8a measured. The full suite and conformance pass unchanged.

## What is measured, in order

1. P-HA.8 on the current code, so the baseline is on record.
2. Package: `hosted` as a destination, the drainer's key lookup, P-HA.1, 2,
   4 (no key), 7 with a fake endpoint.
3. Service: `/v1/alerts`, storage, the cap, Telegram delivery, P-HA.3, 4, 5,
   6 against a local server with a real Guard draining into it.
4. Account page: Recent alerts.
5. Public service: one alert through the Cittela tenant to a linked phone.
