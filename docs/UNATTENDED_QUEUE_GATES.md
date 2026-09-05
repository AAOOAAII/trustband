# Unattended — `queue`: a person answers from their phone. Gates before the code.

**Registered 2026-09-05, before any implementation. The £14.99 add-on, built
as the smallest slice that someone would pay for: an agent that keeps working
overnight because you could approve from bed.**

## What this is

F7 left one disposition unbuilt. `unattended.on_confirmable` accepts `deny`
and `allow`; `queue` was refused at construction with "needs hosted routing".
This is the hosted routing.

With `queue`, a confirmable refusal does not end the call. The gate renders
the confirmation it already knows how to render — value, and where every
argument came from, by band — and posts that rendering to the service. The
service sends the person a link, by email and, if they linked it, by
Telegram. The link opens a page on trust.band that shows the same rendering
with Approve and Deny. The gate waits for the answer until a deadline it
chose before asking. Answer arrives: the call proceeds or refuses, and the
ledger records who decided. Deadline passes: the call refuses, and the ledger
records that somebody was asked and nobody answered.

The message is the courier. The page is where the decision happens. Nothing
that arrives in a chat message or an email can approve anything; only the
page, holding the single-use token, can post a decision. That is the design
point, chosen because a forged chat message is the 2026 attack on every other
mobile approval, and a page rendered from banded data is the defence.

## What it is not

- **Not a route into enforcement.** Enforcement never consults the
  entitlement. `queue` is a disposition the operator chose in policy; the
  service can answer a question the gate asked, and can do nothing the gate
  did not ask. A service that returns anything other than a decision bound
  to the request the gate sent is treated as no answer.
- **Not a trust upgrade for the service.** If the hosted service is
  compromised, an approval can be forged for a queued request — the same
  trust a Pro tenant already places in retention. The gate limits the blast
  radius: only requests the gate itself queued, only within the deadline,
  only for the digest it computed locally. It cannot be made to queue what
  the policy would have allowed, and it cannot be made to allow what the
  policy refused outright.
- **Not hosted alert delivery, push notifications, SMS, WhatsApp, or a
  native app.** Email and Telegram cost nothing per message, which is what
  keeps £14.99 honest. The others are a different pricing shape.
- **Not Pro.** One person, their own agents, one entitlement. No tenancy,
  no retention, no search. An add-on key cannot `sync`.

## Registered predictions

**P-UQ.1 — the decision is the person's.** With `queue` and a reachable
service: approve on the page → the call is allowed, recorded as approved,
with the approver's email. Deny on the page → refused, recorded as denied,
with the approver's email. The recorded outcome equals the page's outcome in
100/100 trials.

**P-UQ.2 — silence refuses.** Deadline passes with no answer → refused, and
the record says asked-and-unanswered, never approved, never "nobody was
asked". The gate returns within deadline plus one poll interval. No deadline
in policy → 15 minutes. Deadline above 24 hours → refused at construction.

**P-UQ.3 — the decision is bound to the request.** The gate computes the
request digest locally before posting. A decision whose digest differs from
the local one, or whose request id the gate did not issue, or that arrives
after the gate already concluded, is ignored and the call refuses. Mutating
the stored request on the service (value, action, bands) after it was
queued changes nothing about what the gate does.

**P-UQ.4 — the page shows provenance, not model text.** What the page
renders is `ConfirmationRequest.render()` as the gate produced it: the value,
the band of every argument, the reason. It carries no tool output, no model
message, no free text from the run. Redaction (F5) runs before the request
leaves the machine, so a named secret in an argument reaches the service and
the email as `[redacted:…]` — measured, as P-F7.5 measured the notifier.

**P-UQ.5 — a link is single-use and expires.** Token stored hashed;
plaintext lives in the email and the message and nowhere else. Used twice:
the second is refused. Used after the deadline: refused. Tampered: refused.
A decision on an already-decided request: refused, and the first decision
stands.

**P-UQ.6 — fail closed, bounded.** Service unreachable, refused key, no
entitlement, malformed answer: the call refuses, the record says
could-not-queue with the reason, and the gate returns within the connect
timeout, never the full deadline. Never an allow. Never a hang.

**P-UQ.7 — shadow does not ask.** In shadow mode a confirmable refusal
records "would have queued" and sends nothing, blocks on nothing, exactly as
P-F7.4 holds for the notifier.

**P-UQ.8 — nothing else moves.** `deny` and `allow` behave byte-for-byte as
F7 measured. An unconfigured install has no reference to the service in its
decision path. Conformance, policy, custody and the full suite pass
unchanged before and after.

**P-UQ.9 — the courier cannot decide.** A Telegram callback, a reply to the
email, or any request to the service that is not the page's POST with a
valid token, cannot produce a decision. The Telegram buttons are links to the
page. The service's Telegram webhook can only link a chat to an account.

**P-UQ.10 — the person's wait, not the gate's.** Posting the request and
returning the first poll costs under one second at p50 over the public
service. The blocking time is whatever the person takes; the gate adds one
poll interval to it, two seconds by default, and polls with backoff so an
overnight wait is a handful of requests, not thousands.

**P-UQ.11 — entitlement is the only gate on the service side.** An add-on
key can queue and cannot ingest. A Pro or Enterprise key can do both. A free
install with no key configured, and `queue` in policy, refuses at the first
confirmable call with a reason that names the add-on — enforcement of
everything else is unchanged.

**P-UQ.12 — the purchase is the same loop as Pro.** Payment Link → Checkout →
webhook → tenant with the add-on entitlement, an owner, a key → /welcome
claims it once. The account page shows the add-on, its price, and the
Telegram link state. Rotation, members and the billing portal work
unchanged.

## What is measured, in order

1. P-UQ.8 first, on the current code, so the baseline is on record.
2. Service side: approvals table and routes, with P-UQ.3, 5, 9, 11 against
   a local server.
3. Gate side: the `queue` disposition, with P-UQ.1, 2, 3, 6, 7 against the
   local server, then P-UQ.10 against the public one.
4. P-UQ.4 with a named secret in the argument, end to end.
5. Site: approve page, add-ons page, the line under the pricing copy.
6. P-UQ.12 in Stripe test mode against a local run, then live objects.

Anything that fails is recorded as it failed, then fixed, then recorded as
fixed, in `UNATTENDED_QUEUE_RESULT.md`.
