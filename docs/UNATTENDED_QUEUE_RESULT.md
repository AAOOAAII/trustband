# Unattended `queue` — result

**Measured 2026-09-05 against the gates registered in
`UNATTENDED_QUEUE_GATES.md`. Built as the £14.99 Unattended add-on.**

## Gates

| | |
|---|---|
| P-UQ.1 the decision is the person's | **PASS-CLEAN** |
| P-UQ.2 silence refuses | **PASS-CLEAN** |
| P-UQ.3 the decision is bound to the request | **PASS-CLEAN** |
| P-UQ.4 the page shows provenance, not model text | **PASS-CLEAN** |
| P-UQ.5 a link is single-use and expires | **PASS-CLEAN** |
| P-UQ.6 fail closed, bounded | **PASS-CLEAN** |
| P-UQ.7 shadow does not ask | **PASS-CLEAN** |
| P-UQ.8 nothing else moves | **PASS-CLEAN** after a fix |
| P-UQ.9 the courier cannot decide | **PASS-CLEAN** |
| P-UQ.10 the person's wait, not the gate's | **PASS-CLEAN** |
| P-UQ.11 entitlement is the only service-side gate | **PASS-CLEAN** |
| P-UQ.12 the purchase is the same loop as Pro | **PASS-CLEAN** in the suite; live objects created, first live purchase not yet made |

Where measured: gate side without a server in the package's
`tests/test_queue.py` (12); service side and end to end in the cloud
repository's `tests/test_unattended.py` (15), with a real `Guard` in
`queue` mode against a local server and a person in a thread who opens the
page and decides. Conformance 22/22. Cloud suite 48/48.

## The gap that had to be closed first

An approval had never been spent. `ConfirmationLedger.as_context` had no
caller anywhere in the package, and the band check in `issuance.py` did not
look at a `confirmed` context at all — only the `confirmed` value predicate
did. A person could approve a document-derived recipient and the next
evaluation would refuse it exactly as before. F7 did not find this because
F7 never answered a question; it only chose what to do when nobody could.

The fix is narrow: under a grant marked `confirmable`, a band failure is
lifted when every failing argument's value is in the confirmed set for that
argument. Measured that an approval for one value lifts nothing for another
(`test_approval_lifts_only_the_approved_value`), that a grant without
`confirmable` is untouched (conformance 8, 12), and that the approved call
still refuses if any other predicate fails (the re-evaluation runs the whole
grant, not the band check alone).

## P-UQ.8 — the fix

The first build put `api_key` and `api_url` on the `Guard` constructor so
`from_file` could build the courier. Conformance check 12 refused it:

```
FAIL  enforcement is identical under every entitlement state
      leaked_terms=['entitlement', 'api_key']
```

That check greps the guard's source for any billing vocabulary, on the
principle that a differential test only covers the states someone thought
to enumerate. It was right. The courier is now built in
`trustband/approvals.py` from the config and handed to the guard as an
object; the guard's source mentions no key. An install without a key holds
a `NoCourier` that refuses at the first confirmable call with a reason that
names the add-on, so construction and every other decision are untouched by
a billing state.

`deny` and `allow` were then re-measured: neither touches the courier, and
their decisions and reasons are those F7 recorded.

## P-UQ.2 / P-UQ.6 — bounds

```
deadline 3 s, nobody answers        -> refused in < 5.5 s (deadline + one poll)
service unreachable at submit       -> refused in < 1 s, "could not queue"
key revoked                         -> refused in < 2 s, reason carries "revoked"
service lost mid-wait (5 misses)    -> refused well before a 3600 s deadline
```

Every one is recorded as refused, with the reason, and `confirmable: true`
so a later reader can tell a queue timeout from a structural refusal.

## P-UQ.3 — binding

The service's stored row was rewritten with a different digest while the
gate waited; the person approved on the page; the gate refused with "not
bound to the question that was asked". The gate compares against the digest
it computed before asking, never against what the service says was asked.

## P-UQ.4 — what leaves the machine

```
argument value : sk-proj-ABCDEF1234567890XYZ
on the wire    : [redacted:named-secret]   (rendered, reason)
digest         : sha of the real value
in the email   : redacted
on the page    : redacted
in the row     : redacted
```

## P-UQ.9 — the courier

With Telegram configured and a chat linked through `/start <code>`, an
approval is delivered to the chat as a message whose button is a link to
the page. Then three shapes a bot could send back — a `callback_query`
carrying `approve:<id>`, a text message saying so, and a second `/start` —
are acknowledged and ignored; the approval stays `pending`, decided by
nobody. A wrong webhook secret is refused. The only route that changes an
approval's state is the page's POST with an unused token.

## P-UQ.10 — cost

```
local server   : submit p50  82 ms   poll p50  58 ms   (machine under load)
api.trust.band : submit p50 164 ms   p95 261 ms   poll p50 141 ms   (from London)
```

The blocking time is the person's. Polling starts at 2 s and backs off to
30 s, so a fifteen-minute wait is about forty requests and an overnight
wait is a few hundred, not thousands.

## P-UQ.11 / P-UQ.12 — the add-on as a product

A checkout whose session carries `metadata.tier = unattended` provisions a
`free` key plus an `unattended` entitlement, an owner, and a claimable
key, through the unchanged Pro loop. That key can queue and cannot ingest,
search or pull policy: 402 with a reason that says Pro. A bare `free` key
can do neither: 402 naming the add-on. The account page says "Unattended
add-on · £14.99 / month" and lists what it includes.

Live objects exist (product, price, Payment Link with the metadata). No
live purchase has been made yet; the first is the first test of that seam,
as it was for Pro.

## What is still out

- Hosted delivery of ordinary alerts while the machine is off. The request
  path exists; the alert path does not use it.
- Push notifications, SMS, WhatsApp, a native app. Each is either a cost
  per message or an approval process, and neither fits £14.99.
- The timing gate in `test_alerts.py` (spool write p50 < 1 ms) failed for
  most of this session at 1.4–2.0 ms with a load average above 10 and a raw
  file write measured at 4.5 ms; the code is unchanged since 0.4.0. It passed
  three runs in a row once the load fell below 10, before release.

## Regression

```
package 86/86 (74 + 12 queue) · conformance 22/22
cloud 48/48
```
