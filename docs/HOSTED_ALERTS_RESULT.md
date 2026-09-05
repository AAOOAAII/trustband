# Hosted alert delivery — result

**Measured 2026-09-05 against the gates registered in
`HOSTED_ALERTS_GATES.md`. Shipped in 0.6.1 and the service the same day.**

## Gates

| | |
|---|---|
| P-HA.1 the decision path is unchanged | **PASS-CLEAN** |
| P-HA.2 no key in the spool, ever | **PASS-CLEAN** |
| P-HA.3 delivered where the person is | **PASS-CLEAN** |
| P-HA.4 entitlement is the only service-side gate | **PASS-CLEAN** |
| P-HA.5 what leaves the machine is the record | **PASS-CLEAN** |
| P-HA.6 bounded | **PASS-CLEAN** after a fix |
| P-HA.7 shadow does not alert | **PASS-CLEAN** |
| P-HA.8 nothing prior moves | **PASS-CLEAN** after a fix |

Where measured: package `tests/test_hosted_alerts.py` (7) with a local
sink standing in for the service; cloud `tests/test_hosted_alerts.py` (5)
with a real Guard draining into a local server and a fake Telegram. The 8a
suite (12) unchanged. Conformance 22/22. Package 93/93, cloud 57/57.

## P-HA.1 — cost

```
fire() p50   webhook 0.131 ms   hosted 0.131 ms
fire() p95   webhook 0.182 ms   hosted 0.195 ms      (500 each, interleaved, quiet machine)
```

The same file write. The only difference in the job is one word and a
directory path.

## P-HA.8 — the fix, and it was the right refusal again

The first build read the key inside `alerts.py` at delivery time. The 8a
suite's pair 6 refused it:

```
test_alerts_have_no_entitlement_path: 'api_key' in source
```

Same principle as conformance 12 for the guard: a module that delivers
alerts must not be a module that reads billing state, because the next
person to edit it will not know where the line was. The lookup moved to
`approvals.py`, which already owns the one config read for `queue`;
`alerts.py` asks it for a target and never sees a key. The reason text for
a missing key was reworded for the same check.

## P-HA.6 — the fix

The cap counted rows in `alerts`. Retention trims that table to the newest
thousand, so with a small retention the count could never reach the cap and
a tenant could post without limit. Found by the test that set both small.
Arrivals are now counted in hour buckets in their own table; the cap reads
this hour and the last, so a rolling hour is never undercounted and may be
overcounted, which is the safe side.

## P-HA.2 / P-HA.4

100 alerts spooled and drained: no spool file, claimed file or failed-log
line contains the key; every delivery carried it as a bearer header read
from `config.json` at that moment. Without a key, the failed log says:

```
hosted alerts need the Unattended add-on (trust.band/add-ons) and `trustband login`; no key in config. Other destinations are unaffected.
```

and a webhook destination in the same policy delivered as before. A bare
key meets `HTTP 402: approval queueing needs the Unattended add-on…` in
the failed log; the service's reason is kept, not a bare status.

## P-HA.3 / P-HA.5

With a chat linked, the refusal line arrived as a Telegram message with no
button (an alert tells, it never asks). Without one, three refusals were
stored and listed newest first on the account page. A named secret in the
refused argument was `[redacted:…]` in the message, the stored text and
the stored event.

## The first live alert

2026-09-05, 20:53:23 BST. A gate on a laptop with `"alerts": {"*": "hosted"}`
and a one-day key for the Cittela tenant refused a document-derived payment
recipient; `drain_now()` delivered the spooled job to api.trust.band in
226 ms with nothing in the failed log. The service stored it as `refusal`
with the line `trustband refused send_payment: taint: recipient is tool,
needs session…`, logged no delivery failure, and the message arrived in the
Telegram chat linked to the owner minutes earlier for approvals. The key
was revoked afterwards.

## What is still out

- Email for per-event alerts, on purpose.
- A per-class routing on the service (all classes to all chats). One chat
  per person for now.
- Alert search or export from the service; the local log is the record and
  Pro's retention is the search.
