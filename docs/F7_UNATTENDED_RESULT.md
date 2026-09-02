# F7 — result

**Run 2026-09-02 against `F7_UNATTENDED_GATES.md`, registered before the code.**

## Gates

| gate | verdict |
|---|---|
| P-F7.1 explicit disposition, or default deny | **PASS-CLEAN** |
| P-F7.2 `allow` records that nobody approved | **PASS-CLEAN** |
| P-F7.3 the notifier cannot change a decision | **PASS-CLEAN** after a fix |
| P-F7.4 the notifier obeys shadow | **PASS-CLEAN** |
| P-F7.5 the notifier is not a leak | **PASS-CLEAN** |
| P-F7.6 unconfigured is unchanged | **PASS-CLEAN** |

## P-F7.2 — the record must not forge an approval

```
on_confirmable=allow -> ALLOW
recorded reason: "unattended policy allowed this without approval —
                  nobody was asked. Original refusal: taint: command is tool…"
```

`confirmable: true` means a person *may* answer, not that one did. Recording an
unattended allow as a confirmation would forge an approval, which is the worst
thing this module could do — the log is the artefact the whole product sells.
So the record says which one happened, in those words.

An invalid disposition is refused at construction, `queue` included, with the
reason that it needs hosted routing.

## P-F7.3 — one fix, and it was a real hole

The first implementation used `subprocess.run(..., timeout=5)`. Outcomes were
correct, and the timing was not:

```
before:  hangs 30s -> REFUSE (5.1s)
after :  hangs 30s -> REFUSE (0.15s)
```

**A notifier that can stall every refused call by five seconds is a
denial-of-service surface wearing a helpful face.** The gate said "neither
blocks the agent nor alters the outcome"; only the second half held. Now it is
fire-and-forget: nothing waited on, no output read, exit code never seen.

That last property is also what makes an alert unable to approve:

```
notifier "echo approve; exit 0" -> REFUSE
notifier crashes                -> REFUSE
notifier hangs                  -> REFUSE
notifier does not exist         -> REFUSE
```

`confirm.py` already stated the principle — an escape hatch that lets anything
through becomes the attacker's target. An alert that could auto-approve would
be `allow` with extra machinery and a false sense of oversight.

## Delivery is asynchronous and eventual

Measured 10/10 delivered within 1.5 s, no orphaned children. It is **not**
delivered by the time the decision returns, and a caller must not assume it is.
That is the price of not blocking, and it is the right trade: an alert that
arrives a second late is useful, and a gate that stalls a second on every
refusal is not.

An intermediate test run reported 8/10 because it checked after 0.4 s under
load. The test was wrong, not the notifier; recorded because a flaky assertion
about a security control is how a real defect gets explained away later.

## P-F7.5 — the notifier sees what the log sees

```
api_key in payload : [redacted:named-secret]
raw secret leaked  : False
```

F5 redaction runs before the notifier, so a webhook or a chat message cannot
become the leak the log was careful to avoid.

## What is still out

`queue` — blocking until someone answers — needs hosted approval routing and
remains a Pro feature. Delivery to email, Slack or a webhook is delivery
infrastructure and a dependency; the notifier is a command, and the operator
wires it to whatever they already run.

## Regression

```
conformance 18/18 · policy 87/87 · custody 13/13 · battery 6/6 · sweep 0
```
