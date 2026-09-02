# P3 — deliverable contracts. Result.

**Run 2026-09-02 against `P3_CONTRACTS_GATES.md`, registered before the code.**

## Gates

| gate | verdict |
|---|---|
| P-P3.1 evaluated on the result, not the call | **PASS-CLEAN** |
| P-P3.2 shadow-first, blocking per contract | **PASS-CLEAN** |
| P-P3.3 the outcome is in the same record | **PASS-CLEAN** |
| P-P3.4 cannot change an authorization decision | **PASS-CLEAN** |
| P-P3.5 an unevaluable contract fails loudly | **PASS-CLEAN** |
| P-P3.6 nothing prior moves | **PASS-CLEAN** |

## What it does

Seven operators over result fields: `at_least`, `at_most`, `present`, `absent`,
`not_equal`, `matches`, `contains_all`. Enough for coverage thresholds,
reviewer-not-author, ticket references, required sections and forbidden
artifacts.

```
non-compliant PR — the CALL was allowed
  FAIL coverage             coverage.pct=61 is not >= 80
  FAIL reviewer-not-author  pr.reviewer='alice' equals 'alice'
  FAIL ticket-referenced    pr.title='quick fix' does not match '[A-Z]+-\d+'
  FAIL required-sections    pr.body is missing ['## Testing']
  FAIL no-debug-artifacts   artifacts.debug is present
  blocking failures: ['coverage']
```

The call was **allowed**, and the work failed. That is the distinction the
phase exists to make: every other rule here answers "may this happen", and a
contract answers "was what came back acceptable".

## P-P3.5 — absence satisfies nothing, here too

```
missing data:
  FAIL coverage    coverage.pct is not in the result, so 'at_least' cannot be
                   checked. An unevaluable contract fails; absence satisfies
                   nothing.
```

A threshold against data that is not there is the easiest place in this whole
feature to pass silently — the number is missing, so nothing is below the bar.
`_dig` returns `found` separately from the value precisely because `0`, `""`
and `False` are legitimate values and all falsey, and conflating absent with
empty is how that failure arrives.

## P-P3.4 — contracts stay out of authorization

```
decisions identical with and without contracts: True
```

Contracts run after the tool ran. They cannot retroactively refuse a call,
touch provenance, or change what `before_tool_call` would decide. A blocking
failure is surfaced on `blocked_contracts` for a CI caller to act on, and is
never used to refuse a tool call — the tool already ran.

## P-P3.2 / P-P3.3

```
shadow   blocking failures surfaced: []
enforce  blocking failures surfaced: ['coverage']
```

Blocking is opt-in **per contract**, not globally: an operator who wants a hard
gate on coverage rarely wants one on required-sections yet, and one wrong
threshold blocking CI removes the whole tool on the first Friday.

Verdicts land in the same `audit.jsonl`, in the same hash chain, and render in
`trace`:

```
← submit_pr      returned  band=tool  1 string(s) remembered
      NO  contract coverage [blocking]: coverage.pct=61 is not >= 80
      NO  contract sections: pr.body is missing ['## Testing']
2 contract(s) failed — these are claims about the WORK, not about permission;
the calls themselves were allowed.
```

That last line is in the output deliberately. A reader glancing at a trace full
of `NO` should not conclude the agent was blocked.

## The claim, and its limit

**Contracts verify what is checkable, not that the work is good.** A coverage
threshold says a number cleared a bar; it says nothing about whether the tests
are worth having. That sentence belongs on the site verbatim.

Malformed contracts are refused at adoption — unknown operator, non-numeric
threshold, uncompilable regex — because a malformed policy is a bug, not a
refusal.

## Out of scope, named

`trustband verify-deliverable` as a CI entry point: a CLI shape question that
can follow. Git and GitHub integration: reviewer identity and ticket state come
from the host, and inventing them here would be a contract about data trustband
cannot see.

## Regression

```
conformance 18/18 · policy 87/87 · custody 13/13 · battery 6/6 · sweep 0
browser replay unchanged · all 7 packs still adopt · adapters pass
```
