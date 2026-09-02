# F3 — result

**Run 2026-09-02 against `F3_TOKENS_GATES.md`, registered in `236ccf2` before
the code.**

## Gates

| gate | verdict |
|---|---|
| P-F3.1 counts read, never estimated | **PASS-CLEAN** |
| P-F3.2 four classes reported separately | **PASS-CLEAN** |
| P-F3.3 transcript lag measured, not assumed | **PASS-WITH-DRIFT** |
| P-F3.4 cost optional and never invented | **PASS-CLEAN** (after two fixes) |
| P-F3.5 per-call attribution a stated convention | **PASS-CLEAN** — not offered |
| P-F3.6 reading tokens touches no decision | **PASS-CLEAN** |
| P-F3.7 a token cap obeys shadow | **PASS-CLEAN** |

## What it reports, on a real session

```
all models
    input                 106,475    0.0%
    output             10,987,319    0.3%
    cache_write        81,712,538    2.1%
    cache_read      3,743,566,507   97.6%
    total           3,836,372,839
```

Per model as well as in total. **97.6% cache reads** is the finding a cost
report would have buried: it is a fact about how the agent is being run,
useful whether or not anyone is paying. It is also why one rate would overstate
this session by 7.2x, and why the four classes are never summed.

## P-F3.4 — two bugs caught, both saying "free" when they meant "unpriced"

The first implementation printed, for a model with no declared rates:

```
cost         0.00 at your declared rates
```

`_price` skipped zero-count classes, so a model with all-zero counts never
reached a missing rate and returned `0.0`. And when *no* model could be priced,
the grand total printed `0.00`.

Both read as "this was free". The truth was "this was never priced", and those
are different claims. Fixed: empty rates yield `None` regardless of counts, and
a total with nothing priced says `nothing priced`.

```
cost   unpriced — no rates declared for claude-opus-5
cost   2,863.71 at your declared rates
cost                   2,863.71
priced as of 2026-09-02 — declared by the operator
some models are unpriced; their tokens are counted above and excluded
```

Partial rates — input declared, the other three missing — price **nothing**
rather than 3% of the tokens.

## P-F3.3 — PASS-WITH-DRIFT, and the drift matters

The docs say the transcript is written asynchronously. Measured on a real file:
the last usage record's timestamp is **709.7 s** before the file's final write.
So a hook firing mid-session sees usage up to the last flushed turn, not the
current one.

The drift from the registered wording: the gate asked what the report "does
about turns it cannot yet price". The report does nothing special — it counts
what is in the file. That is correct for a reconciliation tool and wrong for
anything live, which is why **no live gating on tokens is offered** and
`max_tokens` refuses only when a caller has supplied a reconciled figure.
Recorded as drift rather than a pass because the gate implied handling that
turned out to be unnecessary.

## P-F3.7 — the discipline F2 taught, applied first time

```
usage unknown          -> ALLOW    (a cap on a number we do not have is worse than no cap)
1500/1000, enforce     -> REFUSE
1500/1000, shadow      -> ALLOW — "SHADOW: would have refused — session token cap…"
```

`max_tokens` supersedes the `max_spend` F2 deferred. Tokens run out — the
context window is a hard wall — and a token cap is meaningful on a local model
where spend is not.

## P-F3.5 — per-call is not offered

Usage is recorded per model turn and a turn contains several tool calls. Any
split is a convention, so per-session and per-model are reported and per-call
is not. Offering it with a footnote would have been the tempting version.

## Regression

```
conformance 18/18 · policy 87/87 · custody 13/13 · battery 6/6 · sweep 0
adapter, MCP, tool-desc, extractor pass · stdlib only: json, pathlib, typing
```
