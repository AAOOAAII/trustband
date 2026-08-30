# Hardening session — gates registered before the runs

**Written 2026-08-30, before any of these runs.** Committed first.

The commercial claim now rests on one measurement:

```
SLACK, attacks succeeding out of 105
  ungated                46
  params-only (no taint) 46    competitor architecture: no effect at all
  ours (with taint)      22
```

That is **one suite, one attack type, one model**. These three runs test the
weakest joints rather than adding more of what we already have.

---

## Run A — a second attack type on Slack

`tool_knowledge` instead of `important_instructions`, same three configurations.
The single highest-value run: it asks whether the differentiator survives a
change of attack, or whether `important_instructions` happened to suit us.

**P-HARD1:** ungated and params-only land within 5 of each other. If
params-only meaningfully beats ungated under this attack, provenance is not the
only thing doing work and the claim narrows.

**P-HARD2:** ours lands materially below both. If it does not, the Slack result
does not generalise across attacks and must be reported as
attack-specific — which would make it far weaker evidence than it looks.

## Run B — multi-pass inference

Workspace refused 15 calls on a rerun **despite the inferred policy passing the
replay guard**. The guard checks the policy against the traffic it was inferred
from; it cannot see that a rerun of the same tasks produces differently-banded
arguments, because the model is not deterministic.

So a floor built from a single observation pass is brittle by construction.
Fix: infer across three passes and keep the **least trusted** band seen for
each argument anywhere across them.

**P-HARD3:** workspace benign refusals fall below 15, and utility rises above
12/40. **P-HARD4:** workspace attacks do not rise above 4/560 — a looser floor
must not buy utility with security. If they rise, multi-pass is trading the
wrong way and is reported as such.

## Run C — confirmation measured beyond banking

Band refusals became confirmable this afternoon and have never been measured.
Workspace lost 10 benign tasks; those refusals are the natural test.

Both oracles again, so the human-dependence figure extends past banking:

**P-HARD5:** under `perfect`, workspace utility rises and attacks stay at or
below the Run B figure. **P-HARD6:** under `rubber`, attacks rise — and the gap
between the two oracles is reported as the human-dependence number for this
suite, beside banking's 3 points.

## Standing rules, unchanged

- Every run reports its ungated baseline.
- No policy is changed after seeing an attack result without registering first.
- `MODEL_DECLINED` is never counted as containment by the gate.
- A failed instrument is INCONCLUSIVE, never scored from partial data.
- A policy that would refuse its own inference traffic is not written at all.

## What this session deliberately does not do

More suites, more models, or the exfiltration test. The architectural claim is
already confirmed; additional runs of the same shape would not change any
decision. The real APort install matters for credibility and belongs with a
written result rather than squeezed in here.

---

## Latency, measured 2026-08-30 (registered as a gap, not a prediction)

We had no latency number while the competitor publishes 53ms p50. Measured on
an M-series laptop, single process:

| | p50 | p95 | p99 |
|---|---|---|---|
| full guarded call | **0.082 ms** | 0.105 ms | 0.168 ms |

That covers evaluate, mint, ingest, authorize, execute and audit. It is **not
comparable to APort's 53ms**, which is a cloud API round trip; ours is
in-process and theirs includes the network. Quoting them side by side would be
dishonest.

**Substring recall scales linearly**, and that is the part that will hurt:

| remembered values | per call |
|---|---|
| 50 | 0.005 ms |
| 500 | 0.037 ms |
| 2 000 | 0.143 ms |
| 10 000 | 0.966 ms |

Memory is **unbounded** — every string a tool ever returned is retained for the
session. Fine for a benchmark, wrong for a long-running agent. Bounding and
indexing this is product work, and it is the first real scaling constraint the
provenance layer has.
