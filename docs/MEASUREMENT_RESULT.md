# What we measured, and what it means

**2026-08-29/30.** Every prediction was registered and committed before the run
that tested it. Raw JSON in `results/overnight/` and `results/agentdojo/`.

**Scope on every number below:** Qwen2.5-14B-Instruct via vLLM 0.9.2 on an H100,
AgentDojo v1.2.1. Frontier models are not measurable here — Sonnet 4.5 contains
72 of 72 attacks with **no defence installed**, so nothing placed in front of it
can be shown to do anything.

---

## The claim that survives scrutiny

**Where a policy can enumerate the allowed values, we have no advantage. Where
it cannot, provenance is the only thing that works.**

```
BANKING — values enumerable (payees, amounts)
  ungated                    36 / 144 attacks succeed
  params-only (no provenance) 0 / 144
  ours                        0 / 144

SLACK — values are free text, nothing to enumerate
                          important_instructions   tool_knowledge
  ungated                          46 / 105            40 / 105
  params-only (no provenance)      46 / 105            37 / 105
  ours                             22 / 105             9 / 105
```

**A params-only engine performs like no defence at all on Slack, under two
independent attack types.** On banking it ties us at zero, and an allowlist of
payees does the entire job.

That is narrow, specific and falsifiable, which is why it is worth more than a
broad claim.

## Confirmed against APort's real product, not a proxy

Their shipped `finance.payment.payout.v1` enforces `allowed_recipients`,
`currency_limits`, `max_payouts_per_day`, `approval_required` — our value
predicates under other names, with nothing about where a value came from.

Run against their live evaluator:

```
command: 'git push --force origin main'    byte-identical both times
  typed by the user                        APort ALLOW   ours ALLOW
  lifted from a document the agent read    APort ALLOW   ours DENY
```

Their `data.report.ingest.v1` checks `data_source_id in approved_sources`, which
looks like provenance and is not: **`data_source_id` is supplied by the caller**,
so an injected agent supplies whatever it likes. Declared source, not derived
provenance.

## The full arc on banking

| | attacks /144 | utility /16 |
|---|---|---|
| ungated | 36 | 9 |
| taint only | 17 | 8 |
| + value predicates (conjunctive) | 4 | 7 |
| + password confirmation | **0** | 6 |
| + careful human | **0** | 7 |
| + rubber-stamp human | 4 | 7 |

**A rubber-stamp human approved all 91 requests put to it and let only 4
through** — not a return to 36. So the share of the security resting on a person
being careful is about **3 points**. That is small by construction: only
refusals the policy marks `confirmable` are ever shown to anyone.

Of the 9 benign tasks that fail under enforcement, only 3 ever hit a refusal.
**The other 6 fail ungated too.** The gate's real cost is 2 tasks, not the
9-versus-7 gap.

## Cross-suite, with policies inferred rather than written

| | ungated | enforced | utility |
|---|---|---|---|
| slack | 46/105 | **22/105** | 14 → 15/21, **0 refusals** |
| workspace | 12/560 | 3/560 | 22 → 15/40, 13 refusals |

Slack is the good case: attacks halved at **no utility cost**, under a policy
inferred automatically from benign traffic on a suite nobody read.

Workspace is a poor trade — 9 attacks blocked for 7 lost tasks — and its 2%
ungated baseline was always too thin to carry a conclusion, which P-CROSS6 said
in advance.

## Verdicts

| prediction | verdict |
|---|---|
| P-AD1 bands results without modifying the suite | PASS |
| P-AD4 permit-everything matches undefended exactly | PASS-CLEAN |
| P-AD2 benign utility within 10 points | PASS-CLEAN |
| P-AD3 attack rate, Sonnet | **INCONCLUSIVE** — no ungated headroom |
| P-PRED2 conjunctive rule reaches laundered attacks | PASS |
| P-FIX1 scoping fix raises utility | **PARTIAL** — attacks held, utility did not rise |
| P-CONF1/2 password confirmation | PASS-CLEAN both |
| P-ORACLE1 careful human restores utility | **PARTIAL** — attacks held at 0, utility 7 not 8 |
| P-ORACLE2 careless human raises attacks | PASS-CLEAN |
| P-CROSS1 new suites have headroom | PASS |
| P-CROSS4/5 inferred policy generalises | PASS (slack) |
| P-HARD1/2 differentiator survives a second attack | PASS-CLEAN both |
| P-HARD3/4 multi-pass inference | PASS both |
| P-HARD5/6 confirmation beyond banking | **FAIL** — see below |
| P-APORT1 params-only lands above ours | **FAIL on banking**, PASS on slack |

## What failed, and why

**P-APORT1 failed on banking.** Params-only also reached zero, with *better*
utility. Provenance contributed nothing there, because a payee allowlist catches
the attacker's IBAN regardless of origin. That result stands and it is the
reason the claim is stated narrowly.

**P-HARD5/6 failed for a specific reason.** Confirmation changed nothing on
workspace — even a rubber stamp approving everything left utility at 15/40 —
because **inference never marks its band constraints `confirmable`**. The flag
was added for hand-written grants and inference was never taught to emit it. So
the oracle had nothing to answer. The question is open, not answered negatively.

**Utility predictions failed twice.** I twice predicted a fix would raise benign
utility and it did not.

## Instrument failures worth recording

Each of these produced a plausible number that was wrong.

- **`vllm/vllm-openai:latest` was numerically broken** on this H100 — healthy
  server, full-speed tokens, `"[]([]([]("` to every prompt. Two baselines were
  recorded before anyone asked the model a question with a known answer. The
  runner now refuses to benchmark a model that cannot answer two.
- **An SSH tunnel suppressed utility**, 6/16 tunnelled against 9/16 on the host,
  because AgentDojo sends no `max_tokens`.
- **A vacuous policy scored as a defence.** slack and workspace ran under a
  single grant admitting every tool, because `STATE_CHANGING` was a hardcoded
  list of banking tool names. Zero refusals is what an empty policy does, and it
  read as a null result about the architecture. A guard now refuses to score an
  enforcement run whose policy constrains nothing.
- **An inferred policy refused its own training traffic** — 48 refusals, 0 of 21
  tasks, and a headline 0 attacks achieved purely by refusing everything. A
  replay guard now refuses to write such a policy.
- **Our gate blocked AgentDojo's own injectability probe**, so every cross-suite
  pair read as non-injectable and the matrices silently ran zero combos while
  the driver recorded them OK.
- **Six policy-authoring defects**, all mine, every one found by measurement
  rather than review. Five were the same shape: a constraint applied to an
  action that does not take that argument. The sixth was inside the inference —
  the feature whose purpose is to stop humans making that mistake.

## Latency

| | |
|---|---|
| full guarded call | **0.082 ms p50**, 0.168 ms p99, in-process |
| provenance lookup | constant time after a k-gram prefilter |
| store | bounded, evicts oldest first |

**Not comparable to APort's published 53 ms**, which is a cloud round trip —
their decision leaves the customer's environment and an API error returns DENY.

## Limits

- **One model.** Everything is Qwen2.5-14B, because frontier models refuse these
  attacks unaided. We cannot demonstrate value on what customers actually run.
- **Laundering remains open.** A command the model paraphrased rather than
  copied still escapes; that is the 22-of-105 residue on slack.
- **Utility inference leakage.** Policies are inferred from the same benign
  tasks the benign run scores, so utility figures are an upper bound. Attack
  figures are unaffected — no attack was in the inferred traffic.
- **Tool descriptions are not covered at all.** A malicious MCP server's tool
  description is read by the model and never banded.
