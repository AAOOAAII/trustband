# Model constraints in policy — result

**Measured 2026-09-05 against `MODEL_CONSTRAINTS_GATES.md`. Ships in 0.7.0.**

| | |
|---|---|
| P-MC.1 absent is unchanged | **PASS-CLEAN** |
| P-MC.2 residency by band | **PASS-CLEAN** |
| P-MC.3 cost is refused at the gate | **PASS-CLEAN** after a fix |
| P-MC.4 the hint is the intersection | **PASS-CLEAN** |
| P-MC.5 the pin is drift | **PASS-CLEAN** |
| P-MC.6 shadow, entitlement, no key | **PASS-CLEAN** |
| P-MC.7 recorded and rendered | **PASS-CLEAN** |
| P-MC.8 one adapter, against the installed library | **PASS-CLEAN** after a fix |
| P-MC.9 nothing prior moves | **PASS-CLEAN** |
| P-MC.10 the saving, synthetic | **PASS**, 65.8% on the table given |

`tests/test_models.py` (17) and `tests/test_model_gate_langchain.py` (4,
langchain_core 1.6.1, the library's own fake chat model). Conformance
22/22. The full suite passed with three load-induced timing flakes that
passed on rerun.

## The two fixes

**Money is not a float.** The first draft wrote `max_cost_per_session: 5.0`
and prices as decimals. The policy encoder refused the policy at adoption:
the policy domain has no floats, because a policy is digested and a float
has two spellings of one value. That is the same rule the lockfile follows
by stringifying schema floats. Money is now an integer in minor units,
pence or cents; a ceiling of 500 is £5.00, a price of 250 is £2.50 per
million tokens. The reason is on the page rather than hidden in a
validator.

**A message that embeds a tool result is not one.** The store's `recall`
answers "is this value something a tool returned", and its prefilter
rejects a query containing grams it has never seen, so a prompt that quotes
a page inside its own words recalled to nothing and the LangChain gate let
the large model see tool content. The gate now also asks the reverse
question, `bands_within(text)`: which remembered values appear inside this
message. Bounded by the store; the first-gram test skips almost every entry
before the substring check. The failing test was the library-backed one,
which is the reason P-MC.8 exists.

## What the numbers say

- With SESSION content alone, anything in `allow`. With TOOL content in
  context, only `by_band.tool`; with TOOL and USER, the intersection. A
  model outside `allow` refuses whatever the bands.
- A session that has spent to its ceiling refuses the next call with the
  spend and the ceiling in the reason; a single call over the per-call
  limit refuses before it is made; both classify as `runaway` for alerts.
- `hint.models` is the intersection in policy order; `hint.max_tokens` is
  the per-call limit or the remaining budget at the cheapest permitted
  priced rate, whichever is smaller.
- A provider snapshot named in a response that differs from the pinned one
  is `lock_drift` of kind `model`; the next call refuses under enforce and
  flags under shadow; `accept_lock` clears it. The benign-drift rule
  applies: nothing auto-accepts.
- Shadow records "would have refused" and allows; the models module has no
  billing vocabulary; the tool path decides identically with and without
  the section.
- `trace` renders `NO ⇒ model gpt-4o REFUSED bands=session,tool`, the
  reason, and `may reach: gpt-4o-mini`.

## P-MC.10 — the synthetic saving

100 scripted steps, TOOL content present in 70, 2,000 tokens in and 500
out per step, the example table (large 250/1000, small 15/60 per million):
the policy sends 70 steps to the small model. Priced, the run costs 34.2%
of sending everything to the large model: **a 65.8% saving**. Arithmetic on
a table. It says nothing about any real workload, and the site will say
so if it quotes it.

## What this does not show

- A real provider. The adapter was exercised with LangChain's fake chat
  model; the model name and usage plumbing are the library's, the provider
  is not.
- A silent upgrade behind an unchanged snapshot name. Invisible by
  construction; the page says so.
- Claude Code and MCP proxy: no model call is visible to those adapters;
  nothing was built for them.
