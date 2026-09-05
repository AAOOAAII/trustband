# Model constraints in policy. Gates before the code.

**Registered 2026-09-05, before any implementation. The gate sits between
the agent and the tool and stays there. This adds a second question it can
answer, at the point where the framework is about to call a model: *may
this step reach this model, with this much, given what is in its context?*
The answer is a decision plus a hint; the routing is the framework's.**

## What this is

A `models` section in policy:

```json
"models": {
  "allow": ["gpt-4o*", "claude-*"],
  "by_band": {"tool": ["gpt-4o-mini"], "user": ["gpt-4o-mini"]},
  "max_tokens_per_call": 20000,
  "max_cost_per_session": 500,
  "prices": {"gpt-4o": {"in": 250, "out": 1000}, "gpt-4o-mini": {"in": 15, "out": 60}},
  "pin": true
}
```

`Guard.before_model_call(session, model, tokens_in=None, context_bands=None,
version=None)` decides. The bands in context are, by default, SESSION plus
every band the session's provenance store has remembered; an adapter that
can see the messages may pass them explicitly. A model is permitted when it
matches `allow` and, for every band present, matches that band's list if one
is given. The decision carries `hint = {"models": [...], "max_tokens": n}`,
the set every band present permits, so a router that wants to choose can.

Money is written in minor units, pence or cents, as integers: the policy
domain has no floats, for the reason the lockfile stringifies them. A
ceiling of 500 is £5.00; a price of 250 is £2.50 per million tokens.

Cost: `record_model_usage(session, model, tokens_in, tokens_out)` after each
call; the next call refuses at the gate once the session's spend, priced
from the table, reaches the ceiling. A single call above
`max_tokens_per_call` refuses before it is made. The runaway alert class
fires on both, as it does for the session caps.

The pin: with `pin` true, `(model, version)` is a lockfile item of a new
kind `model`, observed on the first call and on every response that names
a version. A change is drift: refused under enforce until `lock accept`,
flagged under shadow. The benign-drift rule from `BENIGN_DRIFT_RESULT.md`
applies unchanged: nothing is auto-accepted.

## What it is not

- **Not a router, not a proxy.** The gate never makes or forwards a model
  call. It answers a question the framework asks and hands back a hint.
- **Not a new seam for the tool path.** With no `models` section, nothing
  about `before_tool_call` changes, byte for byte.
- **Not a claim to see a silent provider upgrade.** A version is known only
  when the response carries one. Drift is then recorded and refuses the
  *next* call; the call that revealed it has already happened. Stated on
  the page, not hidden.
- **Not a price oracle.** Prices are the operator's table. A model missing
  from it is charged at zero and the record says so.

## Registered predictions

**P-MC.1 — absent is unchanged.** With no `models` section the full suite,
conformance and the battery pass unchanged, and `before_model_call` allows
everything with a reason that says no constraints are configured.

**P-MC.2 — residency by band.** A session that has remembered TOOL content
may reach only `by_band.tool`; one that has remembered TOOL and USER
content may reach only the intersection; one with SESSION content alone may
reach anything in `allow`. A model outside `allow` refuses whatever the
bands. Measured with the store and with explicit `context_bands`.

**P-MC.3 — cost is refused at the gate.** Usage priced from the table
accumulates per session; the call that would follow a crossing refuses with
the spend and the ceiling in the reason. A call above the per-call token
limit refuses before it is made. Both record and alert as `runaway`.

**P-MC.4 — the hint is the intersection.** `hint.models` equals exactly
the set every band present permits, in policy order, and `hint.max_tokens`
is the per-call limit or the remaining budget in tokens of the cheapest
permitted model, whichever is smaller.

**P-MC.5 — the pin is drift.** First call pins `(model, version)`; a
response naming a different version writes `lock_drift` and the next call
refuses under enforce, proceeds and flags under shadow; `accept_lock`
clears it. A response with no version pins the name alone and says so.

**P-MC.6 — shadow, entitlement, no key.** Every model refusal obeys shadow;
enforcement is identical under every entitlement state; the guard's source
still contains no billing vocabulary (conformance 12).

**P-MC.7 — recorded and rendered.** A model decision is one chained entry
with the model, the bands present, the outcome, the reason and the hint;
`trace` renders it; the `refusal` and `runaway` alert classes fire from it.

**P-MC.8 — one adapter, against the installed library.** A LangChain
callback handler asks the gate on `on_chat_model_start`, raises on refusal,
and records usage and version on `on_llm_end`. Tested with the library's
own fake chat model.

**P-MC.9 — nothing prior moves.**

**P-MC.10 — the saving is a number, and it is synthetic.** Over a scripted
run of 100 steps where TOOL content is present in 70, with the example
price table and 2,000 tokens per step, the policy above sends 70 steps to
the cheaper model and the priced difference against sending all 100 to the
larger one is reported. The number is arithmetic on a table and says
nothing about any real workload; it is reported because the site will be
asked for it.

## Scope

In: `models` in policy, validation at adoption, `before_model_call`,
`record_model_usage`, the `model` lock kind, the record, alerts, trace, the
LangChain handler, tests, conformance additions. Out: any proxying, the
Claude Code and MCP adapters (no model call is visible there, stated), a
second adapter, Azure or any provider integration.
