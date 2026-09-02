# trustband — what it is, what's proven, what isn't

> **Naming (2026-08-31):** The product surface was renamed to **trustband**
> on this date. **warrantable** remains the name of the enforcement layer and
> the Zenodo deposit (10.5281/zenodo.22115781). Evidence documents that predate
> the rename — the `*_GATES.md`, `*_RESULT.md`, and status snapshots — keep the
> original name deliberately: they record predictions registered before their
> runs, and were true under that name.


One page over ~15 scattered design and result docs. Start here.

---

## What it does

An LLM agent reads something — a web page, a file, a tool's output — and then
acts on it. trustband tracks **where each argument to a tool call came from**,
so a policy can refuse a payment to an account number that arrived from a web
page while allowing one the user typed. Every decision an adapter makes, allowed or
refused, lands in a hash-chained log on disk, resumed across processes so the
chain survives a hook that exits after one call. An edit or a reorder is
detectable; a truncated tail is not. A `Guard` constructed directly with no
`audit_path` writes nothing.

Most agent-authorization tools decide on the call's *parameters*. trustband
decides on their *provenance* too. That is the whole difference, and it is the
one thing no competitor measured here has.

## The claim, stated as narrowly as the evidence allows

**Where a policy can list the allowed values, provenance adds nothing. Where it
can't, provenance is the only thing that works.**

| suite | what a value is | ungated | params-only | trustband |
|---|---|---|---|---|
| AgentDojo banking | enumerable (payees) | 36/144 attacks | 0/144 | 0/144 |
| AgentDojo slack | free text | 46/105 | 46/105 | 22/105 |
| AgentDojo slack (2nd attack) | free text | 40/105 | 37/105 | 9/105 |

A params-only engine — which is what APort's shipped policies are, confirmed by
running their code — performs like no defence at all on free text. On
enumerable values an allowlist does the whole job and we have no edge. Every
number sits beside its undefended baseline, because a defended number alone
describes the model, not the defence.

## The limits, up front

- **Only verbatim survival is caught.** A payload that reaches the argument as a
  substring of tool output is caught. A quoted injection into a coding agent
  survived verbatim 8/8 on a susceptible model and was caught; the same attack
  in prose was paraphrased and survived 0/5, so it passed. Token-level matching
  closes part of this gap but is opt-in (below).
- **Frontier models refuse most attacks unaided.** Sonnet 4.5 contained 72/72
  AgentDojo attacks with nothing installed; Haiku 4.5 refused 20/20 injected
  coding tasks. On such models the value is the audit trail and the zero
  benign-utility cost, not interception. All attack numbers above are from a
  susceptible open-weights model (Qwen2.5-14B).
- **One model, three suites, three attack phrasings.** Not an adaptive attacker.
- **Implicit flows launder taint**, as they defeat every dynamic taint system.

## What's built and installable

`pip install trustband`, standard library only, no dependencies.

```
trustband init            starter policy + hook config, shadow by default
trustband packs           three starters, each with its measured number
trustband shadow-report   what it would have refused, on your own traffic
trustband infer           a policy that permits exactly what you did
trustband test <file>     policy unit tests in milliseconds
trustband explain ...     which rule decided, and why
trustband status          your tier, and what does not depend on it
```

**Tiers do not touch enforcement.** Free is the whole enforcement layer,
self-hosted. Pro and Enterprise add *hosted services* — retained audit history,
routing an approval to someone other than whoever is at the keyboard, one policy
across a fleet. There is no local licence check to forge, because there is
nothing local to unlock.

So a lapsed key stops the hosted parts and nothing else: enforcement, provenance,
local audit and shadow carry on unchanged. That is not a policy we promise, it is
a conformance check — decisions are byte-identical under no key, a valid key, an
expired key and a forged one, and `guard.py` contains no reference to a key or a
tier through which it could learn otherwise. A security tool that fails open on
an unpaid invoice is worse than no security tool.

**The install path is the product.** It starts in shadow — refuses nothing,
records everything — so an operator sees the cost on their own traffic before
enforcing. A competitor that enforces from the first call cannot offer that, and
it is the objection ("will this break my agent?") that gets security tools
uninstalled.

**Adapters:** Claude Code (`PreToolUse`/`PostToolUse` hooks) and MCP (a stdio
proxy that gates `tools/call` and bands results). A conformance suite every
adapter must pass keeps them from drifting into two products.

## What's proven vs. asserted

**Proven / measured:**
- the attack and utility numbers above, each with a baseline and a registered
  prediction committed before the run
- gate decision latency 0.082 ms p50, in-process, no network
- 1,119 real tool calls replayed with no crashes and sub-ms latency
- the enforcement core follows a Verus model: 31 obligations, 17 counterexamples
  rejected — the *model* is proven, the Python implementation follows it and is
  checked by a conformance harness, not itself proved
- KMS custody validated against a real CMK, zero key bytes in process

**Asserted / not yet done:**
- no human outside the build sessions has installed or used it
- the Claude Code hook field names are verified against two official plugins but
  not against a live build
- token matching's real-world false-positive rate (4.9% on one transcript) is
  measured on one person's traffic
- no pilot, no customer, no revenue

## The opt-in that needs judgement

**Token matching** recognises a tool-returned distinctive token (a domain, an
IBAN) inside an argument the model paraphrased — closing part of the prose gap.
It is **off by default**: on real coding traffic it flagged 4.9% of commands,
and those were real domains (`doi.org`) that legitimately passed through tool
output. Silent enough to enable after watching it in shadow, too noisy to force
on. That is the honest shape of the whole product: provenance is a real signal,
not a silent one.

## Where the docs are

| topic | doc |
|---|---|
| the full measurement arc, all predictions incl. failures | `docs/MEASUREMENT_RESULT.md` |
| strategy, competitors, free/paid line | `docs/COMPOSITION_STRATEGY.md` |
| the Guard interface every adapter implements | `docs/GUARD_INTERFACE.md` |
| does a payload survive verbatim (the beachhead) | `docs/VERBATIM_SURVIVAL_GATES.md` |
| token matching result | `docs/TOKEN_MATCH_GATES.md` |
| value predicates spec | `docs/VALUE_PREDICATES_SPEC.md` |
| the product build plan | `docs/PRODUCT_PLAN.md` |

## The one-line version

Against a susceptible model, provenance catches copy-able injections that
params-only engines miss. Against a frontier model, the value is the audit
trail and zero utility cost. The product installs, runs shadow-first, and is
honest about a narrow, measured claim — which is worth more than a broad one
nobody can check.
