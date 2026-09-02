# P1 — framework adapters. Gates registered before the code.

**Registered 2026-09-02, before any adapter source. Base: F3 at `e18a439`.**

## What the plan assumed, and what is true

The build map says four adapters — LangChain, LangGraph, CrewAI, GitHub Actions
— at roughly a day each, "against a known interception point". Two findings
change the shape:

**A LangChain callback cannot refuse.** `on_tool_start` returns `Any` and
LangChain does not consult it. `BaseCallbackHandler` is an observer. An adapter
built on callbacks can record provenance and run shadow, and **cannot enforce**
— which would make it a different product from the Claude Code adapter, whose
whole point is that the tool runs only if the gate accepts it. The interception
point that *can* refuse is the tool itself: `BaseTool.run` raises on error and
`handle_tool_error` exists, so a wrapper can deny by raising.

**CrewAI is not installed and LangChain, langchain_core 1.6.1 and LangGraph
are.** An adapter I cannot execute against the real library is an assertion,
and this project does not ship assertions as adapters.

## Registered predictions

**P-P1.1 — the LangChain adapter refuses, not merely observes.** A tool wrapped
by it, given an argument derived from prior tool output, does not execute.
Checked by a tool that records whether its body ran: if the body ran, the
adapter failed regardless of what it returned.

**P-P1.2 — both hooks, or it is not an adapter.** Provenance is banded from
tool output on the way back, so a later argument built from it is caught. An
adapter implementing only the authorize half has shipped a policy engine, which
`conformance.py` already refuses for the existing two.

**P-P1.3 — it passes the existing conformance suite unchanged.** No new
assertions written to accommodate it. The suite was frozen before these
adapters existed and is the thing that stops two adapters becoming two
products.

**P-P1.4 — shadow refuses nothing.** Same discipline the call cap broke in F2.
A wrapped tool in shadow mode executes and the would-be refusal is recorded.

**P-P1.5 — sessions are distinct.** Two runs under one adapter do not share a
provenance store. A framework that supplies no session identity must be made to
supply one rather than silently sharing, exactly as the Claude Code adapter
refuses an empty session.

**P-P1.6 — verified against the real library, or not shipped.** Every adapter
claimed on the site runs against the installed framework in this repo's tests.
CrewAI is not installed; either it is installed and verified, or it is not
claimed. No adapter ships on a read of someone's documentation.

## Scope

In: LangChain (tool wrapper, enforcing) and LangGraph, both verified against
the installed libraries.

Out, and named: CrewAI, unless installed and verified — the honest outcome may
be that it is not in this phase. GitHub Actions is **not an adapter**: there is
no agent runtime to intercept. Running trustband in CI is a `verify` command
and belongs with P3 contracts, and the comparison-table row should say so
rather than counting it as a fifth integration.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
