# P3 — deliverable contracts. Gates before the code.

**Registered 2026-09-02, before any implementation. Base: P2 at `48a3561`.**

## What this is, and the claim it must not make

Every other rule here constrains **permissions**: may this call happen. A
contract constrains the **output**: coverage above a threshold, reviewer not
the author, a ticket closed by the commit, a required section present.

It sells to teams who do not fear injection, which is most teams on frontier
models, and it gives the product a job on days nobody is attacking.

**The claim is "contracts verify what is checkable", never "verifies quality".**
A coverage threshold says a number cleared a bar. It says nothing about whether
the tests are good, and a contract that implied otherwise would be the kind of
overclaim this product exists not to make.

## Why it belongs in this engine rather than beside it

Danger and Conftest already do PR rules well. The reason to build rather than
wrap either is that a contract outcome must land in **the same sealed log** as
enforcement decisions, readable by the same `trace` and `replay`. Two policy
engines means two records and the thesis dies. Their rule catalogues are worth
reading; their runtimes are not worth importing.

## Registered predictions

**P-P3.1 — a contract is evaluated on the RESULT, not the call.** It runs at
`after_tool_result`, sees what the tool produced, and can fail work that was
correctly permitted. A contract that only re-checks arguments is a permission
rule with a different name.

**P-P3.2 — contracts are shadow-first, per contract.** Default records and does
not block. Blocking is opt-in per contract, not globally, because a wrong
coverage threshold that blocks CI gets the tool removed on the first Friday.

**P-P3.3 — a contract failure lands in the same record.** Same `audit.jsonl`,
same chain, visible in `trace`, counted in `shadow-report`. If it needs its own
log, it does not belong here.

**P-P3.4 — a contract cannot change an authorization decision.** Contracts run
after the tool ran. They must not retroactively refuse a call, mutate
provenance, or alter what `before_tool_call` would decide.

**P-P3.5 — an unevaluable contract fails loudly, not silently.** A missing
field, an unparseable number, a threshold against absent data: refuse the
contract with a reason, never pass it because nothing was found. Absence has
never satisfied a constraint in this codebase and must not start here.

**P-P3.6 — nothing prior moves.** conformance 18/18, policy 87/87, battery 6/6,
adapters, browser replay, and every one of the seven packs still loads.

## Scope

In: a `contracts` section in the policy; operators for threshold, presence and
inequality over result fields; evaluation at `after_tool_result`; outcomes in
the audit record and in `trace`.

Out, and named: `trustband verify-deliverable` as a CI entry point, which is a
CLI shape question and can follow; git and GitHub integration — reviewer
identity and ticket state come from the host, and inventing them here would be
a contract about data trustband cannot see; anything that reads a repository.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
