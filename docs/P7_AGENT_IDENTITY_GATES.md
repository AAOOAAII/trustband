# Phase 7 — local agent identity. Gates before the code.

**Registered 2026-09-02, before any implementation. Base: `d4b79d7` on
`phase7-agent-identity`. Overnight run, authorised.**

## What this is

A named agent, bound into the key hierarchy the product already runs on. Not a
portable passport: nobody outside the key can verify it, and that is the
point of doing it with a MAC rather than a signature. The gate that mints is
the gate that checks.

`AgentId(name, role, session)` carries `tag = MAC(epoch_key, "agent" ‖ name ‖
role ‖ session)`, computed inside the key store so the key never leaves.
The tag rides on every `ToolCall`, lands in every log entry, is bound into the
capability MAC, and can be revoked structurally.

Three existing conjuncts, applied to a new identifier. No new primitive, no
new dependency.

## What it is not, stated first

- **Not third-party verifiable.** Cross-organisation identity remains an
  Open Agent Passport concern. This phase does not consume OAP; that is a
  follow-up, and when it lands an unverified passport is a *label*, never an
  authorisation input.
- **Not in the deposited proof.** The Verus model does not know about agents.
  Until a Phase 7b extends it, these checks are held by the conformance suite,
  and every document that says "machine-checked" must say so.
- **Not a shared audit log.** Two processes do not write one chain. Each
  process keeps its own log; see pair 5.

## Registered predictions

**P-P7.1 — the name lands in the record and renders from it.** `trace` shows
`researcher → send_message` read from `audit.jsonl`, not from a live object.
The test goes through the log, because a field that is computed and never
persisted has passed unit tests here before.

**P-P7.2 — a capability minted for A, presented by B, is refused.** The agent
tag is an input to the capability MAC. Shape of conjunct C.

**P-P7.3 — a forged or absent tag is refused.** A name with no tag, a tag
computed under a different key, and a well-formed tag for a name never minted
all refuse. Shape of conjunct B. In shadow mode these are recorded as
would-refuse and the call proceeds.

**P-P7.4 — revocation is structural.** `revoke_agent(name)` refuses every
later call by that agent by set membership, using no property of the MAC, and
leaves every other agent untouched. Shape of conjunct H.

**P-P7.5 — the cross-process case works, and every join is named.** A swarm
split across processes means separate Guards, and the MAC only verifies where
the key lives. Free tier: a shared local key file. That is a new join — key
file, adapter, Guard — and this project's defect rate at joins has been steady
all week. The pairs, each with its test:

| # | pair | what must hold | failure this catches |
|---|---|---|---|
| 1 | key file ↔ Guard | two Guards on one file verify each other's tags; a Guard on a different file refuses | key silently regenerated per process |
| 2 | key file ↔ epoch | a tag minted before rotation refuses after it (shape of F); the file records the epoch, not just the key | rotation in one process invisible to the other |
| 3 | key file ↔ write | the file is written atomically (temp + rename) and read with a mode check; a partial file refuses rather than minting under an empty key | two processes racing on first run |
| 4 | adapter ↔ key file | both processes resolve the *same* path from the same config; an adapter that cannot find the file refuses to mint rather than minting locally | env-var in one shell, default in the other |
| 5 | Guard ↔ Guard, audit | each process writes its own chain; `trace` merges by agent across files and says which file each line came from | two writers corrupting one chain |
| 6 | revocation ↔ processes | `revoke_agent` in P1 is honoured in P2 within one call; the set lives beside the key file, re-read on every check, never cached | stale in-memory set |
| 7 | per-call subprocess ↔ identity | the Claude Code hook, which is a fresh process per call, re-derives the identical tag from (name, role, session) without persisting it | tag drifts between calls |
| 8 | handoff ↔ identity | `handoff()` records from-agent and to-agent; the payload stays TOOL-banded | identity laundering the taint |
| 9 | shadow ↔ identity | every identity refusal obeys shadow mode | a new check that ignores the install path |
| 10 | entitlement ↔ identity | enforcement identical under every entitlement state, extended to the three new checks | a billing state changing a security decision |
| 11 | old logs ↔ trace/replay | a 0.2.x log with no agent field renders and replays; missing is shown as missing | a crash on every existing install |

**P-P7.6 — nothing prior moves.** 22 tests, 18/18 conformance, every pack
loads, zero runtime dependencies, `describe_custody()` unchanged.

**P-P7.7 — adapters mint it.** LangGraph from the node name, CrewAI from
`agent.role`, MCP from the client's `initialize` name, Claude Code from the
session. Each tested against the installed library, as P1 was.

## Scope

In: `identity.py`; `agent` on `ToolCall`; the three checks in `Guard`; the tag
in the capability MAC; `revoke_agent`; the key-file custody for cross-process;
`trace` and `export` carrying the name; the four adapters; conformance
additions; the eleven pair tests.

Out, and named: OAP consumption; Ed25519; the proof extension; a shared
multi-writer audit log; fleet views.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
