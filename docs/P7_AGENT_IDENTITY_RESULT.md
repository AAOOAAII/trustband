# Phase 7 — local agent identity. Result.

**Run overnight 2026-09-02 → 03, against the gates registered at `P7_AGENT_IDENTITY_GATES.md` before any code. Branch `phase7-agent-identity`. Not merged, not mirrored, not released.**

## Verdict: PASS-WITH-DRIFT

Every registered prediction holds. The drift is one defect found by attacking
a registered join rather than by the test that was written for it — pair 2
was half-tested, and the untested half was live.

## The numbers

| | before | after |
|---|---|---|
| tests | 22 | **47** (25 new, 11 of them in a real second process) |
| conformance | 18/18 | **22/22** |
| battery | 8/8 routes, 6/6 attacks refused, 2/2 properties | unchanged |
| packs | 7/7 load | 7/7 |
| runtime dependencies | 0 | **0** |
| in-process `describe_custody()` | 12 fields | identical |

## What each prediction did

**P-P7.1 — the name lands in the record and renders from it. PASS.** Asserted
from `audit.jsonl` on disk, then through `trace.render`, not from the live
object. `researcher · read`, and `1 named agent(s): researcher` in the
summary line. Result events carry the name too.

**P-P7.2 — a capability minted for A, presented by B, is refused. PASS,
conjunct C.** The agent's *principal* — an integer derived from its verified
tag — stands where the session goes in `govern_issue`, so the gate's own (C)
refuses it and `Cap` never moved. `Runtime.call(agent=…)` verifies the
identity first and mints for the principal; a forged identity stops at stage
`identity` and never reaches the gate.

**P-P7.3 — a forged or absent tag is refused. PASS, conjunct B.** Four
shapes: a flipped tag, an empty tag, a genuine tag under a different key, and
a genuine tag with the name changed. All B. `identity.required` refuses a
bare call.

**P-P7.4 — revocation is structural. PASS, conjunct H.** `revoke_agent` by
name refuses every later call by set membership; the reason says *no MAC
property used* and it is true. By `AgentId`, it also bumps the gate's session
epoch for the principal, so a capability minted before the revocation is
dead at the gate's own (H), verified directly on `authorize`. The other agent
is untouched.

**P-P7.5 — the cross-process case, every join named. PASS, with the drift
below.** Each pair has a test, and every one that claims two processes runs
two processes: a second object in the same process would share the same
random key and pass for the wrong reason.

| # | pair | result |
|---|---|---|
| 1 | key file ↔ Guard | verifies across processes; a different file refuses at B |
| 2 | key file ↔ epoch | a tag minted before a foreign rotation refuses at F; the file records the epoch and the retired key is gone from it — **and see the drift** |
| 3 | key file ↔ write | a partial file and a group-readable file both refuse with `CustodyError`; six processes racing on first run agree on one key and leave no temp files |
| 4 | adapter ↔ key file | `from_file` keeps the key beside the config, two Guards from one config agree; `"keys": "in_process"` opts out and then they do not |
| 5 | Guard ↔ Guard, audit | one log per process; `trace --also` merges by timestamp, names both agents, marks each line's file, verifies both chains |
| 6 | revocation ↔ processes | `trustband revoke-agent` from a second process is honoured on the next call; a corrupt revocation file fails closed |
| 7 | per-call subprocess ↔ identity | three fresh interpreters re-derive the byte-identical tag |
| 8 | handoff ↔ identity | from-agent and to-agent recorded; the payload stays TOOL-banded and B's later use of it refuses |
| 9 | shadow ↔ identity | a forged identity in shadow is permitted, recorded as would-refuse with the name |
| 10 | entitlement ↔ identity | the three new checks are identical under seven entitlement states, and correct |
| 11 | old logs ↔ trace/replay | a record with no agent field renders, says nothing about agents, and replays |

**P-P7.6 — nothing prior moves. PASS.** Table above.

**P-P7.7 — adapters mint it. PASS.** Claude Code re-derives across two
`from_file` Guards with `subagent_type` as the role; MCP mints from
`clientInfo.name` on `initialize` and the tools/call record carries it;
LangGraph from the node name, refusing an empty one; CrewAI from `role`,
refusing an empty one, and read from a real `crewai.Agent` when one is
constructible offline.

## The drift: pair 2 was half-tested, and the other half was live

The registered test proved that a *tag* minted before another process's
rotation refuses after it. It did not prove that the other process's *Gate
keeps working*. Re-reading `govern_issue` suggested it would not: `gov_epoch`
is in-process, so after P1 rotated the file, P2 would call `keys.tag(0, …)`
on a key the file had discarded.

Reproduced before fixing:

```
P2 after foreign rotation: CRASH KeyError 'epoch 0 was discarded at rotation'
```

A crash where the model says a refusal at (F). Guards do not mint per call,
so the adapter path never hit it; `Runtime.call` in a second process did.

The fix is `Gate._follow_keys()`: when the key store's epoch is ahead of the
gate's, adopt it — same write to `gov_epoch`, same fresh budget, same
discarded key as `govern_rotate`. It is that transition observed late, not a
new one. Called at the top of `govern_issue`, `authorize` and
`govern_rotate`, the last so that two processes each rotating once end at
epoch 2 rather than both at 1. In-process the store can never be ahead, so
for the deposited model's own configuration it is a no-op, checked.

Test `pair2b` now covers both halves: P2 keeps minting after P1 rotates, at
epoch 1; P2's pre-rotation capability dies at F; P2 rotating afterwards goes
to 2.

## What this does not show

- **Not in the deposited proof.** Four refusals, four conjunct shapes, none
  proved. The conformance suite holds them. Phase 7b is the proof extension,
  and until it lands the comparison-table cell reads *local, MAC-bound;
  conformance-held*, not *machine-checked*.
- **Not third-party verifiable.** Deliberately. OAP consumption is the
  follow-up, and an unverified passport will be a label.
- **One audit chain per process.** Two processes do not write one chain and
  are not made to. `trace --also` reads them together.
- **Custody is a file.** Every process of the user that can read `keys.json`
  holds the epoch key. `describe_custody()` says exactly that. Hosted key
  custody is the Pro answer and is not built.
- **No fleet view.** The record names agents; nothing yet groups by them
  beyond the summary line in `trace`.

## Follow-ups, named

1. Phase 7b: extend the Verus model with the agent principal, prove the four
   shapes, redeposit.
2. Consume OAP as a label; Ed25519 verification as an optional extra.
3. Update the site's comparison row — it still says *No*.
4. Fold `revoked_agents.json` and `keys.json` into `trustband status`.
