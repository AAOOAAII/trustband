# Phase 8b — the provenance lockfile. Result.

**Run 2026-09-03 on `phase8-surfaces`, against the gates registered at
`P8_LOCKFILE_GATES.md` before any code.**

## Verdict: PASS-CLEAN on the predictions; PASS-WITH-DRIFT on the joins

Every registered prediction holds, including the one that matters most:
the binding to conjunct (G) is exercised with no lockfile code in the path.
One join defect was found by a test rather than anticipated by a gate, and
one test expectation of mine was wrong. Both recorded.

## The numbers

| | before | after |
|---|---|---|
| tests | 61 | **74** (13 new, one in a real second process) |
| conformance | 22/22 | 22/22 |
| battery | 8/8, 6/6, 2/2 | unchanged |
| runtime dependencies | 0 | 0 |

## What each prediction did

**P-P8b.0 — one digest, global invalidation, stated. PASS as a statement.**
The lock's digest is one field; re-accepting after any item changes moves
the policy digest and kills every outstanding capability. The benign-drift
rate is *not* measured here — it needs real traffic in shadow, and that is
the first thing to read off the first ten users.

**P-P8b.1 — pin on first approval, verify on every load, per adapter.
PASS.** MCP pins every `tools/list` entry (name, description, `inputSchema`)
and sees drift on every list; LangChain/LangGraph/CrewAI pin name,
description and `args` at `guard_tools`; Claude Code pins MCP server entries
from `settings.json` (command, args, URL, env *key names* — never values)
and skill files by hash, and states that it cannot see `tools/list`.

**P-P8b.2 — drift refuses under enforce, flags under shadow. PASS.** A
changed description, a changed schema, a new tool, a removed tool, and a
reordered-but-identical catalog (no drift) are each a case. Under shadow the
call proceeds and the shadow log carries would-refuse.

**P-P8b.3 — the diff is in the record. PASS.** One `lock_drift` entry per
changed item with from/to digests and redacted before/after; rendered by
`trace` as `!! tool:fetch changed since it was pinned`; exported with
`trustband.lock.item` and `trustband.lock.change`; delivered by the
`lock_drift` webhook class from Phase 8a.

**P-P8b.4 — the binding is a MAC failure, not a check. PASS, conjunct G.**
A capability minted under manifest v1 and presented after `accept_lock()`
moved the manifest to v2 is refused by `Gate.authorize` at (G) — the
policy-currency check that was proved in Phase 2 — with no lockfile code in
that path. Pair 1 (the lock digest is in `gov_policy`) and pair 2
(acceptance goes through `Issuer.adopt`) are asserted in the same test.

**P-P8b.5 — re-approval is explicit and recorded. PASS.** `accept_lock()`
writes a `lock_accept` entry with the item count and digest. Nothing
re-pins on its own.

**P-P8b.6 — tool shadowing is refused twice. PASS.** Invariant's shape: a
trivia tool whose description is rewritten to instruct a `send_message`
call with an attacker's number. The pin refuses the trivia tool; and the
number, lifted from the description into `send_message`'s argument, is
TOOL-banded because descriptions are remembered TOOL at observation — pair 4
— so the second call is refused on provenance with no lockfile involved.

**P-P8b.7 — nothing prior moves. PASS.**

## Joins

| # | pair | result |
|---|---|---|
| 1 | lockfile ↔ policy digest | `gov_policy == digest(policy)` with the lock field present |
| 2 | lockfile ↔ adopt | acceptance re-adopts; the gate's digest moves with the evaluator's |
| 3 | MCP `tools/list` | pinned from the response the client reads, after `_scan_descriptions`; a strict-mode replacement pins nothing |
| 4 | lockfile ↔ store | descriptions remembered TOOL; the shadowing argument refused on provenance |
| 5 | lockfile ↔ shadow | flagged, recorded, capabilities keep minting |
| 6 | lockfile ↔ key file | drift accepted by P1's lockfile is seen and refused by P2 |
| 7 | canonicalisation | NFD and NFC of the same description, and a reordered schema, are one pin; one added byte is not; floats in schemas pin stably |
| 8 | hook exit | the hook re-observes every call and never writes the lock |
| 9 | redactor | a credential shape in a changed description is absent from the drift record |
| 10 | old configs | no lockfile: nothing refused, observations go to `lock_pending.json`, `lock status` offers `accept` |

## The two things found on the way

**A fresh home broke the first observation.** `write_pending` opened its
temp file in a directory that did not exist yet. The audit log creates its
parent on first append, and the lockfile wrote before any append. A fresh
install would have hit it on the first `tools/list`. The atomic writer now
creates the parent.

**A corrupt lockfile is not "no lockfile".** Nothing pinned can be verified,
so nothing can be told from drift. It refuses every call with the reason,
rather than falling back to the 0.3.x behaviour and looking open. Tested.

**And one expectation of mine was wrong**: after a `removed` drift that was
never accepted, the pin still exists and the tool is still present, so a
later observation of it is `changed`, not `removed`. The code was right; the
test was corrected to match the registered semantics.

## What this does not show

- **The benign-drift cost under enforce.** Needs real traffic; measured in
  shadow first, as P-P8b.0 requires.
- **Whether the first pin was clean.** Scanning does that; the page says to
  run mcp-scan in CI and trust.band at the gate.
- **Skill drift refuses nothing.** A skill is instruction, not a call; drift
  is recorded and alerted, and there is no call to refuse.
- **Version fields.** Few catalogs carry one; pinned when present.

## Comparison-table cell

*Lockfile pinning, MAC-bound.* Same shape as the identity row: the thing
everyone does, plus the binding nobody has — and this one is inside the
deposited proof.
