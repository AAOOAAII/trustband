# Phase 8b — the provenance lockfile. Gates before the code.

**Registered 2026-09-03, before any implementation. Base: `aeeb154` on
`phase8-surfaces`. The centrepiece of the September surfaces document.**

## What this is

`trustband.lock`: for every tool, skill and MCP server an adapter can see, a
digest of description + parameter schema + version, recorded at first
approval and verified on every load. Drift refuses under enforce, flags under
shadow, and is an event in the sealed log either way.

**The manifest digest is a field of the policy, so it is in the policy
digest, so it is in the capability MAC.** A capability minted under manifest
v1 is dead under v2 at conjunct (G) — the Phase 2 mechanism, already proved
and already deposited. Verified before registration: the encoder covers
unknown top-level keys, so `policy["lock"]` changes the digest with no
encoder change. This is the one claim here that is machine-checked without a
proof extension, and the documents must say so precisely: the *binding* is
proved; the *pinning* is conformance-held.

## What it is not, stated first

- **A pin does not say the first version was clean.** Scanning does that.
  What a pin gives is that clean-then-dirty is caught, and clean-then-dirty
  is the attack pattern: nobody ships poison in 1.0.0 when they can ship it
  in 1.0.16.
- **Descriptions are banded TOOL at first sight, not scanned for meaning.**
  BYO scanner — mcp-scan in CI, trust.band at the gate — is the posture,
  and the page says so.

## The design decision, registered as a gate rather than assumed

**P-P8b.0 — one digest, global invalidation, and the cost is measured.** The
policy digest is one value. A description change on server X invalidates
every outstanding capability for server Y until re-approval. Under shadow
that is a flag; under enforce it is a stop. This is stated on the page as
*the friction is the security*, and the benign-drift rate is measured during
shadow on real traffic before enforce is recommended. A per-tool binding
would mean a new field in `Cap`, which is a proof change; it is taken only if
the measured cost demands it, and it is not taken here.

## Registered predictions

**P-P8b.1 — pin on first approval, verify on every load, per adapter.** What
each adapter can see, and therefore pin, differs and is stated:

| adapter | pins | sees drift at |
|---|---|---|
| MCP proxy | every tool in `tools/list`: name, description, inputSchema | every `tools/list` response |
| LangChain / LangGraph / CrewAI | every wrapped tool: name, description, `args` schema | `guard_tools` and every call |
| Claude Code hook | MCP server entries in the settings file (command, args, env names) and skill files under `.claude/skills` | every invocation — the hook cannot see `tools/list`, and says so |

**P-P8b.2 — drift refuses under enforce and flags under shadow.** A changed
description, a changed schema, a new tool, a removed tool, a reordered
catalog that is otherwise identical (must NOT drift). Each is a case.

**P-P8b.3 — the diff is in the record.** One `lock_drift` entry per changed
item: which, from what digest, to what digest, and the redacted before/after
description. Rendered by `trace`; exported by `export`; delivered by the
`lock_drift` webhook class from Phase 8a.

**P-P8b.4 — the binding is a MAC failure, not a check.** A capability minted
under manifest v1, presented after the manifest moved to v2, is refused at
(G) by the gate, with no lockfile code in the path. Witnessed by a
counterexample in the style of the crate: the policy digests differ, the
tag was computed under v1, (G) refuses by digest comparison. The prior
counterexamples are re-run unchanged.

**P-P8b.5 — re-approval is explicit and recorded.** `trustband lock accept`
re-pins after a human has seen the diff. Never automatic. Under the
unattended dispositions, drift with nobody present is `deny` unless the
operator chose otherwise, and the record says nobody approved it.

**P-P8b.6 — tool shadowing is refused by two mechanisms, both existing.**
The malicious server's description is pinned (drift caught) and TOOL-banded
(cannot raise its own trust); the misuse of the trusted server is refused
because the argument's provenance is TOOL. Measured with Invariant's shape:
a trivia server whose description instructs use of a messaging server.

**P-P8b.7 — nothing prior moves.** 47 tests, 22/22, 8/8, 7/7, zero
dependencies, and `describe_custody()` unchanged.

## Joins — the rate has been one defect per ten pairs

| # | pair | what must hold |
|---|---|---|
| 1 | lockfile ↔ policy digest | the lock's digest is in the policy digest; changing the lock changes `gov_policy` at the next `adopt` |
| 2 | lockfile ↔ adopt | re-pinning goes through `Issuer.adopt`, so the evaluator and the gate move together — the desync that was fixed once in issuance |
| 3 | lockfile ↔ MCP `tools/list` | the pin is taken from the response the client will actually read, after `_scan_descriptions`, not before |
| 4 | lockfile ↔ store | a pinned description is remembered TOOL in the session store, so text lifted from it into an argument is TOOL |
| 5 | lockfile ↔ shadow | drift flags, capabilities keep minting, the digest still changed, and the record says both |
| 6 | lockfile ↔ key file | two processes on one key file and one lockfile: drift seen by P1 is seen by P2 on its next load |
| 7 | lockfile ↔ canonicalisation | the digest is over canonical bytes — `policy.encode` — so NFC-distinct strings that render alike do not pass as unchanged |
| 8 | lockfile ↔ hook exit | the Claude Code hook re-reads the lock every call, deterministically, and never writes it unless told to accept |
| 9 | lockfile ↔ redactor | the before/after in the drift record is redacted |
| 10 | lockfile ↔ old configs | a config with no lock behaves exactly as 0.3.x: nothing pinned, nothing refused, `trustband lock init` offered |

## Out of scope

Skills for the framework adapters (no surface); dependency pinning (`pip`
does that); scanning description content for injection (BYO).

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
