# Closing the open items — triage, and gates for the two that close

**Registered 2026-09-02. Base: handoff at `46b2d6b`.**

## Triage

| open item | closable | how |
|---|---|---|
| handoff attribution | **yes, now** | record the originating session on the result event |
| deciding rule is prose, not an identity (P-F0.5) | **yes, now** | surface the matched grant from the issuer |
| host must call `handoff()` | **partly** | the adapters can call it; a host that does not is the same contract `after_tool_result` already carries |
| paraphrase / authorship (0/5 prose) | **no, not by provenance** | token matching partially; the quarantined extractor is the only real answer and is unbuilt |
| cross-session memory | **measurable, unmeasured** | its own phase |
| async / queued execution | **measurable, unmeasured** | its own phase |
| answer-channel exfiltration | **no** | structural: provenance gates tool calls, not the model's reply |
| closed platforms | **no** | no interception point exists at any price |
| plan under a live agent (utility) | **measurable, unmeasured** | needs an agent loop, not a gate test |
| one model | **no, here** | frontier models refuse unaided; the 14B is gone |

Four of these do not close, and saying so is more useful than a roadmap item
that quietly never ships. Two close now.

## Registered predictions

**P-OI1 — the record names who handed off.** A result event carries the
originating session, so a reader can tell that B's taint came from A rather
than from B's own reading. Absent today: `handoff()` passes `from` and the
result event drops it, because result events record no arguments.

**P-OI2 — attribution does not weaken isolation.** Recording *that* A was the
origin must not give B's store access to A's content, or expose A's values in
B's record. The stores stay separate; only the name crosses.

**P-OI3 — the deciding rule is an identity, not only prose.** A refusal records
which grant decided, by index, alongside the reason. This is the P-F0.5 PARTIAL
from F0, and it is the gate F4 replay needs: grouping decisions by prose text
is not grouping them by rule.

**P-OI4 — the identity is stable and honest.** Where no grant matched, the
record says so rather than naming an arbitrary one. An identity that points at
the wrong rule is worse than none, because a replay would then attribute a
decision to a rule that did not make it.

**P-OI5 — enforcement is unchanged.** Decisions byte-identical. The issuer is
the enforcement core and this is a reporting change; conformance 18/18, policy
87/87, battery 6/6.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
