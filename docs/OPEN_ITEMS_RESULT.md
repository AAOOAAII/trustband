# Closing the open items — result

**Run 2026-09-02 against `OPEN_ITEMS_GATES.md`, registered before the code.**

## Gates

| gate | verdict |
|---|---|
| P-OI1 the record names who handed off | **PASS-CLEAN** |
| P-OI2 attribution does not weaken isolation | **PASS-CLEAN** |
| P-OI3 the deciding rule is an identity | **PASS-CLEAN** |
| P-OI4 the identity is stable and honest | **PASS-CLEAN** after a fix |
| P-OI5 enforcement unchanged | **PASS-CLEAN** |

## P-OI1 / P-OI2 — the name crosses, the store does not

```
result   session=A  tool=read_page  from=None
result   session=B  tool=handoff    from=A
```

B's record now says its taint originated with A. Isolation is unaffected:

```
A store entries: 1   B store entries: 1   shared object: False
B can recall A's page text: False
```

That is the point. Merging the stores would have given attribution and
destroyed the property provenance is scoped for. Only the name crosses.

## P-OI3 / P-OI4 — the rule, not the sentence

This closes the P-F0.5 PARTIAL carried since F0.

```
run_cmd       allowed=False  grant=1   taint: cmd is tool, needs session
run_cmd       allowed=True   grant=1   granted by session … at tier <= 2
read_page     allowed=True   grant=0   granted by session … at tier <= 2
unknown_tool  allowed=False  grant=0   action 'unknown_tool' not in the actions granted
```

The issuer tracked `last_reason` — the most specific *message* — and no
identity. Grouping decisions by message text is not grouping them by rule, and
F4 replay needs the rule.

**The fix needed fixing.** The first version set the identity only on the
refusal path, so every permitted call recorded `grant=None` — which reads as
"no rule decided this" and is false. A replay would have been unable to group
allows by rule at all. Allows now name their grant.

Where genuinely no grant matched, the record still says `None` rather than
naming an arbitrary one, because an identity pointing at the wrong rule would
have a replay attribute a decision to a rule that did not make it.

## What did not close, and will not

Recorded so it is not carried as a roadmap item that quietly never ships:

- **Paraphrase / authorship.** Not closable by provenance. Token matching helps
  partially at a measured 4.9% false-positive cost; the quarantined extractor
  is the only real answer and is unbuilt.
- **Answer-channel exfiltration.** Structural. Provenance gates tool calls, not
  the model's reply to the user.
- **Closed platforms.** ChatGPT, Gemini, hosted Assistants and Bedrock execute
  tools server-side. No interception point exists at any price.
- **One model.** Frontier models refuse these attacks unaided and the 14B used
  for prior runs is gone.

## Measurable but unmeasured, each needing its own phase

Cross-session memory. Async and queued execution. The plan's utility cost under
a live agent — every plan result so far is at the gate, and whether a model
works usefully under a fixed plan is a different question.

## Regression

```
conformance 18/18 · policy 87/87 · custody 13/13 · battery 6/6 · sweep 0
browser replay unchanged: quoted 5/5, markup 5/5
```
