# F4 — replay. Result.

**Run 2026-09-02 against `F4_REPLAY_GATES.md`, registered before the code.**

## Gates

| gate | verdict |
|---|---|
| P-F4.1 replay reproduces the record | **PASS-CLEAN** after the record was fixed |
| P-F4.2 provenance rebuilt from result events | **PASS-CLEAN** |
| P-F4.3 monotonicity | **PASS-CLEAN** |
| P-F4.4 the diff names what changed | **PASS-CLEAN** |
| P-F4.5 replay is read-only | **PASS-CLEAN** |
| P-F4.6 nothing prior moves | **PASS-CLEAN** |

## P-F4.1 caught the feature lying, on the first run

Before any fix:

```
self-check: reproduced 1/2
  seq 1 run_cmd: recorded refuse, replay allow
```

The record held `strings_remembered: 1` and a band — **not what the tool
returned**. So the replayed provenance store was empty, the tool-derived
argument looked session-authored, and the taint refusal vanished.

Shipped without this gate, replay would have told a user their candidate policy
refuses nothing. That is the most reassuring possible wrong answer, produced by
a feature that looks like it is working.

This is the third instance of one defect shape in this codebase — a field
computed and not written — and the first where the consequence was a feature
**alive and lying** rather than dead.

## The fix, and the honest half of it

Result events now record what the tool returned, redacted by F5 and capped.
**Off by default**, because tool outputs are large and this is the log a person
reads.

Which means most logs cannot be replayed — so replay **refuses** rather than
under-reporting:

```
cannot replay: this log has 1 result event(s) and none records what the tool
returned, so provenance cannot be rebuilt. Replay would report fewer refusals
than the truth.
```

Refusing is the only honest answer available. Under-reporting was the
flattering one and it was what the code did an hour ago.

With recording on:

```
self-check: the recorded policy reproduces 3/3 recorded decisions
```

## P-F4.3 — monotonicity

```
recorded   refusals=1   changes vs record=0
tighter    refusals=2   changes vs record=1
looser     refusals=0   changes vs record=1
```

Not a proof of correctness, but a replay that violated it would be wrong in a
way arithmetic catches.

## P-F4.4 — a diff, not a number

```
3 recorded decision(s); the candidate policy changes 1
  1 that were allowed would be refused
  0 that were refused would be allowed

  seq 3    send           allow -> REFUSE   grant 0 -> 0
        to=ops@evil.io
```

Grant identity on both sides is what the P-F0.5 work bought: a reader can see
which rule decided before and after, not only that a count moved.

## P-F4.5 — read-only

```
audit log unchanged: True
notifier fired during replay: False
```

Replaying a week of traffic appends nothing and alerts nobody. The replay Guard
is constructed in shadow with no audit path, so both properties are structural
rather than remembered.

## Limits

- **`record_results` costs log size.** Capped at 4000 characters per result by
  default and redacted first, but it is still the tool output on disk. An
  operator turns it on to gain replay and should know what they are storing.
- **A session recorded before enabling it cannot be replayed**, and replay says
  so rather than guessing.
- **Not against a different model.** The record holds what the model did, not
  what another would do.
