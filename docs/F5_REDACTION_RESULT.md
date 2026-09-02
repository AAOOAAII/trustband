# F5 — result

**Run 2026-09-02 against `F5_REDACTION_GATES.md`, registered in `c7255ba`
before the code.**

## Gates

| gate | verdict |
|---|---|
| P-F5.1 known secret shapes are redacted | **PASS-CLEAN** |
| P-F5.2 false-positive rate measured, ≤2% | **PASS-CLEAN** — 0.0% |
| P-F5.3 redaction happens before disk | **PASS-CLEAN** |
| P-F5.4 enforcement sees the real value | **PASS-CLEAN** |
| P-F5.5 a redaction is visible | **PASS-CLEAN** |
| P-F5.6 configurable, on by default | **PASS-CLEAN** |

## P-F5.2 — the number the design turned on

```
decisions            300   (real traffic, an actual session)
decisions redacted     0
rate                 0.0%   ceiling 2%
naive regex baseline  73    24.3%
```

The naive rule the plan implied — `api_key|token|secret|password|bearer|sk-` —
would have redacted **a quarter of every trace**: `K.to(float32)`,
`echo "=== venv modal ==="`, ordinary code edits. That is not a tuning problem,
it is the difference between a log a user reads and a log they turn off.

Matching **credential shapes** instead of **English words** costs nothing
measurable. `ghp_` followed by twenty base62 characters is a GitHub token; the
word "token" in a sentence is a sentence.

## P-F5.1 / P-F5.3 — what actually lands on disk

Read from `audit.jsonl`, not from rendered output, because a filter that
redacts in the viewer while the raw value sits in the file protects nothing and
looks like protection:

```
openai   export OPENAI_API_KEY=[redacted:openai-key]
github   git push https://[redacted:github-token]@github.com/x/y
aws      aws configure set aws_access_key_id [redacted:aws-access-key]
pypi     twine upload -p [redacted:pypi-token]
slack    curl -H 'x: [redacted:slack-token]'
pem      [redacted:private-key]
jwt      Authorization: [redacted:jwt]
named    [redacted:named-secret]          (argument called api_key)

raw secrets found on disk: 0
```

The surrounding context survives, which is the point — a trace still shows that
a push happened and to where, without the token.

## P-F5.4 — redaction must not move a decision

The gate evaluates the real value; only the record is redacted:

```
redaction on   allowed=False  taint: command is tool, needs session
redaction off  allowed=False  taint: command is tool, needs session
identical decision: True
```

The test uses a secret that arrived through tool output, so provenance must
still refuse it. A redactor that changed what the gate saw would be a bypass
dressed as a privacy feature.

## P-F5.5 / P-F5.6

A redacted argument is still present with a marker naming what matched, so a
reader can tell a redaction from an absent value — silence would make the trace
lie by omission. On by default; `redact: false` or `redact: {enabled: false}`
turns it off; custom patterns append rather than replace.

On by default is a deliberate difference from token matching, which is off at a
measured 4.9% false-positive rate. At 0.0% this costs the user nothing they
notice, and the failure mode of "off" is credentials in a file they did not
know they were writing.

## Corrections to the plan

**No existing rule was generalised.** The build map describes F5 as
generalising "the existing rule (exception types, never messages)". No such
rule exists — scattered `type(e).__name__` format strings and no filter
anywhere. F5 is new.

**Tool outputs are not redacted, because they are not recorded.** The record
holds argument values and a count of strings remembered, not the outputs
themselves. When outputs are recorded, they need their own pass.

## Regression

```
conformance 18/18 · policy 87/87 · custody 13/13 · battery 6/6
sweep 0 suspects · pairs 0 suspects · adapter, MCP, tool-desc, extractor pass
stdlib only: re, typing
```
