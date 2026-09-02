# F5 — redaction. Gates registered before the code.

**Registered 2026-09-02, before any implementation. Base: F2 at `196982b`.**

## Why this moved ahead of F3

F0 made the record durable and F1 prints argument values from it. Both were
right — a trace that cannot show what was refused explains nothing — but
together they mean **anyone running this on real traffic is writing their own
arguments to disk in plain text**, and `trace` prints them. That is a new
exposure this week created, and it should not be one release old before it is
closed.

The build map describes F5 as generalising "the existing rule (exception types,
never messages)". No such rule exists. There are scattered
`type(e).__name__` format strings and no redaction filter anywhere. F5 is new,
not a generalisation, and the estimate rested on that.

## The measurement that shapes the design

A naive secret regex — `api_key|token|secret|password|authorization|bearer|sk-`
— run over 300 real decisions matched **73 of them**. Nearly all are false:
`K.to(float32)`, `echo "=== venv modal ==="`, ordinary code edits. Redacting a
quarter of every trace would destroy the feature F1 just built.

So the design is precision-first, and precision is a measured claim here, not
an aspiration.

## Registered predictions

**P-F5.1 — known secret shapes are redacted.** A value carrying an OpenAI
`sk-`, GitHub `ghp_`/`gho_`, AWS `AKIA`, PyPI `pypi-AgEI`, a Slack `xox` token,
or a PEM private-key header is redacted wherever it appears in an argument.

**P-F5.2 — the false-positive rate is measured and stated, not assumed.** Run
over the same 300 real decisions, the shipped filter's redaction rate is
reported as a number in the result document. If it exceeds **2%** the filter is
too broad and the defaults are narrowed before shipping.

**P-F5.3 — redaction happens before the value reaches disk.** Not at render
time. A filter that redacts in `trace` while the raw value sits in
`audit.jsonl` protects nothing and would be worse than none, because it would
look like protection. Checked by reading the file, not the output.

**P-F5.4 — enforcement sees the real value.** Redaction never changes a
decision. The gate evaluates the argument as given; only the record is
redacted. A policy that matched on a secret's value must still match.

**P-F5.5 — a redaction is visible, never a silent drop.** The record shows that
a value was redacted and what kind matched, so a reader knows something was
there. An argument that silently vanishes makes a trace lie by omission.

**P-F5.6 — it is configurable and on by default.** Default patterns are the
high-precision ones above. A user may add patterns or disable it. On by
default, because the failure mode of "off" is secrets on disk, and unlike token
matching — which is off by default at a measured 4.9% false-positive rate — a
precision-first redactor should not cost a user anything they notice.

## Scope

In: argument values in the audit record, configurable patterns, on by default,
marker showing what was redacted.

Out, and named: tool *outputs* are not in the record today, so there is nothing
to redact there yet; entropy-based detection, which is the classic source of
false positives; redaction of values already written before this shipped.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
