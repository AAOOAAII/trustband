# Span-pointer extractor — gates registered before the experiment

**Written 2026-08-29, before the extractor exists and before any model is run.
Committed before the first measurement. Not scoreable afterwards.**

---

## What is being tested

A quarantined extractor that **cannot emit a value** — only a pointer into the
source document:

```
recipient = @[142:164]
amount    = @[203:209]
```

A deterministic translator resolves spans against the original text. The model
has no literal channel, so a fabricated value has no span to point at.

## What this is NOT claimed to do

**It does not prevent value corruption.** An injection can steer the extractor
to point at the attacker's IBAN, and that span is perfectly well-formed. The
architecture assumes a corruptible extractor. The security property comes from
the value arriving banded TOOL and a per-argument policy refusing it into
`recipient` while still permitting a tool-derived `amount`.

Anyone reading a low corruption rate as the security result has misread it.

## Why spans rather than constrained decoding alone

Measured today: 17 attacks still succeeded against Qwen2.5-14B because the
attacker's payload sat **inside** a poisoned document. Whole-value taint
remembered the document and never the embedded IBAN, so the argument reached
the gate as model-authored. Substring recall patched this heuristically. Spans
make derivation structural — a value's provenance IS its span.

## Registered predictions

**P-SPAN1 — the instrument, and it must pass first.** Extraction on **clean**
documents succeeds at a usable rate. If it does not, the model is too small and
nothing about injection is learnable from the run. Step up a size and re-run
before concluding anything.

**P-SPAN2 — hallucination is structurally impossible.** Every value the
translator emits is a literal substring of the source, verified mechanically.
Target: **100%**, because this is an architectural claim rather than a
behavioural one. Any exception is a defect in the translator, not the model.

**P-SPAN3 — corruption rate under injection.** The share of fields whose span
moves when the injection is present. **Reported, not targeted.** Predicted
before running: **spans will move at 0.5B**, placing us in the design note's
case two, where schema enforcement must live in the decoder rather than the
prompt.

**P-SPAN4 — the product question.** Of the **17 laundered cases** measured
today, how many become catchable because the extracted value now carries a
span-derived TOOL band. This is the only prediction that speaks to whether the
design closes the gap it was designed for.

**P-SPAN5 — the utility cost.** Extraction failures are utility losses, not
security losses. Reported beside P-SPAN4 so the trade is visible, because a
design that catches everything and extracts nothing is not a product.

## Ordering rule

**P-SPAN1 gates P-SPAN3 and P-SPAN4.** A model that cannot extract from clean
text will show a low corruption rate for the wrong reason, and that reading is
the one most likely to be mistaken for a security result.

## Controls, fixed now

- **Frontier control.** The same extraction with a large model, to separate
  "this model is too small" from "this extraction is hard".
- **Clean/injected pairs.** Every document measured both ways; the comparison
  is within-pair, never against an aggregate.
- **Fixed schema per suite**, written before any document is read.

## Scope

- Test set: AgentDojo banking injection vectors, the 17 laundered cases first.
- Models: smallest first, stepping up only when P-SPAN1 fails.
- Every number carries the model, the schema, and the document count.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
