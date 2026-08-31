# Bring-your-own detector — gates before the build

**Registered 2026-08-31, before the code.**

---

## Why this composition

Detection is the most commoditised layer in agent security. Meta gives Prompt
Guard away; Lakera, Azure and AWS sell or bundle it. Building our own is a
research treadmill we should not own — a classifier decays as attacks rephrase.

But a buyer with an RFP wants "prompt injection detection" on the checklist, and
many already own a detector. So the move is a **plugin interface**: bring your
own, and it makes our layer stricter rather than duplicating it. That turns
competitors into complements and closes the "we already have detection"
objection without our taking on the treadmill.

## The one property that makes it safe

A third-party detector in the decision path is dangerous if it can permit
something. So it cannot.

**A detector may only LOWER trust, never raise it.** It returns a band floor: a
value the store banded SESSION, a detector may push to TOOL or USER (less
trusted), never toward GOVERNANCE. The guard clamps the result so even a
detector returning GOVERNANCE for everything changes nothing.

Consequences, each one a gate:

- **A broken or malicious plugin cannot create a bypass.** Its worst act is to
  over-refuse, which is visible and annoying, not a security failure.
- **A plugin that errors, times out, or returns None degrades to exactly
  today's behaviour** — the band the store already assigned. Not fail-open; the
  policy was never relying on the detector.
- **The detector is itself quarantined** in the same sense as the extractor: it
  reads untrusted text, has no tool access, and can emit exactly one thing — a
  band floor. There is no channel through it.

## Where it runs, and why it's useful

On arguments, in `before_tool_call`, after provenance assigns a band. The
interesting case is the **laundering gap**: a value the model paraphrased is
banded SESSION (model-authored, trusted). A detector that recognises it as
injection-shaped lowers it to TOOL, and the policy then refuses it.

So the detector is a second opinion that catches what provenance alone trusts —
the same gap token matching addresses, by a different and composable mechanism.

## Registered predictions

**P-DET1 — monotonicity is enforced, not documented.** A detector that returns a
MORE trusted band than the current one has no effect: the guard clamps it. Tested
with an adversarial plugin that returns GOVERNANCE for everything — utility and
refusals are byte-identical to no detector.

**P-DET2 — a crashing detector is a no-op.** A plugin that raises on every call
leaves every decision exactly as it was without one.

**P-DET3 — a real detector closes some laundering.** A reference detector that
fires on injection-shaped text lowers a model-authored argument to TOOL, and a
policy needing SESSION then refuses it. Measured on the same paraphrased-attack
case token matching was tested against.

**P-DET4 — the default path pays nothing.** No detector configured means the
band assignment is byte-for-byte what it is today. Differential-checked.

## What a detector is NOT allowed to be

- **Not a verdict.** It returns a band, and the gate decides. A detector that
  could say "block" would be a decision that can be argued with in the path.
- **Not sold as the control.** In any external claim, the detector is a signal
  that tightens provenance, never the thing that stops the attack. An adaptive
  attacker recovers high success against a signature defence, and we do not want
  to have staked the security claim on one.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
