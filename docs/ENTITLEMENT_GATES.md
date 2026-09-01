# Tiers, functionalised — gates before the code

**Registered 2026-09-01, before implementation.**

---

## The decision that shapes everything

**There is no local licence check.** The client is open source, so any key that
verifies a licence locally ships in the source and can be forged by anyone who
reads it. Local licence enforcement in an open-source client is theatre.

Instead: **paid features are hosted, and access control lives at the server.**
The client holds an API key; the hosted endpoint accepts or rejects it. A forged
local token buys nothing, because there is nothing local to unlock.

This falls out of the tier decision already made — free is the whole enforcement
layer self-hosted; Pro and Enterprise are hosted audit retention, approval
routing, fleet policy and fleet inference. Those are services, not features to
unlock.

## The property that must hold, mechanically

**Enforcement never consults entitlement.** No tier check, no key check, no
network call anywhere in the decision path. A user with no key, an expired key,
a revoked key or a garbage key gets byte-identical enforcement to a paying
Enterprise customer.

This is not generosity. It is the thing that makes the product safe to adopt: a
security tool that fails open on an unpaid invoice is worse than no security
tool. It is also a sales line, and a sales line that is mechanically true is
worth more than one that is policy.

## Registered predictions

**P-LIC1 — enforcement is identical across every entitlement state.** The same
calls, the same policy, the same provenance: no key, valid key, expired key,
forged key. Differentially checked, decision for decision.

**P-LIC2 — a lapsed or absent key disables only hosted features.** Local audit
logging, shadow recording, inference and policy testing continue unchanged. What
stops is retention beyond the local log, approval routing to another human, and
fleet distribution.

**P-LIC3 — a hosted feature with no key fails with a clear, actionable message**
and never silently degrades into a security difference. "This needs a Pro key"
is a fine failure. Quietly not routing an approval is not.

**P-LIC4 — the conversion moment is computed from the user's own traffic**, not
asserted. `trustband status` and the shadow report say what Pro would add for
*this* install, derived from what actually happened, or say nothing.

**P-LIC5 — no telemetry.** Determining entitlement must not report usage,
policy content, or tool-call data anywhere. A key is checked; nothing about the
agent is transmitted. For a product whose pitch is that decisions stay local,
phoning home with usage would be self-refuting.

## What this is not

Not a licence manager, not a DRM layer, not a feature flag system. It is: a key
in a config file, a cached answer about what that key entitles, and a set of
hosted features that decline politely without one.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.

---

# Results

**Run 2026-09-01, against the gates registered above.**

| prediction | verdict |
|---|---|
| P-LIC1 enforcement identical across entitlement states | **PASS-CLEAN** |
| P-LIC2 a lapsed key disables only hosted features | **PASS-CLEAN** |
| P-LIC3 hosted refusal is clear and actionable | **PASS-CLEAN** |
| P-LIC4 conversion prompt computed from real traffic | **PASS-WITH-DRIFT** — see below |
| P-LIC5 no telemetry | **PASS-CLEAN** |

## P-LIC1, checked two ways because either alone is weak

Differentially, over seven entitlement states — no key, valid Pro key,
Enterprise key, forged key, empty key, null key, integer key — the decisions
are identical, and identically *correct*: the tool-derived argument refused,
the hand-typed one allowed.

Structurally, `guard.py` and `gate.py` contain no occurrence of `entitlement`,
`api_key`, `licen`, `subscription`, or a tier comparison. Enforcement has no
channel through which to learn the tier.

Both arms are mutation-tested. Two mutants were built and both were caught:

| mutant | differential arm | structural arm |
|---|---|---|
| fails open when no key is configured | **missed** | caught |
| unconditional `return Decision(True)` with no giveaway words | caught | **missed** |

The first mutant is why the differential arm asserts the decisions are correct
and not merely *identical* — a defence that fails open in every state is
perfectly identical and completely broken, and the first version of this check
scored it `identical=True`. The second is why the structural arm exists at all.
Neither arm is redundant; each catches what the other misses.

## P-LIC4 drifted, and the drift was a real defect

The prompt was correct on synthetic observations and dead on real traffic.

`upgrade_prompt` keys on whether a would-be refusal is one a person could have
approved. The guard computes that, returns it on the `Decision` — and did not
write it into the shadow record. Every consumer of the shadow log therefore saw
an install where no refusal was ever confirmable, and the unit tests passed
because they supplied the field themselves.

This is the second instance of one defect shape. The first was P-HARD5/6, where
inference never marked its constraints `confirmable` and the whole confirmation
path was dead on any inferred policy. **A field the downstream feature keys on
is computed and never recorded; the tests pass because they construct the input
by hand.** Unit tests cannot catch it. Running the real binary over real
traffic catches it immediately.

Fixed, and conformance now asserts the *record* rather than the computation.

Measured after the fix, over 300 events of a real Claude Code session driven
through the installed hook binary as 300 subprocesses:

```
150 calls observed, 25 would have been refused (17%)
  25 of 25 are ones a person can approve
```

That also confirms provenance survives across processes: `file_path` carries
band `tool` in a later subprocess because an earlier one recorded where the
value came from.

## Found while running this

`git status --porcelain warrantable` in the three artifact-producing scripts.
The package was renamed to `trustband`, the pathspec stopped matching anything,
git returned empty stdout with return code 0 — and **every artifact produced
after the rename was stamped `tree_clean=True` no matter how dirty the tree
was.** Not one of the suites failed; they all just quietly lost their
provenance.

A stamp that cannot report "dirty" is worse than no stamp, because it is
believed. All three now verify the watched paths exist and record an explicit
unknown when they do not.
