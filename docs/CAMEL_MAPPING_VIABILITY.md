# CaMeL labels onto the warrantable band lattice — viability

**2026-08-28. Investigation only. No adapter written, no change to
`warrantable-py`.** Read from CaMeL's source, not the paper.

**CaMeL state:** `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`, 2025-06-20, 3
commits. **Unchanged since the kill test on 2026-08-16** — same HEAD, no delta
to analyse.

**Licence:** Apache 2.0 (Google LLC, 2025), stated in every source header.
`warrantable-py` is also Apache 2.0, so an adapter could ship. Licence is not a
blocker.

---

## 1. The two models, separately

### CaMeL

A capability is `Capabilities(sources_set, readers_set, other_metadata)`
(`src/camel/capabilities/capabilities.py:24-27`). It is **two-dimensional**, and
the dimensions are different kinds of thing:

**Sources — integrity.** `frozenset[Source]` where
`Source = SourceEnum | Tool` (`sources.py:38`). `SourceEnum` is
`{CaMeL, User, Assistant, TrustedToolSource}` (`sources.py:22-26`), and `Tool`
is `(tool_name: str, inner_sources: frozenset)` (`sources.py:31-36`) —
**parameterised by arbitrary strings, so the source space is unbounded.**
Sources combine by **union** down the dependency graph (`utils.get_all_sources`).
The predicate policies use is `is_trusted(v)` = *every* source is in the trusted
set (`utils.py`, `is_trusted`).

**Readers — confidentiality.** `Readers = frozenset[str] | Public`
(`readers.py:36`). `Public` is the **top** and absorbs: `Public & X = X`
(`readers.py:24-33`). Readers combine by **intersection** —
`value_readers &= new_value_readers` (`utils.get_all_readers`). Restrictiveness
*increases* as the set shrinks. The predicate is `is_public(v)`, or
`can_readers_read_value(recipients, v)`.

**`other_metadata`** is `dict[str, Any]` with no schema and no ordering. Nothing
in the interpreter or any policy reads it.

**At a tool call**, `SecurityPolicyEngine.check_policy`
(`security_policy.py:75-96`) denies any state-changing tool whose dependencies
are not all public, then dispatches to a per-tool policy. Default is denial.

### Warrantable

A band is one of four, **totally ordered**:
`TRUST_ORDER = (GOVERNANCE, SESSION, TOOL, USER)` (`taint.py:54-55`), ranked by
position (`taint.py:56`). The band is stamped from the arrival channel and never
read from the payload (`gate.py:49-55`).

Combination is `meet` — the **less trusted** of two (`taint.py:67-69`) — and
`combine` folds it over a derivation's inputs (`taint.py:127`). The order is
enforced by `at_least(actual, minimum)` (`taint.py:72-74`), consumed at
`issuance.py:189` where a grant's `min_band` is checked against the arguments.

**One dimension: integrity.** There is no notion anywhere of *who may read* a
value.

---

## 2. Verdict on the embedding

# EMBEDS-WITH-COLLAPSE — and the collapse is disqualifying

**The confidentiality dimension has no image.** CaMeL's readers axis asks "may
recipient R read value V". Warrantable's band answers "where did V arrive from".
These are not the same question and no total function from one to the other
preserves the first, because the target has no vocabulary for it.

### The collapse, quantified over CaMeL's own suite policies

All 17 policies across `banking.py`, `slack.py`, `travel.py` and
`workspace.py`:

| what the policy depends on | count | maps? |
|---|---|---|
| sources only (integrity) | **8** | yes, soundly |
| readers only (confidentiality) | **4** | **no** |
| both | **5** | integrity half only |
| **total** | **17** | |

**9 of 17 policies — 53% — depend on a dimension warrantable cannot express.**
A sound `f` must deny whenever the readers axis is load-bearing, because
over-approximation is the only safe option when the target cannot represent the
constraint. Those 9 policies degrade to **unconditional denial**.

### And the integrity axis collapses too

CaMeL's source space is unbounded — `Tool(tool_name, inner_sources)` ranges over
arbitrary tool names and, in the suites, email addresses. `is_trusted` reduces
all of it to a **boolean**. So the honest mapping is:

```
f(L) = SESSION  if is_trusted(L)
       TOOL     otherwise
```

Sound and monotone. **Image size: 2.** An unbounded lattice lands on two of four
bands; `GOVERNANCE` and `USER` are unreachable from any CaMeL label, because
CaMeL has no concept corresponding to either.

**Collapse ratio: unbounded source lattice → 2 bands, and 53% of real policies →
constant denial.** That is safe and useless, which is exactly the failure mode
the brief named as disqualifying.

---

## 3. Crossing cases

Labels more restrictive than a band on one axis and less on the other. Each is a
place where over-approximation is forced.

**C1 — trusted source, private readers.** A value from the user
(`is_trusted` true) whose readers are `{alice@corp}`. Integrity says *permit* —
it maps to SESSION and passes a `min_band: session` grant. Confidentiality says
*deny* for any recipient other than alice. Concrete: `send_money_policy`
(`banking.py`) accepts the recipient because it came from the user, then
separately checks the recipients can read the subject, amount and date. **The
band answers the first check and is silent on the other three.**

**C2 — untrusted source, public readers.** A value scraped from a public web page
by a tool. Readers are `Public`, so CaMeL's base policy permits it. Warrantable
maps it to TOOL and refuses any grant requiring SESSION. **We are stricter than
CaMeL here** — sound, but it rejects behaviour CaMeL allows, which shows up as
lost utility rather than lost safety.

**C3 — intersection versus meet.** Two values, readers `{a,b}` and `{b,c}`.
CaMeL's intersection gives `{b}` — still readable by someone. The band meet of
two SESSION values is SESSION. **CaMeL's combination carries information that
survives the join; ours discards it**, because there is nothing to carry.

**C4 — `Tool` inner sources.** `Tool("email", {SourceEnum.User})` is a tool
source carrying a user-provenance annotation inside it (`sources.py:31-36`,
constructed at `agentdojo_function.py`). Warrantable's band is stamped from the
socket and is flat: TOOL, with nowhere to record that the tool's own input came
from the user. **Structure is lost, not translated.**

---

## 4. What does not map, and must be refused

**`other_metadata: dict[str, Any]`** — unbounded value domain, no schema.
`warrantable/policy.py` is total and injective only on a restricted domain, so
this cannot be digested without either restricting it or falling back to a
default digest. **A fallback would silently collapse distinct policies onto one
tag and is unsound; refusal is correct.**

Frequency in CaMeL's own code: **it is never read.** Not by the interpreter, not
by any of the 17 suite policies. It is carried and ignored. So refusing values
that carry non-encodable metadata **breaks nothing that CaMeL itself exercises**
— it is dead weight in their model, and that is the cheapest unmappable
construct to refuse.

**Reader sets over arbitrary identifiers** — `frozenset[str]` of email addresses
and usernames. Not refusable in the same sense: they are load-bearing in 9
policies. There is nothing to refuse *at the boundary*; the constraint simply
cannot be carried, which is §2's collapse rather than a boundary check.

---

## 5. Do we already have what makes CaMeL valuable?

Honest comparison, capability for capability.

**What CaMeL does that we do not:**

- **Confidentiality.** Reader sets and `can_readers_read_value`. We have no
  analogue and this is not a small gap — it is over half their enforced policies.
- **Fine-grained provenance.** `Tool(name, inner_sources)` distinguishes which
  tool and what fed it. Our band is one of four, from the socket.
- **Dependency-graph propagation.** `get_all_readers` walks the transitive
  dependency graph with cycle detection. Ours propagates across an explicit
  `combine` at each derivation the caller makes.
- **A quarantined LLM.** Untrusted content is processed by a model with no tool
  access, which is the discipline that makes harness-level taint sound. We
  document that we cannot enforce it.

**What we do that CaMeL does not:**

- **Unforgeable provenance.** Our band is stamped from the accepting socket and
  the payload's claim is never read — `_band_for_channel` does not take the
  payload as an argument, and `structural_selftest` asserts that signature.
  CaMeL's capabilities are interpreter metadata: correct only while the
  interpreter is.
- **Cryptographic binding.** A capability's tag commits to the policy digest.
  Theirs is a frozen dataclass.
- **Revocation.** Epoch rotation, per-session revocation, elevation withdrawal.
  CaMeL has none.
- **A tamper-evident audit log.** They have none.
- **Machine-checked enforcement.** 30 obligations, 11 counterexamples.

**Is CaMeL's value here capability, or recognition?**

**Recognition.** On capability, their contribution is the confidentiality axis
and the quarantined-LLM split — and an adapter buys us *neither*. A mapping
cannot import the readers dimension, because the collapse in §2 is the proof
that it does not fit; and the dual-LLM split is an architecture choice we could
adopt directly without touching their code.

What an adapter would buy is the ability to say "compatible with CaMeL", against
a repository that has not moved in fourteen months and whose authors state they
will not maintain it.

---

## 6. Is an adapter worth building?

**No.** Not for capability, and the recognition is thin.

The mapping is sound and monotone and it lands 53% of CaMeL's own policies on
unconditional denial while compressing an unbounded source lattice onto two of
our four bands. An adapter that refuses half of what the thing it adapts would
permit is not an integration; it is a demonstration that the models disagree.
The disagreement is real and structural: **they enforce confidentiality, we
enforce integrity.** One is not a coarsening of the other.

The useful result is the diagnosis, not the adapter. If confidentiality matters
to a buyer — and `send_money_policy` is a good argument that it does — the right
move is to **add a reader dimension to our own lattice**, with its own
counterexamples and its own proof obligations, rather than to translate someone
else's. That is a Phase 5 with a clear shape: a second partial order over
recipients, a join that intersects, and a gate conjunct that fails when the
recipient set cannot read an argument. It would be ours, proved, and revocable —
which is three things CaMeL's version is not.

**If an adapter were built anyway**, the smallest provable interface contract is
one function with three obligations:

```
f : Capabilities -> Band
```

1. **Monotone** — `is_trusted(L1) ≤ is_trusted(L2)  ⟹  at_least(f(L1), f(L2))`
2. **Sound** — `at_least(f(L), min_band)` implies every source in `L` is
   trusted; the adapter must additionally **deny outright** whenever the policy
   being translated consults readers, since `f` cannot witness that constraint
3. **Refusing** — `f` is partial on `other_metadata` outside the restricted
   domain and must raise rather than default

Obligation 2 is the one that matters, and stating it honestly is what makes the
adapter's value visible as near-zero: it is mostly a denial.
