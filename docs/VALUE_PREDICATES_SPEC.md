# Value predicates — specification

**Written 2026-08-29, before implementation.** The measured gap this closes is
in `SPAN_EXTRACTOR_RESULT.md`.

---

## The gap, in one measurement

The legitimate payee and the attacker's payee arrive from the **same poisoned
document** with **identical provenance**:

```
recipient: session  ->  legit bill=refuse  attack=refuse
recipient: tool     ->  legit bill=ALLOW   attack=ALLOW
```

No band-based rule separates them. Strict refuses the bill, permissive admits
the attack. CaMeL's dependency tracking fails the same case, because "where did
this come from" has the same answer for both IBANs.

What separates them is a predicate over the **value**. That is authorization,
not data flow.

## Grant schema extension

A grant gains an optional `require`, a **conjunction** of predicates:

```json
{
  "sess": 7, "max_tier": 2, "actions": ["send_money"],
  "arg_bands": {"recipient": "tool", "amount": "tool"},
  "require": [
    {"arg": "recipient", "op": "in_set",
     "values": ["UK12345678901234567890"]},
    {"arg": "amount", "op": "max_int", "value": 25000}
  ]
}
```

Grants remain a **disjunction**: any grant that permits, permits. Within a
grant, every predicate in `require` must hold. This keeps the existing
"multiple grants for one session" shape working, which was itself a defect fix.

## Operators

| op | holds when | field |
|---|---|---|
| `in_set` | value is in a literal allowlist | `values`: list of str |
| `in_context` | value is in a named runtime set | `key`: str |
| `max_int` | integer value ≤ bound | `value`: int |
| `confirmed` | a human confirmed this argument | — |

Four, because these are what the banking suite actually exercises: seven of its
nine injection tasks route money to an attacker IBAN, one redirects a recurring
payment, one changes a password.

**`in_set`** is the static allowlist. **`in_context`** is "seen in prior
transaction history" — the same test against data supplied at call time rather
than baked into the policy, so history changes without a policy rotation.
**`max_int`** is the reversible-limit bound. **`confirmed`** is human
confirmation for the one field that is both untrusted and consequential.

## Money is integers in minor units

`max_int` takes an **int**, never a float. `policy.py` rejects floats outright:
IEEE NaN has no equality and signed zero has two representations, either of
which breaks the digest's injectivity. A float bound could not be encoded, so
it could not be bound into a capability.

Amounts are therefore compared in **minor units** — 25000 is £250.00. A
non-integer argument fails the predicate rather than being rounded, because
rounding a monetary comparison silently is worse than refusing it.

## Fail-closed rules

These are the cases that decide whether the feature is safe, so they are fixed
before implementation rather than discovered:

1. **A predicate naming an argument the call does not pass REFUSES.** Absence
   does not satisfy a constraint. This matches `arg_bands`, where the same rule
   already prevents a renamed parameter from dropping its own constraint.
2. **`in_context` with no context supplied REFUSES.** A missing history is not
   an empty history, and treating it as one would permit every value the moment
   a caller forgot to pass it.
3. **`confirmed` with no confirmation set REFUSES.**
4. **A value of the wrong type fails its predicate.** `max_int` against
   `"lots"` refuses; it does not coerce.
5. **Predicates are evaluated on the PLAIN value**, unwrapped through nesting.
   The band is checked separately by `arg_bands`; a predicate asks a different
   question and both must hold.

## Order of checks within a grant

`tier` → `action` → `arg_bands` → `recipients` → **`require`** → allow.

Predicates run last because they are the most expensive and the most likely to
need runtime context, and because a refusal earlier is more specific.

## Refusal text

Every refusal names the operator, the argument and the bound, because the audit
record is the product:

```
policy refused: predicate: recipient 'US133000000121212121212'
is not in the 1-entry allowlist (grant for session 7)
```

## What this does not do

**It does not detect injection.** A poisoned document that names an
allowlisted payee passes. The claim is narrower and stronger: a consequential
action cannot execute unless its arguments satisfy a policy that was fixed in
advance, and the log shows which predicate decided.

**It does not replace taint.** Bands still answer "may this provenance reach
this argument". Predicates answer "is this value permitted". Both are required:
predicates alone would admit a laundered value that happens to be allowlisted,
and bands alone cannot separate two values from one document.

## Acceptance

1. The banking case separates: legit bill ALLOW, attacker payee refuse, under
   one policy, with both values banded TOOL.
2. Policy digest covers `require`; two policies differing only in a bound have
   different digests, and key order does not matter.
3. Every fail-closed rule above has a test.
4. No regression: battery, policy demo, custody, sweep, pairs.
