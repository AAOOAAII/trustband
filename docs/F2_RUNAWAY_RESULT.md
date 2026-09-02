# F2 — result

**Run 2026-09-02 against `F2_RUNAWAY_GATES.md`, registered in `7056ce0` before
the code.**

## Gates

| gate | verdict |
|---|---|
| P-F2.1 refuses at the cap, not before or after | **PASS-CLEAN** |
| P-F2.2 the counter is per session | **PASS-CLEAN** |
| P-F2.3 survives process boundaries | **PASS-CLEAN** |
| P-F2.4 a cap refusal is legible and distinguishable | **PASS-CLEAN** |
| P-F2.5 no cap configured means no behaviour change | **PASS-CLEAN** |
| P-F2.6 refusable, never silently fatal | **PASS-CLEAN** |

## The defect this phase found, in its own code

The first implementation **blocked in shadow mode**. Five subprocesses under a
cap of three: three "would have allowed", then two hard refusals.

No registered gate caught it. The standing discipline did — *shadow-first for
anything that can refuse or block* — and it is worth naming why the cap was the
one that slipped. Every other refusal in this product is a claim about where a
value came from, which a user has to be persuaded of. A call cap is a limit the
user set themselves, which makes it feel like something they already consented
to. They did not: they asked for a limit **once enforcement is on**. A shadow
install that blocks is not shadow, and it breaks the one promise that gets this
tool kept.

Fixed: the cap records `would_allow: false` in the shadow log and returns
allowed, exactly as every other refusal does.

```
shadow, cap 3, five subprocesses
  ALLOW  SHADOW: would have allowed — granted by session …
  ALLOW  SHADOW: would have allowed — granted by session …
  ALLOW  SHADOW: would have allowed — granted by session …
  ALLOW  SHADOW: would have refused — session call cap reached: 3/3
  ALLOW  SHADOW: would have refused — session call cap reached: 3/3

enforce, cap 3, five subprocesses
  ALLOW · ALLOW · ALLOW · REFUSE · REFUSE
```

## P-F2.3 — why F0 had to come first

The adapter is a subprocess per tool call. An in-memory counter counts to one
forever. The count is rebuilt from the durable record at construction, so five
independent processes share one budget. This gate was unbuildable before F0.

## P-F2.1, P-F2.2

Call N allowed, call N+1 refused, with the cap and the count in the reason.
Two sessions under one policy: `alpha` exhausts at three while `beta`'s second
call still passes. A shared counter would let one tenant deny another, which is
the same reason provenance is scoped per session.

## P-F2.4 — a cap must not read like a provenance refusal

```
NO → Bash           REFUSED   0.017 ms
      command          band=session     echo 4
      why: session call cap reached: 3/3 calls. Raise session.max_calls
           or start a new session.
```

The reason names the cap, the count, and the two ways out. A user who hits it
does not go looking for a policy bug.

## P-F2.5, P-F2.6

Decisions are identical with and without a `session` section. Regression clean:
conformance 18/18, policy demo 87/87, custody 13/13, battery 6/6, sweep and
pairs 0 suspects. Hitting a cap refuses one call; it does not crash the hook,
break the chain, or affect the next session.

## Deferred, and why

`max_spend` is not built. Spend needs token accounting and a price table, and a
cap computed from prices nobody has stated would be a confidently wrong number
enforced as though it were right. It belongs with F3, where the pricing source
and its date have to be declared.
