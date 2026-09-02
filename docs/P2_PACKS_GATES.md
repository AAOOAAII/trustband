# P2 — policy packs. Gates before the code.

**Registered 2026-09-02, before any new pack. Base: F6 at `c8f07c6`.**

## The rule the build map set, taken literally

> "8 packs, each with a measurement" beats "21 packs" in your register.

So the count is an **output**, not a target. A pack ships only if a measurement
in this repository supports what its description claims. Where no measurement
exists, no pack ships, and the honest number is whatever that leaves.

Three exist today: `coding-agent`, `financial-actions`, `messaging-agent`.
Today's work produced measurements that support several more, and one that
supports none.

## Registered predictions

**P-P2.1 — every pack cites a measurement that exists.** Each pack names the
result document behind its claim, and that document is in the repository. A
pack whose number cannot be pointed at is not shipped, however plausible it is.

**P-P2.2 — every pack loads, validates and adopts.** `trustband packs` lists it
and a `Guard` accepts it. A pack that fails validation is worse than absent: it
is a starter that does not start.

**P-P2.3 — every pack does what it says on a representative call.** For each,
one call the description implies is refused **is** refused, and one it implies
is permitted **is** permitted. A pack that refuses everything is not a policy,
and a pack that refuses nothing is decoration.

**P-P2.4 — no pack claims a number from a different suite.** The banking figure
does not appear on a browser pack; the browser figure does not appear on a
messaging pack. Each description carries its own scope, including the model.

**P-P2.5 — descriptions state the limit, not only the win.** Every pack that
rests on verbatim survival says paraphrase escapes, because a starter policy is
the first thing a new user trusts and the first place an overclaim does damage.

**P-P2.6 — nothing prior moves**, and the packs still ship in the wheel — an
earlier release shipped a wheel with no packs at all.

## Candidate packs, and whether a measurement exists

| pack | measurement | ships? |
|---|---|---|
| coding-agent | 8/8 verbatim quoted, 0/5 prose | exists |
| financial-actions | AgentDojo banking 36→0 | exists |
| messaging-agent | AgentDojo slack 46→22 and 40→9 | exists |
| browser-scoped | `host_in_set` 5/5, `HOST_ALLOWLIST_RESULT.md` | exists |
| browser-open | markup 0/5→5/5 with canonical forms | exists |
| multi-agent | handoff banding, `HANDOFF_RESULT.md` | exists |
| unattended | F7 gates — **not an attack measurement** | **decide** |

The last is the interesting case. F7 is verified behaviour, not a measured
attack outcome, so its description must not imply an attack number. Either it
ships describing behaviour and saying so, or it does not ship.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
