# Benign drift — result

**Run 2026-09-05 against `BENIGN_DRIFT_GATES.md`. macOS arm64, node
v20.20.2, npm registry as of that date. Instrument `measure/benign_drift.py`;
data under `results/benign_drift/`.**

## Scope first (P-BD.4)

| server | versions in window | started | window |
|---|---|---|---|
| @modelcontextprotocol/server-everything | 28 | 23 | 2024-11-19 → 2026-08-31 |
| @modelcontextprotocol/server-filesystem | 19 | 16 | 2024-11-21 → 2026-08-31 |
| @modelcontextprotocol/server-memory | 14 | 14 | 2024-11-21 → 2026-08-31 |
| @modelcontextprotocol/server-sequential-thinking | 9 | 9 | 2024-12-03 → 2026-08-31 |
| @playwright/mcp | 30 (newest of 73) | 30 | 2026 |
| @upstash/context7-mcp | 30 (newest of 68) | 30 | 2026 |
| chrome-devtools-mcp | 30 (newest of 60) | 29 | 2026 |
| @notionhq/notion-mcp-server | 21 | 21 | 2025-04-03 → 2026-07-25 |
| @supabase/mcp-server-supabase | 30 | **0** | excluded: needs an access token to start |

211 versions attempted, 39 failed to start: all 30 of Supabase, and 9 early
2024 releases of the reference servers that no longer boot on node 20
(`ERR_MODULE_NOT_FOUND`). 164 consecutive-release comparisons remain across
eight servers. Every catalogue came from a running server over stdio;
every digest is `trustband.lock.observe` (P-BD.5). Newest 30 versions per
server, as registered; for the three fast-moving third parties that is
roughly the last year.

## Within-version stability (P-BD.2)

Eight of eight servers gave identical digests for every tool across three
starts of their newest version. No spurious drift: a pinned user who never
upgrades never sees a refusal from this source.

## The rates (P-BD.1)

| server | compared | none | description-only | schema | added/removed | drift per release | drifts per server-month | refused tools per drifting release (median / max) |
|---|---|---|---|---|---|---|---|---|
| server-everything | 22 | 15 | 0 | 1 | 6 | 0.32 | 0.33 | 0 / 11 |
| server-filesystem | 15 | 9 | 2 | 1 | 3 | 0.40 | 0.28 | 1 / 14 |
| server-memory | 13 | 11 | 0 | 2 | 0 | 0.15 | 0.09 | 9 / 9 |
| server-sequential-thinking | 8 | 5 | 1 | 2 | 0 | 0.38 | 0.14 | 1 / 1 |
| notion-mcp-server | 20 | 9 | 1 | 7 | 3 | 0.55 | 0.70 | 6 / 22 |
| @playwright/mcp | 29 | 19 | 0 | 6 | 4 | 0.34 | 1.11 | 2 / 22 |
| context7-mcp | 29 | 19 | 0 | 10 | 0 | 0.34 | 1.24 | 1 / 2 |
| chrome-devtools-mcp | 28 | 13 | 4 | 8 | 3 | 0.54 | 2.19 | 2 / 29 |
| **pooled** | **164** | **100** | **8** | **37** | **19** | **0.39** | **0.51** | **1.5 / 29** |

"Schema" means the input schema changed, with or without the description;
"description-only" means only the description did. A release that adds or
removes a tool is counted there even if other tools also changed.

Read plainly: **two releases in five move a pin.** For a server that ships
monthly that is one drift every two months; chrome-devtools-mcp, shipping
weekly, drifts about twice a month. When a release drifts, the typical
cost under enforce is one or two tools refused until `lock accept`
(P-BD.6); the worst seen is a whole catalogue, when a server renamed or
reshaped everything at once (chrome-devtools-mcp 29 tools, notion 22).

## The rule (P-BD.3)

Pre-registered: no drift class is auto-accepted, and the result that would
change that is a class occurring in more than half of honest releases that
cannot carry the attack the pin exists for.

- Description changes, the attack's vehicle (P-P8b.6): 8 of 164 releases
  description-only, 45 of 164 with the description changing at all. Rare,
  and disqualified anyway.
- Schema changes: 37 of 164. Of those, **purely additive with the
  description untouched — the only candidate class — 1 of 37.**
- Tools added or removed: 19 of 164. Not a candidate; a new tool is a new
  description.

Nothing comes near the threshold. **The rule stays: nothing is accepted
without a person.** The measurement also settles the tone of the page: the
pin is not a tax that fires constantly. It fires on roughly every third
upgrade, for one or two tools, and never between upgrades.

## What it means for the product

- **Drift watch** (the second add-on, when asked for) has a real rate to
  quote: about one notice per server every two months, weekly-shipping
  servers excepted.
- **Model pins** (`MODEL_CONSTRAINTS_GATES.md`) follow the same rule. A
  provider snapshot change is drift, refused until accepted. Providers
  re-snapshot far less often than these servers ship, so the cost is
  lower still; the case for auto-accepting is weaker, not stronger.
- The `lock diff` output should lead with the *kind* of change, since the
  kind is what a person decides on and the split here shows schema and
  added/removed are the common ones.

## What this does not show

- **Real traffic.** This is release history, not a user's upgrade cadence;
  a user who pins once and never upgrades sees none of it.
- **Whether a pinned change was benign.** Every release here is assumed
  honest; the measurement is of how often honest releases move a pin, not
  of whether any of them was an attack.
- **Python servers, credentialed servers, servers off npm.** Named out of
  scope; the rate may differ.
- **The oldest versions.** Nine early releases could not start and are not
  in the rates; the 2024 rate is therefore from fewer points.
