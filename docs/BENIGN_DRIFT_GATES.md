# Benign drift — how often a legitimate release moves a lockfile pin. Gates before the run.

**Registered 2026-09-05, before any data was collected. P-P8b.0 left this
unmeasured: "the benign-drift rate needs real traffic". Real traffic is not
here yet; published release history is, and it answers the same question
from the other side: when a pinned MCP server is upgraded, how often does
the pin break, and what kind of change broke it.**

## The question

A lockfile pin covers a tool's name, description, input schema and version
field, digested by `trustband.lock.observe`. Under enforce, a change to any
of them refuses calls to that tool until `trustband lock accept`. If honest
releases change descriptions constantly, the pin is a tax nobody keeps and
auto-accepting some class of drift becomes tempting. If they rarely do, the
pin is cheap and the right rule is the current one: nothing is accepted
without a person.

## The instrument

For each server in scope, every non-prerelease version on npm, newest 30
at most, is started with `npx -y <package>@<version>` and asked for its
catalogue over stdio: `initialize`, `notifications/initialized`,
`tools/list`. Each tool is digested with the package's own `observe()`, so
the measurement uses the lockfile's definition of change and not a
re-implementation (P-BD.5). Publish dates come from the registry.

Consecutive versions are compared. A release is classified by what moved:
nothing; description only; schema (with or without description); tools
added or removed. A version that will not start is recorded as such and
excluded from rates, and the count is reported.

The newest version of each server is started three times; any difference
between runs is spurious drift, the kind a user would meet with no upgrade
at all, and is reported separately (P-BD.2).

## Scope, stated before the run (P-BD.4)

Servers published to npm, started without credentials, with at least nine
non-prerelease versions:

- `@modelcontextprotocol/server-filesystem`, `server-memory`,
  `server-everything`, `server-sequential-thinking` (the reference set)
- `@playwright/mcp`, `@upstash/context7-mcp`, `chrome-devtools-mcp`
  (widely installed third parties)
- `@supabase/mcp-server-supabase`, `@notionhq/notion-mcp-server` if they
  list tools without a token; excluded and named if not.

Not in scope: Python servers, servers needing a key to start, deprecated
archive servers whose history ended in 2024, and any catalogue obtained by
reading source rather than by asking a running server.

## Registered predictions

**P-BD.1 — the rate is reported per release and per month, per server and
pooled**, with the split by class. No single number stands alone.

**P-BD.2 — within-version stability.** Three starts of one version give
identical digests for every tool. If any server differs between starts,
the differing field is named and that server's per-release rate is
reported with and without it.

**P-BD.3 — the rule is decided by the data, and the decision is stated
before the data.** The current rule is: no drift class is auto-accepted.
The result that would change it: a class of change that occurs in more
than half of honest releases *and* cannot be the vehicle of the attack the
pin exists for. Description changes are the attack's vehicle (P-P8b.6), so
no description-drift rate, however high, changes the rule. Schema changes
are candidates only if they are additive and the description is untouched.
The pre-registered expectation is that the rule stays.

**P-BD.4 — scope first.** The result's first section names the servers,
version counts, dates, failures to start, and the machine, before any rate.

**P-BD.5 — the lockfile's own digest.** The script imports `observe` from
`trustband.lock` and nothing computes a digest any other way.

**P-BD.6 — cost under enforce, stated.** For each drifting release, how
many tools a pinned user would be refused on until they accepted, as a
median and a maximum, so the per-upgrade cost is a number.

## What is measured, in order

1. Collection, cached per package and version, resumable.
2. Stability, three runs of the newest version per server.
3. Classification and rates.
4. The rule, restated against the numbers.
