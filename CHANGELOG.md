# Changelog

## 0.2.0 — 2026-09-02

The decision record became durable, and five read paths were built on it.

### The one that mattered

**The tamper-evident log was never written to disk.** `AuditLog` implemented
hash-chaining and nothing ever gave it a path, while three documents and a
comparison table claimed the log existed. Not a regression — no commit on any
branch had ever contained `audit.jsonl`. It is written now, resumed across
processes so a per-call subprocess adapter builds one chain rather than many.

Everything else here reads that record.

### New

- `trustband trace` — a session as a tree: every argument with the band it
  arrived at, the rule that decided, timing, and the chain's state. On 600 real
  events it showed 0 refusals and **71 arguments that came from tool output**,
  which is the reason to keep it installed on a day nobody is attacking.
- `trustband report` — token accounting per class, read from the host's
  transcript, never estimated. Cost is an optional overlay you price yourself:
  97.6% of a real session's tokens were cache reads, and one rate would have
  overstated it 7.2×.
- `trustband replay` — a candidate policy against recorded traffic. It
  reproduces the recorded decisions first, and **refuses** when the record
  cannot support a replay rather than under-reporting.
- Redaction, on by default at a measured 0.0% false-positive rate.
- `session.max_calls` and `session.max_tokens`, counted from the record so they
  survive subprocesses. Both obey shadow.
- `unattended` — what a confirmable refusal means with nobody at the keyboard.
  `deny` by default; `allow` records that **nobody approved** rather than
  forging an approval. A `notify` command runs fire-and-forget and cannot
  approve anything, because nothing reads its answer.
- `contracts` — rules about what came back, not about permission. Coverage
  thresholds, reviewer-not-author, required sections. **Contracts verify what
  is checkable, not that the work is good.**
- `trustband export` — OTLP/JSON over HTTP, no SDK, carrying the provenance
  attributes no other exporter can emit. Ids are hex, which is what OTLP/JSON
  requires and a documented deviation from the protobuf JSON mapping's base64;
  a generic protobuf parser will read them wrongly and not complain.
- The measurement reports the packs cite now **ship inside the package**, and
  `trustband packs` resolves each citation to a file on your disk. The source
  repository is private, so the old repo-relative citation resolved nowhere for
  exactly the people it existed to convince.
- LangChain, LangGraph and CrewAI adapters, each verified against the installed
  library. Two different silent bypasses were found that way.
- Canonical provenance — the store remembers the rendered and decoded forms of
  what tools returned. A payload split across HTML tags went from **0/5 refused
  to 5/5**.
- `host_in_set`, correct against 16 host-confusion bypasses.
- Plan-then-execute, where a plan fixed after untrusted content is **not
  trusted** — a check that needs provenance to make.
- `Guard.handoff()` — closes multi-agent laundering without merging session
  stores.
- Four new policy packs, each citing a measurement that exists in the repo.

### Breaking, and the migration

**Logs written by 0.1.0 cannot be replayed.** Result events then carried a count
and a band, not what the tool returned, so provenance cannot be rebuilt from
them. `trustband replay` says so and refuses rather than reporting fewer
refusals than the truth.

To enable replay, set `record_results.enabled` in the policy and replay a
session recorded after that. It is **off by default**: tool outputs are large
and this is the log a person reads.

### Still not closed

Paraphrase. A model that rewrites a payload in its own words escapes every
mechanism here, measured at 0/5 on prose. Exfiltration through the model's reply
rather than a tool call is structural. Closed platforms have no interception
point. Every attack number is from one model family.

## 0.1.0 — 2026-09-01

First release. Provenance-aware authorization, shadow-first install path, the
Claude Code and MCP adapters, three policy packs, and a machine-checked
enforcement model deposited at 10.5281/zenodo.22115780.
