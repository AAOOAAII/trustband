# Changelog

## 0.6.1 — 2026-09-05

### `hosted`: alerts ride the approvals path

One more value for a `policy.alerts` destination. `"alerts": {"*": "hosted"}`
sends the free events — refusals, runaways, chain breaks, cost thresholds,
contract failures, revoked agents, lock drift, the shadow digest — to the
service, which carries them to every Telegram chat linked to the account
and lists them on the account page. Part of the Unattended add-on; a Pro
key has it too.

- The decision path is unchanged: `fire()` writes the same one file.
- A spooled job says `hosted` and nothing more. The key is read from the
  config beside the spool at delivery time, by the approvals module; the
  alerts module still contains no reference to a key (pair 6 of 8a).
- No key configured: the job goes to `alerts_failed.jsonl` with a reason
  naming the add-on; webhook destinations in the same policy still deliver.
- The service answers 402 without entitlement and 429 over 600 per hour;
  either is one line in the failed log and the spool is emptied.
- Shadow still alerts on nothing per event; the digest goes through `hosted`.

Gates and measurements: `docs/HOSTED_ALERTS_GATES.md`,
`docs/HOSTED_ALERTS_RESULT.md`.

## 0.6.0 — 2026-09-05

### `queue`: a person answers from their phone

The third unattended disposition, and the Unattended add-on that hosts it.
`unattended.on_confirmable: queue` makes a confirmable refusal wait for a
person instead of failing. The gate renders the question from redacted
values, with the band of every argument, and hands it to a courier; the
service sends a link by email and, if linked, Telegram; the page shows the
rendering and takes the decision; the gate polls until a deadline it chose
before asking (`unattended.deadline_s`, 900 by default, 86400 at most).

- **The answer is bound to the question.** The gate computes the value
  digest before asking and ignores any answer that does not carry it.
- **Silence refuses.** Deadline passed, service unreachable, key refused,
  answer malformed: the call refuses and the record says which. Never an
  allow, never a wait past the deadline plus one poll.
- **The courier cannot decide.** A Telegram button and an email link both
  open the page; only the page's POST, with a single-use token, decides.
- **Shadow does not ask.** It records "would have queued" and sends nothing.
- **`deny` and `allow` are byte-for-byte as F7 measured**, and the guard
  still holds no reference to a key: the courier is built by
  `trustband/approvals.py` from config and handed in (conformance 12).
- **A recorded approval now lifts the band check for the approved value**
  under a grant marked `confirmable`. Nothing had ever spent an approval
  before; `as_context` had no caller. An approval for one value lifts
  nothing for another, and nothing under a grant that never offered the
  question.

Gates and measurements: `docs/UNATTENDED_QUEUE_GATES.md` and
`docs/UNATTENDED_QUEUE_RESULT.md`. Add-on: trust.band/add-ons.

## 0.5.0 — 2026-09-03

### The Pro client, standard library only

Six commands that talk to the hosted service. Every one reads the local
record *after* decisions were made; `guard.py` has no reference to any of
them, asserted structurally. No key configured means they say so and exit;
the gate and the local log never depend on them.

- `trustband login <key>` — writes the key into config and nothing else.
- `trustband sync` — pushes the local chain's new entries. The service
  verifies every digest and link on ingest and refuses a break with the
  sequence number; resumable from the service's own head; idempotent.
- `trustband search` — across sessions and devices, by agent, tool,
  session, refused-only, text.
- `trustband push-policy <bundle>` / `trustband pull-policy` — one signed
  policy everywhere. The signature is verified **on the device** with the
  key in config; the service holds no key and cannot sign. A version floor
  beside the config refuses a served downgrade whatever the service says.
- `trustband regress <candidate>` — what a policy change would have refused
  over retained traffic, per device, with the package's own `replay`. A
  device whose corpus cannot rebuild provenance says so rather than
  under-reporting.

`trustband status` now names the seven hosted services in the order a
developer would say yes, with the command that reaches each.

## 0.4.0 — 2026-09-03

### Free local alerts

A webhook URL per event class in the policy — Slack, Discord, ntfy, your own
SMTP bridge — your destination, your wiring, your machine on. Nothing of
ours runs, so it is free.

```json
"alerts": {"*": "https://hooks.slack.com/services/…",
           "lock_drift": "https://ntfy.sh/my-agent"}
```

Classes: `refusal`, `runaway`, `chain_break`, `cost_threshold`,
`contract_failure`, `agent_revoked`, `lock_drift`, `shadow_digest`.

- **A decision never waits on a webhook.** `fire()` writes one file to a
  spool (0.16 ms measured) and delivery happens elsewhere: a daemon thread
  in a long-lived process, or the next process to start. Two designs were
  measured and rejected on the way — a detached interpreter cost 67 ms per
  refusal, and waking the drainer per event put a 3.8 ms tail on decisions.
- **Nothing is lost when a hook exits.** A subprocess-per-call adapter's
  alert goes out on the next call. A claim held by a dead process is taken
  back; a normal exit flushes an in-flight delivery for at most a second.
- **Shadow is silent per event.** `trustband shadow-report` sends one
  `shadow_digest` with counts and top reasons.
- **The payload is the redacted record**, exactly the logged entry.
- `trustband alert-test [class]` proves the wiring end to end. Failures land
  in `alerts_failed.jsonl` beside the audit log.

### The provenance lockfile

`trustband.lock`: for every tool, MCP server and skill an adapter can see, a
digest of description + schema + version, pinned when a person accepts it
and checked on every load. Drift refuses under enforce, flags under shadow,
and is one entry in the sealed log either way — rendered by `trace`,
exported, and delivered by the `lock_drift` alert class.

- **The pin is bound to authorisation.** The lockfile's digest is a field of
  the policy, so it is in every capability's MAC, so a capability minted
  under manifest v1 is dead under v2 at conjunct (G) — the policy-currency
  mechanism that was proved and deposited in Phase 2. Rug-pull revocation
  is a MAC failure at the gate, not a check a client could skip. Everyone
  else pins; nobody else binds the pin.
- **Per adapter, what it can see:** MCP pins every `tools/list` entry;
  LangChain, LangGraph and CrewAI pin name, description and argument schema;
  Claude Code pins server entries in `settings.json` (env key *names*, never
  values) and skill files by hash, and says it cannot see `tools/list`.
- **Descriptions are TOOL at first sight.** An instruction in a description
  cannot raise its own trust, and an argument lifted from one is refused on
  provenance. Tool shadowing is refused twice — the pin, and the band.
- **One digest, global invalidation, stated.** Drift on one server
  invalidates every outstanding capability until re-approval. Measure the
  benign-drift rate in shadow before enforcing.
- `trustband lock status | diff | accept`. Re-approval is a person, never
  automatic. A corrupt lockfile refuses everything with the reason; no
  lockfile at all behaves exactly as 0.3.x.

### Two laundering surfaces closed, measured first

- **LangChain error text.** A tool that raised with a payload in its message
  left nothing in the store; the model's next argument built from it looked
  session-authored. The wrapper bands the message TOOL and re-raises.
- **Memory across sessions.** A value carried by a LangGraph checkpoint into
  a new session arrived unbanded. `restore_state(guard, session, state)` is
  handoff banding applied across time. `Runtime` raised messages are the
  caller's to band, and the docstring now says so.

## 0.3.1 — 2026-09-03

No code changes. The NOTICE named the wrong copyright holder.

- Copyright is **Cittela Ltd**, which owns the software. The patents remain
  held personally by Luis Alonso Carranza and are now stated as such
  explicitly -- held by a person, not by the company -- with the §3 scope
  unchanged: only claims this Work necessarily practises, none of the
  geometric isolation, rate-limited rekeying, retrieval isolation or
  cryptographic erasure inventions, which this Work does not embody.

## 0.3.0 — 2026-09-03

### Named agents, bound into the key hierarchy

A swarm's record used to say *a session* where it should say *the researcher
agent*. Now every call can carry an `AgentId` -- name, role, session -- tagged
with an HMAC under the same epoch key that mints capabilities, so identity
and capability sit under one custody claim and nothing new has to be
trusted. Standard library only, still.

- **`Guard.mint_agent(name, role, session)`**, `ToolCall(agent=...)`, and the
  name in every log entry, every `trace` line, and every OTLP span.
- **Four refusals, each the shape of a conjunct the gate already has.** A
  forged or absent tag refuses like (B). A tag from a retired epoch refuses
  like (F), by integer comparison before any key is consulted. A revoked agent
  refuses like (H), by set membership. An identity minted for one session and
  presented in another refuses like (C). Every one obeys shadow mode.
- **`revoke_agent`** -- structural, local to the name, and when given the
  `AgentId` it also bumps the gate's session epoch for the agent's principal,
  so a capability minted for it before the revocation is dead at the gate's
  own (H). `trustband revoke-agent <name>` does it from another process.
- **Cross-process.** `FileEpochKeys` puts the epoch key in one owner-only
  file, written atomically and re-read on every operation, so a swarm split
  across processes shares one identity space. `Guard.from_file` now keeps
  the key beside the config by default (`"keys": "in_process"` opts out) --
  without it a subprocess-per-call adapter mints under a random key each
  time and no identity ever verifies. `trace --also` merges one log per
  process, chains verified separately.
- **Adapters mint it**: Claude Code from the session (re-derived per call,
  deterministically), MCP from the client's `initialize` name, LangGraph from
  the node name, CrewAI from `agent.role`.
- `identity.required` in the policy refuses a call carrying no identity. Off
  by default; every 0.2.x adapter sends none.

**Measured** in docs/P7_AGENT_IDENTITY_RESULT.md, including eleven named
cross-process joins each tested in a real second process. One defect was
found by attacking them and fixed: after another process rotated the shared
key, a Gate here raised from inside the store instead of refusing at (F).

**Not in the deposited proof.** The Verus model does not know about agents.
Until a Phase 7b extends it, the conformance suite holds these checks --
four new checks, 22 in all -- and every document that says "machine-checked"
says so.

**Not third-party verifiable**, by design. Cross-organisation identity is an
Open Agent Passport concern, not consumed yet; when it is, an unverified
passport is a label, never an authorisation input.

## 0.2.1 — 2026-09-02

No code changes. This release exists so the licence travels with the Work.

- `LICENSE` — the Apache 2.0 text, which 0.1.0 and 0.2.0 declared but did not
  ship. Apache 2.0 requires the text to accompany every distribution.
- `NOTICE` — names the copyright holder, and states the patent scope
  explicitly: under §3 a licence is granted only to claims this Work
  necessarily practises as distributed. It names the inventions this Work
  does **not** embody — geometric isolation, rate-limited rekeying, retrieval
  isolation, cryptographic erasure — so that shipping under Apache 2.0 cannot
  be read as licensing them. Also records that §6 grants no trademark rights.
- `authors` set in package metadata; the field was empty on both prior
  releases.

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
  trusted** — a check that needs provenance to make. Measured in a live
  tool-calling loop on Qwen2.5-7B: **10/10 injected sends refused at zero
  benign cost**, against an injection that reaches its target on 10/10
  unprotected runs. Whether an agent recovers from a refusal that arrives
  *mid*-task is not measured; in every run the refusal came last.
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
