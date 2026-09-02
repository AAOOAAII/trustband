# F0 — persist the decision record. Gates registered before the code.

**Registered 2026-09-02, before any change to `audit.py`, `guard.py` or the
adapters.**

## Why

`AuditLog` implements hash-chaining and is exercised by the custody demo, 13/13.
It is **never written to disk**. `AuditLog.__init__` takes no path, `export()`
is called from nowhere in the package, and no commit on any branch has ever
contained `audit.jsonl` or `audit_path`. `Guard` builds a `Gate`, which builds
an `AuditLog` in memory; the Claude Code adapter is a fresh subprocess per call,
so the chain never reaches a second entry. Measured: three decisions through
`Guard` write **zero files** and leave **one** in-memory entry.

Meanwhile:

- `OVERVIEW.md` — "Every decision, allowed or refused, lands in a hash-chained,
  tamper-evident log."
- `README.md`, shipped on PyPI — "in a tamper-evident log"
- trust.band's comparison table — "Tamper-evident audit · Hash-chained", against
  "No" for three competitors

**This was never true of the installed product.** It is not a regression; it was
never wired. The mechanism is real and the wiring is missing, which is why the
fix is code rather than a retraction.

It also blocks the roadmap. F1 trace, F3 cost, F4 replay and F6 OTel all read a
durable per-decision record. `shadow.jsonl` is the only thing persisted and it
carries no timestamp, no duration, no argument values, no rule identity and no
link from a call to its result. Building four read paths on that record would
repeat the `confirmable` defect at four times the scale — a field computed,
never written, and four features quietly reading a record too thin to support
them.

## Registered predictions

**P-F0.1 — every decision is recorded.** One entry per `before_tool_call`,
allowed or refused, in every mode including shadow. Count of entries equals
count of decisions.

**P-F0.2 — the chain survives process boundaries.** N separate subprocess
invocations of the hook produce one valid chain of N entries. This is the whole
point: the adapter is a subprocess, and an in-memory chain is worth nothing to
it.

**P-F0.3 — tampering is detected.** Editing any recorded body, reordering two
entries, or altering a digest makes verification fail and names the first bad
sequence number.

**P-F0.4 — truncation is detected only up to the last seal.** Removing entries
from the tail is undetectable from the chain alone; that is a property of hash
chains, not a defect to be hidden. The verify report must state the unsealed
tail length rather than implying the whole log is covered.

**P-F0.5 — the record is sufficient for the read paths.** Each entry carries:
timestamp, session, tool, argument names with bands, argument values subject to
redaction, decision, the deciding rule as an identity rather than only prose,
duration, and the linkage from a call to its result. Sufficiency is checked by
reconstructing a session from the log alone, with no other source.

**P-F0.6 — enforcement is unaffected.** Decisions are byte-identical with the
log enabled and disabled. **A logging failure must never change a decision**:
if the disk is full or the file is unwritable, the gate decides exactly as it
would have and the failure is surfaced, not swallowed and not converted into a
refusal. An agent broken by a full disk is a worse outcome than an unrecorded
decision, and the opposite choice would make the audit path a denial-of-service
surface.

## What this phase does not do

- No log rotation, retention policy, or size bound. Named so it is not assumed.
- No signing of the file itself; sealing remains the existing mechanism.
- No concurrency guarantee across simultaneous hook processes beyond append
  ordering — if two decisions race, the chain must still verify, but their
  relative order is whatever the filesystem gave. Stated rather than claimed.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
