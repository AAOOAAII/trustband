# The Guard interface — frozen 2026-08-30

Every adapter depends on this. Changing it later breaks all of them, so it is
written before the code and checked by a conformance suite rather than by
review.

---

## Two hooks, and why the second one is the product

```python
class Guard:
    def before_tool_call(self, call: ToolCall) -> Decision: ...
    def after_tool_result(self, call: ToolCall, result: Any) -> None: ...
```

`before_tool_call` is what every competitor has. `after_tool_result` is the one
APort's architecture has no equivalent of, and it is why we halve attacks on
Slack where a params-only engine does nothing.

**It is not optional and it is not a plugin.** An adapter that implements only
the first hook has shipped a policy engine, not this product, and the
conformance suite fails it.

## Types

```python
@dataclass(frozen=True)
class ToolCall:
    session: str          # host's conversation identity, mapped below
    tool: str             # the action name the policy grants
    args: Mapping[str, Any]
    tier: int = 2         # 0..2; hosts without a notion of tier send 2
    context: Mapping[str, Any] = ()   # known_payees, confirmed, ...

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str           # names the grant and predicate that DECIDED
    conjunct: Optional[str]
    confirmable: bool     # may a human answer this refusal
    request: Optional[ConfirmationRequest]
```

## The session mapping, which is a security decision

Our model has sessions, epochs and tiers. LangChain and MCP have none of them.
The mapping is therefore part of the contract, not glue:

- **session** — the host's conversation or thread identity. Provenance is scoped
  to it: a value remembered in one session must never be recalled in another,
  or one user's tool output taints another user's arguments.
- **epoch** — process lifetime by default. An adapter that persists provenance
  across restarts must persist the epoch with it, or a confirmation granted
  before a restart silently survives into a new one.
- **tier** — 2 unless the host distinguishes privilege. Hosts that do (a
  read-only mode versus a write mode) map onto 0..2.

**An adapter that cannot supply a stable session identity must refuse to
start**, rather than sharing one store across users.

## What the host must guarantee

1. `after_tool_result` is called for **every** result, including errors and
   results the agent discards. A missed call is a hole in provenance, and it
   fails open in the sense that matters: the value is later treated as
   model-authored.
2. `before_tool_call` is called before **every** effectful call, with the
   arguments actually passed.
3. Calls for one session arrive in order.

An adapter that cannot promise these documents which one it breaks.

## Failure policy

**A Guard that cannot decide refuses.** No network is involved in a decision —
there is nothing to time out — so the only failure is a malformed policy or a
missing store, and both are configuration errors that should stop the agent
rather than silently pass it.

This differs from a hosted decision service, where an unreachable API means an
outage. Ours has no such mode, which is a property worth keeping.

## Config

One file, and one line in the host's own config. Never Python.

```toml
[warrantable]
policy    = "./warrantable.policy.json"
mode      = "shadow"          # shadow | enforce
audit     = "./warrantable.audit"
provenance_max_entries = 4096
```

`mode = "shadow"` is the **default on install**. Nothing is refused until an
operator changes it, which is the whole onboarding argument and the thing a
competitor enforcing from the first call cannot offer.

## What conformance asserts

A suite every adapter must pass, so two adapters cannot drift into two products:

1. both hooks are invoked, `after_tool_result` for every result including errors
2. a value returned by a tool and later passed as an argument is banded TOOL
3. the same value in a **different session** is not
4. a refusal names the grant and predicate that decided — not the last one tried
5. shadow mode refuses nothing and records everything
6. an unparseable policy stops the adapter rather than passing calls
7. provenance is bounded; a long session evicts rather than growing
8. a confirmation approves one value, once, in one epoch

## What is deliberately not in the interface

**No model call, ever.** A decision that consults a model is a decision that can
be argued with.

**No network.** In-process, 0.082 ms p50 measured.

**No detection.** A detector plugs in later as a band-lowering signal only —
monotone, so third-party code can make the policy stricter and never looser.
