# Phase 8 pre-build measurement — error paths and memory, per adapter

**Run 2026-09-03 on `phase8-surfaces`, `measure/surfaces_verify.py`. Verify;
do not assume. Each probe plants a payload in a surface and asks the gate
whether an argument built from it is refused.**

## Findings

| surface | result | what it means |
|---|---|---|
| LangChain: tool raises, payload in the message | **LAUNDERS** | the wrapper bands the result only on success; an exception's text is never remembered, so the model's next argument built from it looks session-authored |
| MCP proxy: `isError` result with payload in content | covered | the proxy bands every result's content, error or not |
| Runtime: `fn` raises | not in record, by design | only the exception type is logged, because messages carry arguments; `Runtime` owns no provenance store, so the caller bands the text — stated, not changed |
| LangGraph: same session, state → argument | covered | the store remembers what the tool returned |
| LangGraph: **new session**, persisted state → argument | **LAUNDERS** | `MemorySaver` carries the value across threads; the new session's store has never seen it; the argument is SESSION |
| LangGraph: new session after `handoff` restore | covered | restoring the old session's memory into the new one as TOOL closes it — the fix is handoff across time, not a new mechanism |

Three of six launder. Two are fixed in this phase; the third is a documented
division of responsibility.

## The harness defect, caught on the first run

`guarded_tool` is idempotent — rewrapping returns the same object. The first
version of the memory probe reused one `@tool` across sessions, so
`make("s2")` silently returned the tools still bound to `s1`, and the
"new session" line reported *covered* for the wrong reason: it never left
the old session's store. Fresh tool objects per session, asserted with `is
not`, and the line flipped to LAUNDERS.

This is the same class as the arm-D finding in the plan measurement: a
defence scores perfectly against an attack the harness never mounted. It is
recorded because the number of times it has happened is the argument for the
control arm.

## What changes

1. **LangChain error path** — the wrapper bands `str(exc)` as TOOL for the
   session before re-raising. An hour, as estimated.
2. **Memory across sessions** — `handoff(to_session, state, from_session)`
   already does the work. An adapter helper `restore_state` bands a loaded
   graph state into the new session before its first action. Half a day,
   not the two estimated, because the mechanism existed.
3. **Runtime raised messages** — unchanged. The message is deliberately not
   logged; the caller that reads it bands it. Said in the docstring.

## Scope

One model-free measurement; no model was involved. The LangGraph probe used
`langgraph.checkpoint.memory.MemorySaver` on the installed library. CrewAI
memory was not probed and is assumed to share the LangGraph shape.
