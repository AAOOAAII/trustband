# The LiteLLM adapter — the hint reaches a real router. Gates before the code.

**Registered 2026-09-06, before any implementation. Overnight run,
authorised. `MODEL_CONSTRAINTS_RESULT.md` left the second adapter out and
named LiteLLM as the one that matters, because it is the router people put
in front of several providers.**

## What the library allows, measured before writing

Three probes against the installed `litellm` 1.99.0 with mock responses:

- A `CustomLogger` that raises in `log_pre_api_call` does **not** abort
  `litellm.completion`; the library catches logger exceptions and the call
  proceeds. So a logger cannot refuse in the SDK path, and the adapter must
  not claim it can.
- A `CustomLogger` whose `pre_call_check(deployment)` raises removes that
  deployment from a `Router`'s candidates when `enable_pre_call_checks` is
  on. This is where the hint can act: a deployment the bands do not permit
  is dropped and the router chooses among the rest.
- A mock response carries `usage.prompt_tokens`, `usage.completion_tokens`
  and `model`, so usage and version recording can be tested without a
  provider.

## What this is

`trustband.adapters.litellm.gated(guard, session, agent=None)` returns a
gate object with:

- `completion(**kwargs)` and `acompletion(**kwargs)`: ask
  `before_model_call` with the model from `kwargs["model"]`, the bands
  computed from the messages' text (the store's `recall` and
  `bands_within`, as the LangChain gate does), and a token count from
  `litellm.token_counter` when it can be had; refuse by raising
  `ModelRefused(reason, hint)` before any request is made; on success
  record usage and the response's `model` as the version.
- `logger`: a `CustomLogger` for `litellm.callbacks`. Its `pre_call_check`
  and `async_pre_call_check` ask the gate about each Router deployment's
  underlying model, using the session's stored bands (the Router does not
  hand the check the messages), and raise for a deployment the gate refuses,
  so the Router routes around it. Its success hooks record usage for calls
  the wrapper did not make, and skip calls the wrapper already recorded.

## What it is not

- **Not a proxy and not a router.** The wrapper calls `litellm.completion`
  after the gate says yes; the Router still chooses. Nothing here rewrites
  a request.
- **Not a refusal in the SDK logger path.** Measured impossible above; the
  wrapper is the refusal surface, and the result says so.
- **Not streaming-aware in v1.** A streamed call is gated before it starts
  and its usage is recorded only if the final chunk carries it; otherwise
  the record says usage was not available. Stated, not hidden.

## Registered predictions

**P-LL.1 — refused before the call.** With TOOL content in the messages
and a model outside `by_band.tool`, the wrapper raises `ModelRefused`
carrying the hint, and no request is made: a counting logger sees zero
pre-call events. The permitted model proceeds and returns the mock reply.

**P-LL.2 — usage, spend, ceiling.** Each successful call records the
response's usage, priced from the table; the call that follows the ceiling
refuses with the spend and the ceiling in the reason; the mock's tokens
are what the record holds.

**P-LL.3 — per-call limit before the call.** With `max_tokens_per_call`
below the messages' token count, the wrapper refuses before any request
using the library's own counter; with the counter unavailable, it does not
guess and the call is judged on the other constraints.

**P-LL.4 — the hint acts on a real Router.** A model group of two
deployments, large and small: with TOOL content in the messages, five
calls through `gate.route(router, "chat", messages)` all answer from the
small deployment and the record's hint names it; with SESSION content
alone, the whole group stays and the first permitted deployment runs. A
group with nothing permitted refuses with the hint and makes no call.

*Amended 2026-09-06, after the first run, before the result:* the
registration above first said the logger's `pre_call_check` would drop a
deployment and the Router would choose again. Measured with two
deployments, it does not: the check runs after the Router has chosen and a
raise fails the call. The first probe, with one deployment, could not tell
the two apart. So the hint acts in `route()`, before the choice, and the
logger's check is the safety net: a Router called directly on a refused
deployment fails, with the reason in the record, and nothing is called.

**P-LL.5 — version and pin.** The response's `model` is recorded as the
version; with `pin` true a later response naming a different model writes
`lock_drift` and the next call refuses under enforce.

**P-LL.6 — async is the same gate.** `acompletion` refuses and records
exactly as `completion`; the Router's async check behaves as the sync one.

**P-LL.7 — the logger cannot refuse, and the adapter never says it can.**
A test asserts the library's behaviour: a raising `log_pre_api_call` does
not stop a call. If a future LiteLLM changes this, the test fails and the
result is updated rather than silently benefiting.

**P-LL.8 — nothing prior moves.** The full suite, conformance and the
LangChain gate tests pass unchanged; the guard's source still holds no
billing vocabulary; the adapter imports `litellm` lazily so an install
without it is untouched.

## Scope

In: `trustband/adapters/litellm.py`, tests against the installed library
with mock responses, the result document, the changelog, a line on the
site naming the two adapters. Out: streaming usage beyond what the final
chunk carries, the proxy server's hooks, any provider credential.
