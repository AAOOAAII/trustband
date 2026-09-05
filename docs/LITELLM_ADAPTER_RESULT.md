# The LiteLLM adapter — result

**Measured 2026-09-06 against `LITELLM_ADAPTER_GATES.md`, overnight run,
against the installed `litellm` 1.99.0 with mock responses. Ships in
0.7.1.**

| | |
|---|---|
| P-LL.1 refused before the call | **PASS-CLEAN** |
| P-LL.2 usage, spend, ceiling | **PASS-CLEAN** |
| P-LL.3 per-call limit before the call | **PASS-CLEAN** |
| P-LL.4 the hint acts on a real Router | **PASS-WITH-DRIFT**: the mechanism moved, the gate was amended before the result |
| P-LL.5 version and pin | **PASS-CLEAN** after a test fix |
| P-LL.6 async is the same gate | **PASS-CLEAN** |
| P-LL.7 the logger cannot refuse, and the adapter never says it can | **PASS-CLEAN**, held by a test that fails if the library changes |
| P-LL.8 nothing prior moves | **PASS-CLEAN** |

`tests/test_model_gate_litellm.py` (15), three consecutive runs identical.
Conformance 22/22. The LangChain gate tests unchanged.

## Where the gate stands, measured

Three probes before writing, one more after:

- A `CustomLogger` raising in `log_pre_api_call` does not stop
  `litellm.completion`. The library catches it and the call proceeds. The
  wrapper is therefore the refusal surface, and P-LL.7 keeps a test that
  asserts the library's behaviour so a change is noticed rather than
  silently relied on.
- A `pre_call_check` that raises **fails the call**. The first probe, with
  one deployment, could not distinguish "dropped" from "failed"; the test
  with two deployments in one group could, and did: the check runs after
  the Router has chosen, and the Router does not choose again. The gate
  registration said otherwise and was amended, dated, before this result.
- The library's `token_counter` gives a count from the messages, so the
  per-call limit is judged before any request; with no counter the adapter
  does not guess.
- A mock `ModelResponse` carries the model name it is given, so version
  recording and pin drift are testable without a provider.

## What was built, and where the hint acts

`gated(guard, session)` returns one object:

- `completion` / `acompletion`: ask, then call. The bands come from the
  messages' text through the store's `recall` and `bands_within`, as the
  LangChain gate does; the count from the library; the record from the
  response's usage and `model`. Streaming is gated before it starts and
  records usage from the final chunk when `include_usage` was requested;
  otherwise the record says usage was unavailable.
- `route(router, group, messages)` / `aroute`: the hint first, with
  nothing recorded; the group narrowed to the deployments the hint permits,
  in the hint's order; then the one recorded question is about the
  deployment chosen, so the record names the model that ran. Nothing
  permitted: the question is asked about the group's first deployment so
  the refusal and its band reason are on the record, and no call is made.
  With TOOL content in the messages, five calls through a two-deployment
  group all answered from the small deployment; with SESSION content alone,
  the first permitted deployment ran.
- `logger`: the safety net. Registered in `litellm.callbacks`, its
  `pre_call_check` refuses a deployment the gate refuses, which fails a
  Router call that reached it by any other path, with the reason on the
  record and nothing called. Its success hooks record usage for calls the
  wrapper did not make and skip the ones it did.

The Router still chooses among what `route()` leaves it; when one
deployment remains, that is the choice. The adapter never forwards or
rewrites a request.

## The test fix

The pin test asserted drift on the second response without accepting the
first observation. As for tools, a model version is pending until a person
accepts it into the lockfile; the existing P-MC.5 test does exactly that.
The test was wrong, not the pin.

## What this does not show

- A real provider. Every response was a mock; the usage and version
  plumbing are the library's, the provider is not.
- Streaming usage without `stream_options={"include_usage": True}`: the
  record says unavailable, and the spend is not charged for that call.
- The proxy server's hooks. Out of scope, stated in the gates.
- A routing strategy of the Router's own among several permitted
  deployments: `route()` runs the first permitted in the hint's order,
  which is policy order. A later version can hand the narrowed set to the
  Router's strategy if someone needs it.
