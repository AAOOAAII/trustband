# F6 — OpenTelemetry export. Gates before the code.

**Registered 2026-09-02, before any implementation. Base: F4 at `31c0368`.**

## The constraint that decides the design

`pip install trustband` ships **zero dependencies**, and that is a claim on the
PyPI page and a reason a security-minded reader trusts the install. The
OpenTelemetry SDK is a dependency, and a large one.

It is also unstable ground: the GenAI semantic conventions moved to their own
repository at v1.42.0 and remain **pre-stable with no 1.0**, and installing
CrewAI into this environment already broke `opentelemetry-exporter-otlp`'s
declared pins. Taking the SDK would trade a shipped claim for a moving target.

So this emits **OTLP/JSON over HTTP using `urllib`**. The wire format is the
contract, not the library.

## What is actually ours to contribute

`gen_ai.*` covers model calls and token usage and is other people's ground.
**Nobody has provenance attributes.** `trustband.*` — the band an argument
arrived at, the deciding grant, whether a refusal was confirmable — is the part
no other exporter can emit, and it is why "their dashboard, our data" is a
better position than competing with AgentOps.

## Registered predictions

**P-F6.1 — spans carry the provenance attributes.** Each decision emits a span
with `trustband.decision`, `trustband.grant`, `trustband.bands.<arg>`, and
`trustband.confirmable`. A span that says only "a tool ran" is what every other
exporter already emits.

**P-F6.2 — zero dependencies preserved.** No third-party import anywhere in the
export path. Checked structurally, not by intent.

**P-F6.3 — export never changes or blocks a decision.** An unreachable
collector, a hanging endpoint or a malformed response must not alter an outcome
or delay a call. Same principle as the audit write and the notifier, and the
notifier already taught this lesson once: a five-second timeout is still a
block.

**P-F6.4 — exported attributes are redacted.** F5 runs before export. A span
shipped to a third-party platform must not carry a credential the local log was
careful to strip.

**P-F6.5 — the payload is structurally valid OTLP/JSON.** Resource spans, scope
spans, span records with trace and span ids of the right length, times in
nanoseconds. **Ingestion by a live collector is NOT claimed unless one is
actually run**; structural validity and ingestion are different assertions and
the result will say which was tested.

**P-F6.6 — nothing prior moves.**

## Scope

In: an exporter that turns decision and result events into OTLP/JSON spans,
emitting over HTTP or to a file, with provenance attributes.

Out, and named: metrics and logs signals; trace context propagation from a host
that already has a trace, which needs the host to pass ids and is a bigger
contract; protobuf encoding; a vendored SDK.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.
