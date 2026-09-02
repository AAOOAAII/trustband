# F6 — OpenTelemetry export. Result.

**Run 2026-09-02 against `F6_OTEL_GATES.md`, registered before the code.**

## Gates

| gate | verdict |
|---|---|
| P-F6.1 spans carry provenance attributes | **PASS-CLEAN** |
| P-F6.2 zero dependencies preserved | **PASS-CLEAN** |
| P-F6.3 export never changes or blocks a decision | **PASS-CLEAN** |
| P-F6.4 exported attributes are redacted | **PASS-CLEAN** after fixing a leak in F5 |
| P-F6.5 structurally valid OTLP/JSON | **PARTIAL** — structure verified, ingestion not |
| P-F6.6 nothing prior moves | **PASS-CLEAN** |

## P-F6.4 found a hole in F5, not in F6

Exporting a refusal shipped a live credential to a third-party collector. The
cause was upstream:

```
audit args   : {'token': '[redacted:openai-key]'}
audit reason : predicate: token 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz01…'
               is not in the 1-entry allowlist
```

**F5 redacted argument values and never the sentence describing them.** The
issuer builds refusal reasons from the raw value — `in_set`, `host_in_set` and
the predicate messages all quote it — so the log carried a redacted argument
and the plaintext secret side by side.

F5 passed all six of its gates because they tested argument values. Nobody
tested the reason.

Fixed at the record, which fixes three channels at once:

```
secret in audit log : False
secret in OTLP span : False
secret in notifier  : False
```

This is the second time a redaction hole was found by building the thing
downstream of it. The lesson is not "test reasons" — it is that a redactor
should be applied at every boundary the record crosses, and the boundaries are
easier to enumerate than the fields.

## P-F6.1 — the attributes nobody else emits

```
run_cmd.decision   trustband.decision=refuse  trustband.grant=1
                   trustband.band.cmd=tool    trustband.confirmable=true
read_page.result   trustband.band=tool        trustband.strings_remembered=1
```

`gen_ai.*` covers model calls and every vendor emits it. Provenance is the part
no other exporter can produce, which is what makes "their dashboard, our data"
a position rather than a concession.

`trustband.grant` emits `-1` for "no rule matched", never `0`, because 0 is a
real grant index and attributing a decision to a rule that did not make it is
the failure the P-OI4 work exists to prevent.

## P-F6.2 / P-F6.3

No non-stdlib import anywhere in the export path: `json`, `os`, `time`,
`urllib`, `typing`. The SDK is not taken, and the GenAI conventions being
pre-stable at v1.42.0 makes that the right call — the wire format is the
contract.

Export is **not in the decision path**. `guard.py` contains no reference to the
exporter; spans are built from the audit log after the fact. So a collector
that is down, slow or lying cannot reach a decision at all — a stronger
property than the notifier's, which had to be made non-blocking after it stalled
every refused call by five seconds.

```
unreachable collector -> False in 0.01s, error recorded, nothing raised
```

## P-F6.5 — PARTIAL, and a second instrument confirmed why

**Update, same day.** No collector could be run — the docker daemon is not up
and Colima does not boot on this machine — so the next best instrument was
tried: parsing the payload with the **official** `opentelemetry.proto`
protobuf definitions, which is the first thing a collector does.

It parsed. It was also a false positive, and the detail is the finding:

```
traceId bytes : 24   (OTLP requires 16)
spanId bytes  : 12   (OTLP requires 8)
```

**OTLP/JSON encodes trace and span ids as hex**, a documented deviation from
the protobuf JSON mapping, which uses base64 for `bytes` fields. Generic
`json_format` therefore read a correct 32-character hex id as base64 and
produced 24 bytes — **without raising**. Verified both directions: feeding it
base64 yields the right bytes, feeding it spec-correct hex yields the wrong
ones.

So the implementation is correct and **the validator was the wrong
instrument**. Had the check stopped at "parsed into ExportTraceServiceRequest:
yes", it would have claimed a validation it did not have, in the reassuring
direction.

The schema does catch what it can: an unknown field and an untyped attribute
are both rejected. It cannot catch an id-length error, which is precisely the
class of error a collector would.

P-F6.5 stays **PARTIAL**. What changed is that the reason is now specific: not
"we did not try", but "generic protobuf validation cannot settle OTLP/JSON id
encoding, and only an OTLP-aware receiver can".

## P-F6.5 — the original structural checks

Verified: `resourceSpans`, resource attributes, `scopeSpans`, 32-hex trace ids,
16-hex span ids, nanosecond times as strings, `end >= start`, every attribute
typed, and the payload round-trips through JSON.

**Not verified: that a live collector ingests it.** No collector was run.
Structural validity and ingestion are different assertions, and claiming the
second on the strength of the first is how a feature ships that nobody can
actually use. One `docker run otel/opentelemetry-collector` would settle it.

## Out of scope, named

Metrics and logs signals. Trace-context propagation from a host that already
has a trace — that needs the host to pass ids and is a larger contract.
Protobuf encoding. A vendored SDK.
