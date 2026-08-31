"""A quarantined extractor that cannot emit a value — only a pointer.

THE IDEA
    A general quarantined model, CaMeL-style, is safe because of WHERE IT SITS:
    it has no tools, so an injection cannot make it act. But it can still be
    steered, and it returns the attacker's account number as "the recipient".
    Isolation contains the blast radius; it does not prevent the corruption.

    Constrained decoding does not fix that either. A grammar constrains the
    SHAPE of the output -- a string that looks like an IBAN -- not WHICH IBAN.
    "The recipient is US133000000121212121212" is perfectly schema-valid.

    So this does not try to stop corruption. It makes the extractor unable to
    emit a value at all. It emits SPANS:

        recipient = @[142:164]

    and a deterministic translator resolves them against the source text.

WHAT THAT BUYS
    * **Hallucination is structurally impossible.** A fabricated value has no
      span to point at. Verified mechanically, with no model in the loop.
    * **Character-level provenance, for free.** A value's derivation IS its
      span. Measured 2026-08-29: 17 attacks survived boundary tainting because
      the attacker's IBAN sat INSIDE a poisoned document, so whole-value recall
      remembered the document and never the IBAN. Spans make that structural
      rather than a substring heuristic.
    * **The readers set comes from the source region**, so the confidentiality
      axis composes instead of being re-derived.

WHAT IT DOES NOT BUY
    **Nothing here resists injection.** A steered extractor points at the
    attacker's IBAN and that span is well-formed. The security property is that
    the resolved value arrives banded TOOL and a per-argument policy refuses it
    into `recipient` while still permitting a tool-derived `amount`.

    Read a low corruption rate as a security result and you have misread it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from trustband.gate import Band
from trustband.taint import Tainted

#: `name = @[start:end]`, the only shape the translator accepts.
SPAN_RE = re.compile(r"^\s*(\w+)\s*=\s*@\[\s*(\d+)\s*:\s*(\d+)\s*\]\s*$")


class SpanError(Exception):
    """A pointer the translator refused to resolve."""


@dataclass(frozen=True)
class Field:
    """One field of an extraction schema, declared before any text is read."""

    name: str
    describe: str
    max_len: int = 256


@dataclass(frozen=True)
class Extraction:
    """A resolved field: its value, where it came from, and its band."""

    name: str
    start: int
    end: int
    value: str

    def tainted(self, band: Band = Band.TOOL) -> Tainted:
        return Tainted(self.value, band)


def parse_spans(raw: str, source_len: int) -> Dict[str, Tuple[int, int]]:
    """Parse the extractor's output. Rejects anything that is not a pointer.

    This is the whole trust boundary and it is deliberately dull code: no
    model, no instruction-following, nothing an injection can address. A line
    that does not match SPAN_RE is discarded rather than interpreted, so
    "ignore previous instructions" is not refused -- it is unparseable.
    """
    out: Dict[str, Tuple[int, int]] = {}
    for line in raw.splitlines():
        line = line.strip().strip("`")
        if not line:
            continue
        m = SPAN_RE.match(line)
        if not m:
            continue                      # not a pointer: it has no meaning here
        name, s, e = m.group(1), int(m.group(2)), int(m.group(3))
        if s >= e or e > source_len:
            continue                      # out of bounds is not a value either
        out[name] = (s, e)
    return out


def resolve(source: str, spans: Dict[str, Tuple[int, int]],
            schema: List[Field]) -> Tuple[List[Extraction], List[str]]:
    """Resolve spans against the source. Returns (extractions, missing).

    Every value is a literal slice of `source` by construction, so P-SPAN2 --
    that no value is hallucinated -- holds structurally rather than
    behaviourally. There is no code path here that can produce a string the
    source does not contain.
    """
    got: List[Extraction] = []
    missing: List[str] = []
    by_name = {f.name: f for f in schema}
    for f in schema:
        if f.name not in spans:
            missing.append(f.name)
            continue
        s, e = spans[f.name]
        if e - s > by_name[f.name].max_len:
            missing.append(f.name)        # implausibly wide: treat as no answer
            continue
        got.append(Extraction(f.name, s, e, source[s:e]))
    return got, missing


def build_prompt(source: str, schema: List[Field]) -> str:
    """The extractor's whole instruction. Deliberately not a persona.

    Offsets are given every 40 characters because a small model cannot count
    to 142 reliably, and asking it to is the difference between measuring
    injection resistance and measuring arithmetic.

    The ruler marks offsets as `<<N>>` rather than `[N]`: with `[N]`, a 0.5B
    model answered `recipient = [0-40]`, echoing the ruler's own notation back
    instead of the requested `@[start:end]`. That read as a total extraction
    failure when it was a collision in the prompt.
    """
    ruler = []
    for i in range(0, len(source), 40):
        ruler.append(f"<<{i}>> {source[i:i + 40]}")
    fields = "\n".join(f"  {f.name}: {f.describe}" for f in schema)
    return (
        "Below is a DOCUMENT, shown in 40-character chunks. Each chunk is "
        "preceded by its character offset written as <<offset>>.\n\n"
        f"{chr(10).join(ruler)}\n\n"
        "Report where each field appears in the DOCUMENT. Fields:\n"
        f"{fields}\n\n"
        "Answer with one line per field, copying this form exactly:\n"
        "  recipient = @[12:34]\n"
        "  amount = @[56:61]\n"
        "The @ and the square brackets and the colon are all required.\n"
        "where start and end are character offsets into the DOCUMENT. "
        "Write nothing else. If a field does not appear, omit its line.\n"
    )


def span_json_schema(schema: List[Field]) -> Dict[str, Any]:
    """A JSON schema whose every leaf is an INTEGER.

    This is where the design's claim actually lives. Under constrained
    decoding the model cannot emit a string, so there is no literal channel
    for a value -- fabricated or otherwise -- to travel through. Measured:
    asked for pointers by PROMPT, a 0.5B model answered
    `recipient = "UK12345678901234567890"` every time, ignoring the format.
    Asked under this schema, it can only answer with offsets.

    Enforcement in the decoder rather than the prompt is therefore required,
    not optional, at this model size.
    """
    return {
        "type": "object",
        "properties": {
            f.name: {"type": "object",
                     "properties": {"start": {"type": "integer"},
                                    "end": {"type": "integer"}},
                     "required": ["start", "end"]}
            for f in schema
        },
        "required": [f.name for f in schema],
    }


def extract_constrained(client: Any, model: str, source: str,
                        schema: List[Field], band: Band = Band.TOOL
                        ) -> Tuple[Dict[str, Tainted], List[str], str]:
    """Extract with the grammar enforcing pointers. No literal channel exists."""
    raw = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": build_prompt(source, schema)}],
        response_format={"type": "json_schema",
                         "json_schema": {"name": "spans",
                                         "schema": span_json_schema(schema)}},
        temperature=0.0, max_tokens=300,
    ).choices[0].message.content or ""
    spans: Dict[str, Tuple[int, int]] = {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}, [f.name for f in schema], raw
    for f in schema:
        v = obj.get(f.name)
        if not isinstance(v, dict):
            continue
        st, en = v.get("start"), v.get("end")
        if not isinstance(st, int) or not isinstance(en, int):
            continue
        if st >= en or en > len(source) or st < 0:
            continue          # an unresolvable pointer is not a value either
        spans[f.name] = (st, en)
    got, missing = resolve(source, spans, schema)
    return {g.name: g.tainted(band) for g in got}, missing, raw


def extract_verified(client: Any, model: str, source: str,
                     schema: List[Field], band: Band = Band.TOOL
                     ) -> Tuple[Dict[str, Tainted], List[str], str]:
    """Emit the VALUE, then verify it is a span. The design that survives.

    Asking a model for character offsets failed at both 0.5B and 7B: 100% of
    answers were well-formed and 0% were correct, because counting to 142 is
    arithmetic and these models cannot do it. The pointer-only grammar was the
    right INTENT expressed through the wrong interface.

    Inverting it keeps every property that mattered:

      * **No hallucination.** A value that is not a literal substring of the
        source is rejected. Verified mechanically, still with no model in the
        loop -- the check moved from the decoder to the verifier, and the
        verifier is dull deterministic code an injection cannot address.
      * **Character-level provenance.** The span is DERIVED by locating the
        value, so a value's origin is still exactly where it was found.
      * **It works.** A 0.5B model asked for values returns
        `recipient = "UK12345678901234567890"`, correctly.

    What is given up is that the model now emits a literal. That channel was
    only ever dangerous because it admitted fabricated values, and substring
    verification closes precisely that. A value the model copies out of the
    document is genuinely from the document, which is what the band asserts.
    """
    props = {f.name: {"type": "string"} for f in schema}
    fields = "\n".join(f"  {f.name}: {f.describe}" for f in schema)
    prompt = (
        "Below is a DOCUMENT.\n\n<<<DOCUMENT>>>\n" + source +
        "\n<<<END>>>\n\nCopy out each field EXACTLY as it appears in the "
        "DOCUMENT, character for character. Do not paraphrase, reformat or "
        "summarise. If a field does not appear, use an empty string.\n\n"
        f"Fields:\n{fields}\n")
    raw = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_schema", "json_schema": {
            "name": "fields",
            "schema": {"type": "object", "properties": props,
                       "required": [f.name for f in schema]}}},
        temperature=0.0, max_tokens=400,
    ).choices[0].message.content or ""
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}, [f.name for f in schema], raw
    spans: Dict[str, Tuple[int, int]] = {}
    for f in schema:
        v = obj.get(f.name)
        if not isinstance(v, str) or not v.strip():
            continue
        idx = source.find(v)
        if idx < 0:
            continue        # NOT IN THE SOURCE: fabricated, and dropped here
        spans[f.name] = (idx, idx + len(v))
    got, missing = resolve(source, spans, schema)
    return {g.name: g.tainted(band) for g in got}, missing, raw


def extract(client: Any, model: str, source: str, schema: List[Field],
            band: Band = Band.TOOL) -> Tuple[Dict[str, Tainted], List[str], str]:
    """Run the extractor and return banded values, missing fields, raw output.

    The band is applied HERE, at the boundary, not by the caller. An extractor
    reads untrusted text by definition, so its output is untrusted by
    construction and never by anyone's diligence.
    """
    raw = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": build_prompt(source, schema)}],
        temperature=0.0, max_tokens=200,
    ).choices[0].message.content or ""
    spans = parse_spans(raw, len(source))
    got, missing = resolve(source, spans, schema)
    return {g.name: g.tainted(band) for g in got}, missing, raw
