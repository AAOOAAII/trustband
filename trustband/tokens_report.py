"""Token accounting, read from the host's own record.

TOKENS, NOT COST, AND THE REASON IS ARITHMETIC
    Measured on a real session: 97.6% of 3.84 billion tokens were cache
    *reads*, which price at roughly a tenth of input, while output prices at
    roughly five times it. Pricing everything at one rate overstates that
    session by 7.2x. So the four classes are never collapsed, and cost is an
    optional overlay the operator declares rather than a table this package
    ships and lets go stale.

    Token count is also the only figure that is true of every model. A local
    model costs nothing, and asking its operator to price it is an insult
    dressed as a feature.

WHERE THE NUMBERS COME FROM
    `transcript_path` is present in both hook events and points at the session
    JSONL, which records real per-turn usage. This reads that file. It does not
    estimate: `len(text)/4` cannot see caching and would have been ~7x wrong on
    the session above.

    The transcript is written asynchronously and may lag the live conversation,
    so this reconciles after the fact. It is a read path and nothing in the
    gate consults it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: The four classes, in the order a reader wants them. Never summed into one:
#: that is the 7.2x error.
CLASSES = ("input", "output", "cache_write", "cache_read")

_FIELD = {
    "input": "input_tokens",
    "output": "output_tokens",
    "cache_write": "cache_creation_input_tokens",
    "cache_read": "cache_read_input_tokens",
}


def turns(transcript: Path) -> Iterable[Dict[str, Any]]:
    """Per-turn usage, in transcript order. Turns without usage are skipped.

    A torn or unreadable line is skipped rather than fatal -- a transcript is
    the host's file, written concurrently, and a reader that dies on one bad
    line is a reader nobody can use.
    """
    try:
        fh = transcript.open(encoding="utf-8")
    except OSError:
        return
    with fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            msg = rec.get("message") or {}
            u = msg.get("usage")
            if not isinstance(u, dict):
                continue
            yield {
                "model": msg.get("model"),
                "service_tier": u.get("service_tier"),
                "ts": rec.get("timestamp"),
                **{c: int(u.get(_FIELD[c], 0) or 0) for c in CLASSES},
            }


def totals(rows: Iterable[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, int]], int]:
    """Per-model totals per class, and the turn count."""
    by_model: Dict[str, Dict[str, int]] = {}
    n = 0
    for r in rows:
        n += 1
        m = r.get("model") or "(model not recorded)"
        d = by_model.setdefault(m, {c: 0 for c in CLASSES})
        for c in CLASSES:
            d[c] += r[c]
    return by_model, n


def _price(counts: Dict[str, int], rates: Dict[str, float]) -> Optional[float]:
    """Money for one model, or None if it cannot be priced honestly.

    Partial rates yield None rather than a partial total: a number that
    silently omits 97% of the tokens is worse than no number.

    NO RATES AT ALL ALSO YIELDS None, EVEN WHEN EVERY COUNT IS ZERO. The first
    version returned 0.0 there, because it skipped zero classes and so never
    reached a missing rate -- and printed "0.00 at your declared rates" for a
    model whose rates were never declared. "Free" and "unpriced" are different
    claims and only one of them was true.
    """
    if not rates:
        return None
    total = 0.0
    for c in CLASSES:
        if counts[c] == 0:
            continue
        if c not in rates:
            return None
        total += counts[c] / 1_000_000.0 * float(rates[c])
    return total


def render(transcript: Path, cost_cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    rows = list(turns(transcript))
    if not rows:
        return [f"  no per-turn usage found in {transcript}",
                "  the host records usage there; if it is absent, this reports "
                "nothing rather than estimating."]

    by_model, n = totals(rows)
    cfg = cost_cfg or {}
    rate_table = cfg.get("rates_per_mtok") or {}
    as_of = cfg.get("priced_as_of")
    source = cfg.get("source")

    out: List[str] = [f"  {n} turn(s) with recorded usage", ""]
    grand = {c: 0 for c in CLASSES}
    money: List[Tuple[str, Optional[float]]] = []

    for model, counts in sorted(by_model.items()):
        tot = sum(counts.values())
        out.append(f"  {model}")
        for c in CLASSES:
            share = (counts[c] / tot) if tot else 0.0
            out.append(f"      {c:<12} {counts[c]:>16,}  {share:6.1%}")
            grand[c] += counts[c]
        out.append(f"      {'total':<12} {tot:>16,}")
        if rate_table:
            m = _price(counts, rate_table.get(model, {}))
            money.append((model, m))
            if m is None:
                out.append(f"      cost         unpriced — no rates declared "
                           f"for {model}")
            else:
                out.append(f"      cost         {m:,.2f} at your declared rates")
        out.append("")

    g = sum(grand.values())
    out.append("  all models")
    for c in CLASSES:
        out.append(f"      {c:<12} {grand[c]:>16,}  "
                   f"{(grand[c]/g if g else 0):6.1%}")
    out.append(f"      {'total':<12} {g:>16,}")

    if rate_table:
        known = [m for _, m in money if m is not None]
        if known:
            out.append(f"      {'cost':<12} {sum(known):>16,.2f}")
        else:
            # Printing 0.00 here would read as "this was free" when the truth
            # is "nothing could be priced".
            out.append(f"      {'cost':<12} {'nothing priced':>16}")
        if as_of or source:
            out.append(f"  priced as of {as_of or '(no date declared)'}"
                       f"{f' — {source}' if source else ''}")
        if any(m is None for _, m in money):
            out.append("  some models are unpriced; their tokens are counted "
                       "above and excluded from the money total.")
    else:
        out.append("  no rates declared, so no cost is shown. Add cost."
                   "rates_per_mtok to price these; a local model costs nothing "
                   "and needs none.")

    if grand["cache_read"] and g:
        out.append("")
        out.append(f"  cache reads are {grand['cache_read']/g:.1%} of all "
                   f"tokens. They are the cheapest class, which is why the four "
                   f"are never summed into one rate.")
    return out


def main(transcript: Path, cost_cfg: Optional[Dict[str, Any]] = None) -> int:
    for line in render(transcript, cost_cfg):
        print(line)
    return 0
