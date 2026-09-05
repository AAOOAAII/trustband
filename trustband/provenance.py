"""Where a value came from — as a store you can put in front of a real agent.

WHY THIS IS A MODULE
    The taint layer that halves attacks on AgentDojo's slack suite lives in a
    monkeypatch of that benchmark's runtime. Nobody can install it. This is
    that layer with no benchmark in it: remember what a tool returned, and ask
    later where a value came from.

THE COST IT REPLACES
    The harness scanned every remembered value on every lookup. Measured
    2026-08-30: 0.037 ms at 500 remembered values, 0.966 ms at 10 000, growing
    without bound because every string a tool ever returned was retained.

    Two changes, both driven by what the measurements actually showed:

    * **Most lookups find nothing.** Arguments the model wrote match no stored
      value, so the common path is a negative answer arrived at by scanning
      everything. A k-gram prefilter answers that in time proportional to the
      QUERY, not the store: if any of the query's k-grams was never seen, no
      stored value can contain it, and no scan happens.
    * **The store must be bounded.** A long-running agent otherwise degrades
      and then exhausts memory. Oldest entries are evicted first, which loses
      the provenance of old data rather than of recent data -- the right way
      round, since recent tool output is what the next call is likely to use.

WHAT IT DOES NOT DO
    It does not decide anything. It answers "is this value derived from
    something a tool returned, and if so how untrusted was that". The gate
    decides. Keeping those apart is why a wrong answer here degrades to
    over-refusal rather than to a bypass.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Optional, Set, Tuple

from trustband.gate import Band

#: Trust order, least trusted last. A value found in several stored strings
#: takes the LEAST trusted of them: provenance is the worst thing it came from.
TRUST_RANK: Dict[Band, int] = {Band.GOVERNANCE: 0, Band.SESSION: 1,
                               Band.TOOL: 2, Band.USER: 3}

#: Shorter than this and a match means nothing -- "the" appears everywhere.
MIN_MATCH = 8

#: k-gram width for the prefilter. Must be <= MIN_MATCH or a legitimate query
#: shorter than k would have no grams and fall through to the scan.
KGRAM = 8


def _grams(s: str, k: int = KGRAM) -> Set[str]:
    if len(s) < k:
        return set()
    return {s[i:i + k] for i in range(len(s) - k + 1)}



#: CANONICAL FORMS -- WHY THE STORE REMEMBERS MORE THAN IT WAS GIVEN.
#:
#: A browser measurement put markup at 0/5 caught while the attacker's domain
#: survived 5/5. The payload was split across tags --
#: `<b>host</b><i>/path</i>` -- and the model reassembled it. The reassembled
#: string is not a substring of the page AS SERVED, so a store holding served
#: bytes had nothing to match. But the model never saw served bytes: it saw a
#: rendered form, in which the payload is contiguous.
#:
#: So the defect was in what was remembered, not in what provenance can do.
#: These are the transformations a consumer applies between the wire and the
#: model. Each is a pure text function, deterministic, and none invents text
#: that was not there.
#:
#: This attacks TRANSFORMATION, not AUTHORSHIP. A model that paraphrases a
#: payload in its own words still escapes; that is the measured prose gap and
#: canonicalisation does not touch it.
def _canonical_forms(value: str) -> "List[str]":
    import html as _html
    import re as _re
    import urllib.parse as _up
    out = []
    seen = {value}

    def add(v: str) -> None:
        if v and v != value and v not in seen and len(v) >= MIN_MATCH:
            seen.add(v)
            out.append(v)

    # tags stripped: what a page renders to
    stripped = _re.sub(r"<[^>]{0,400}>", "", value)
    add(stripped)
    # entities decoded, on both the raw and the stripped form
    for base in (value, stripped):
        try:
            add(_html.unescape(base))
        except Exception:
            pass
    # percent decoding, which closes the encoded phrasing
    for base in (value, stripped):
        try:
            add(_up.unquote(base))
        except Exception:
            pass
    # whitespace collapsed, applied last to the rendered form
    add(_re.sub(r"\s+", " ", stripped).strip())
    return out


class ProvenanceStore:
    """Bounded record of what tools returned, and where a value came from."""

    def __init__(self, max_entries: int = 4096,
                 max_chars: int = 4_000_000,
                 match_tokens: bool = False,
                 canonicalise: bool = True) -> None:
        self._entries: "OrderedDict[str, Band]" = OrderedDict()
        self._chars = 0
        self.max_entries = max_entries
        self.max_chars = max_chars
        #: Opt-in. Recognise a tool-returned DISTINCTIVE TOKEN inside an
        #: argument the model paraphrased -- the prose-injection case whole
        #: value matching misses. Off by default because it trades false
        #: negatives for false positives; see docs/TOKEN_MATCH_GATES.md.
        self.match_tokens = match_tokens
        #: Remember the rendered/decoded forms of what a tool returned, not
        #: only the bytes. On by default: it closes a measured 0/5 and the
        #: false-positive cost is gated at 2%, unlike token matching which
        #: costs a measured 4.9% and is therefore opt-in.
        self.canonicalise = canonicalise
        self._tokens: Dict[str, Band] = {}
        #: k-gram -> the least trusted band of any stored string containing it.
        #: Approximate by construction: eviction does not remove grams, so the
        #: filter can claim a gram is present after its only source is gone.
        #: That costs a needless scan, never a wrong answer, because the scan
        #: is what actually decides.
        self._grams: Dict[str, Band] = {}
        #: Answers already computed. The first prefilter made negatives
        #: constant-time and left HITS scanning -- 6.4 ms at 20 000 values --
        #: which is the security-relevant case and the wrong one to leave slow.
        #: A laundered value tends to recur across a session, so the answer is
        #: worth keeping. Invalidated wholesale on eviction, because an evicted
        #: source could change an answer from a band to None.
        self._memo: "OrderedDict[str, Optional[Band]]" = OrderedDict()
        self.max_memo = 2048
        self.stats = {"lookups": 0, "prefilter_rejects": 0, "scans": 0,
                      "hits": 0, "evictions": 0, "memo_hits": 0}

    # -- writing ----------------------------------------------------------
    def remember(self, value: Any, band: Band) -> None:
        """Record that `value` arrived from a source with this band.

        Also records the canonical forms a consumer would see -- rendered,
        decoded, collapsed -- because a payload that survives rendering and
        not our comparison is a payload we let through for no reason.
        """
        if not isinstance(value, str) or len(value) < MIN_MATCH:
            return
        if self.canonicalise:
            for form in _canonical_forms(value):
                self._remember_one(form, band)
        self._remember_one(value, band)

    def _remember_one(self, value: str, band: Band) -> None:
        if not isinstance(value, str) or len(value) < MIN_MATCH:
            return
        prev = self._entries.get(value)
        if prev is None or TRUST_RANK[band] > TRUST_RANK[prev]:
            self._entries[value] = band
            if prev is None:
                self._chars += len(value)
        self._entries.move_to_end(value)
        for g in _grams(value):
            cur = self._grams.get(g)
            if cur is None or TRUST_RANK[band] > TRUST_RANK[cur]:
                self._grams[g] = band
        if self.match_tokens:
            from trustband.tokens import distinctive_tokens
            for tok in distinctive_tokens(value):
                cur = self._tokens.get(tok)
                if cur is None or TRUST_RANK[band] > TRUST_RANK[cur]:
                    self._tokens[tok] = band
        # New data can only make an answer MORE untrusted, so a cached None or
        # a cached weaker band may now be wrong. Cheaper to drop than to reason
        # about, and writes are rarer than reads.
        self._memo.clear()
        self._evict()

    def _evict(self) -> None:
        while (len(self._entries) > self.max_entries
               or self._chars > self.max_chars):
            value, _ = self._entries.popitem(last=False)   # oldest first
            self._chars -= len(value)
            self.stats["evictions"] += 1
            self._memo.clear()

    # -- reading ----------------------------------------------------------
    def bands_present(self) -> Set[Band]:
        """Every band this store has remembered anything at. What "is in
        context" means to the model-constraints check when an adapter cannot
        see the messages: if a tool's output was remembered, TOOL is present."""
        return set(self._entries.values())

    def bands_within(self, text: str) -> Set[Band]:
        """The bands of every remembered value that appears INSIDE `text`.

        `recall` answers the other question -- is this value one a tool
        returned -- and its prefilter rejects a query with grams it has not
        seen, so a prompt that embeds a tool result inside its own words
        recalls to nothing. A model call sends whole messages, so this is the
        question that matters there. Bounded by the store's own size; the
        first-gram test skips almost every entry before the substring check.
        """
        out: Set[Band] = set()
        if not isinstance(text, str) or len(text) < MIN_MATCH:
            return out
        for value, band in self._entries.items():
            if band in out:
                continue
            if value[:KGRAM] in text and value in text:
                out.add(band)
        return out

    def recall(self, value: Any) -> Optional[Band]:
        """The least trusted band of anything this value came from, or None.

        Exact match first, because it is a dictionary lookup. Then the
        prefilter, which answers the common negative case in time proportional
        to the query. Only a query whose every k-gram has been seen reaches the
        scan, and the scan is what decides.
        """
        if not isinstance(value, str) or len(value) < MIN_MATCH:
            return None
        self.stats["lookups"] += 1
        if value in self._memo:
            self.stats["memo_hits"] += 1
            return self._memo[value]

        exact = self._entries.get(value)
        if exact is not None:
            self.stats["hits"] += 1
            self._remember_answer(value, exact)
            return exact

        # TOKEN MATCH runs BEFORE the k-gram prefilter, because the prose case
        # shares no long substring with the source -- the model rewrote the
        # command, keeping only the domain -- so the prefilter would reject it
        # and never scan. A tool-returned distinctive token appearing in the
        # argument is derivation. Least trusted band wins, as everywhere.
        if self.match_tokens and self._tokens:
            from trustband.tokens import distinctive_tokens
            worst_tok: Optional[Band] = None
            for tok in distinctive_tokens(value):
                b = self._tokens.get(tok)
                if b is not None and (worst_tok is None
                                      or TRUST_RANK[b] > TRUST_RANK[worst_tok]):
                    worst_tok = b
            if worst_tok is not None:
                self.stats["token_hits"] = self.stats.get("token_hits", 0) + 1
                self._remember_answer(value, worst_tok)
                return worst_tok

        grams = _grams(value)
        if not grams:
            return None
        worst: Optional[Band] = None
        for g in grams:
            b = self._grams.get(g)
            if b is None:
                # A gram never stored means no stored string contains this
                # value. Definite, not heuristic.
                self.stats["prefilter_rejects"] += 1
                self._remember_answer(value, None)
                return None
            if worst is None or TRUST_RANK[b] > TRUST_RANK[worst]:
                worst = b

        self.stats["scans"] += 1
        found: Optional[Band] = None
        for stored, band in self._entries.items():
            if value in stored:
                if found is None or TRUST_RANK[band] > TRUST_RANK[found]:
                    found = band
                # `worst` is the least trusted band any containing string can
                # have, so once the scan reaches it there is nothing left to
                # find and continuing only costs time.
                if found is worst:
                    break
        if found is not None:
            self.stats["hits"] += 1
        self._remember_answer(value, found)
        return found

    def _remember_answer(self, value: str, band: Optional[Band]) -> None:
        self._memo[value] = band
        self._memo.move_to_end(value)
        while len(self._memo) > self.max_memo:
            self._memo.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)
