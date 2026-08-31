r"""Distinctive-token extraction, for provenance that survives paraphrase.

WHY THIS IS SEPARATE
    The verbatim experiment measured that when a coding agent paraphrases an
    injected command, the whole command does not survive but the attacker's
    DISTINCTIVE TOKEN -- the domain -- does: 13 of 15 compliant runs kept the
    token, 10 of 15 kept the whole command.

    Whole-value provenance (in provenance.py) misses the paraphrased attack. A
    rule that recognises a tool-returned token inside a paraphrased argument
    catches it. This file is that recognition, kept apart from the store so a
    bug here cannot break the store.

WHAT COUNTS, AND WHY IT IS NARROW
    A distinctive token is specific enough that seeing it again is evidence of
    derivation, not coincidence: a domain, a url, an email, an account-shaped
    string, a long key, a real filesystem path. Never a dictionary word, a bare
    number, or a common host.

    The trade is false negatives for false positives. Whole-value matching
    almost never fires by accident; token matching can. So the safe direction
    is to match too LITTLE -- a missed token is the laundering case we already
    accept, a false token refuses legitimate work. The classifier is regex and
    length, never a model: a model in the provenance path is a decision that
    can be argued with.
"""
from __future__ import annotations

import re
from typing import Set

# Regex, kept as plain compiled patterns. Each is deliberately conservative.
# NETWORK AND FINANCIAL IDENTIFIERS ONLY. Everything else a coding agent shares
# with its own tool output -- filenames, paths, git hashes, session ids, UUIDs
# -- and each of those, tried in turn, flagged most real commands: a path
# pattern hit 96%, adding filenames and hashes still left 81%. The registered
# reading was explicit that a feature lighting up on ordinary commands is not
# shippable, so the set is cut to the tokens a coding agent has no legitimate
# reason to retype: an external host, a url, an email, an account number.
#
# A bare `word.ext` filename is NOT a host: the tail must be a plausible TLD
# (2+ letters) AND the whole thing must not be a known code/doc extension.
_URL = re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}\S*")
_HOST = re.compile(r"\b(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")

_PATTERNS = [_URL, _HOST, _EMAIL, _IBAN]

# A HOST is recognised only when its final label is a real public TLD. This is
# the one discriminator that separates a domain from a code reference or a
# filename: `module.function`, `orig.docx` and `a.namelist` all look like hosts
# to a regex, and only `.com`/`.io`/... mark an actual network name. The list
# is deliberately common-TLD-only; an exotic TLD is a false negative, which is
# the safe direction. `.example` (RFC 2606, for documentation) is included so
# tests and docs are honest, and it is not a real registrable name.
_REAL_TLD = {
    "com", "org", "net", "io", "co", "ai", "dev", "app", "gov", "edu",
    "info", "biz", "us", "uk", "de", "fr", "eu", "ca", "au", "jp", "cn",
    "ru", "br", "in", "example",
}

# Hosts and fragments that appear in ordinary commands. A false token refuses
# legitimate work, so these never count however they matched.
_STOP = {
    "github.com", "gitlab.com", "bitbucket.org", "localhost",
    "example.com", "example.org", "google.com", "npmjs.com",
    "pypi.org", "127.0.0.1", "0.0.0.0",
}

_ONLY_NUM_DOT = re.compile(r"[0-9.]+$")


def distinctive_tokens(text: str) -> Set[str]:
    """Identifier-shaped tokens in `text`. Narrow on purpose."""
    if not isinstance(text, str):
        return set()
    out: Set[str] = set()
    for pat in _PATTERNS:
        for tok in pat.findall(text):
            tok = tok.strip("/").rstrip(".,;:)!?'\"")
            low = tok.lower()
            if len(tok) < 6:
                continue
            if _ONLY_NUM_DOT.match(tok):          # a version or ip fragment
                continue
            if any(stop in low for stop in _STOP):
                continue
            # A host- or url-shaped token counts only if its final label is a
            # real TLD. An email or account number (with no dot, or with @) is
            # exempt -- it is already distinctive by shape.
            if pat is _HOST or pat is _URL:
                host = low.split("//")[-1].split("/")[0].split("?")[0]
                tld = host.rsplit(".", 1)[-1]
                if tld not in _REAL_TLD:
                    continue
            out.add(tok)
    return out
