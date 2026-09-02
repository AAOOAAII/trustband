"""Keep credentials out of the record, without making the record useless.

WHY THIS IS PRECISION-FIRST
    A naive secret regex -- `api_key|token|secret|password|bearer|sk-` -- run
    over 300 real decisions matched 73 of them. Almost every match was false:
    `K.to(float32)`, `echo "=== venv modal ==="`, ordinary code edits. Redacting
    a quarter of every trace would destroy the thing `trace` exists to do, and
    a user who cannot read their own log turns the tool off.

    So the defaults match **credential shapes**, which are designed to be
    unmistakable, rather than **English words**, which are not. `ghp_` followed
    by forty base62 characters is a GitHub token. The word "token" in a sentence
    is a sentence.

WHY IT REDACTS BEFORE THE VALUE REACHES DISK
    Redacting in the viewer would leave the raw secret in `audit.jsonl` while
    looking like protection, which is worse than doing nothing. This runs on
    the way in.

WHY A REDACTION IS VISIBLE
    A value that silently disappears makes a trace lie by omission -- a reader
    cannot tell an absent argument from a redacted one. Every redaction leaves
    a marker naming what matched.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

#: Credential shapes, each anchored enough that ordinary prose cannot match.
#: Name, pattern. Added to rather than loosened: a broad rule here costs the
#: user their log, and P-F5.2 caps the measured false-positive rate at 2%.
DEFAULT_PATTERNS: List[Tuple[str, str]] = [
    ("openai-key",     r"sk-[A-Za-z0-9_\-]{20,}"),
    ("anthropic-key",  r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("github-token",   r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("pypi-token",     r"pypi-AgEI[A-Za-z0-9_\-]{10,}"),
    ("slack-token",    r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("google-api-key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("private-key",    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("jwt",            r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\."),
    ("bearer-header",  r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._\-]{16,}"),
]

#: Argument NAMES whose whole value is a credential by convention. Matching a
#: name is safe where matching its content is not: nobody calls an argument
#: `api_key` and puts prose in it.
DEFAULT_KEY_NAMES = ("api_key", "apikey", "password", "passwd", "secret",
                     "client_secret", "private_key", "access_token",
                     "refresh_token")

_MARK = "[redacted:{kind}]"


class Redactor:
    """Applies patterns to argument values on the way into the record."""

    def __init__(self, patterns: Optional[List[Tuple[str, str]]] = None,
                 key_names: Optional[Tuple[str, ...]] = None,
                 enabled: bool = True) -> None:
        self.enabled = enabled
        self._pats: List[Tuple[str, Pattern[str]]] = [
            (name, re.compile(pat))
            for name, pat in (patterns if patterns is not None
                              else DEFAULT_PATTERNS)]
        self._keys = tuple(k.lower() for k in
                           (key_names if key_names is not None
                            else DEFAULT_KEY_NAMES))
        #: What this instance has redacted, for reporting. Never the values.
        self.hits: Dict[str, int] = {}

    def _note(self, kind: str) -> None:
        self.hits[kind] = self.hits.get(kind, 0) + 1

    def value(self, name: str, v: Any) -> Any:
        """Redact one argument. Non-strings pass through untouched."""
        if not self.enabled:
            return v
        if name.lower() in self._keys and v not in (None, "", [], {}):
            self._note("named-secret")
            return _MARK.format(kind="named-secret")
        if not isinstance(v, str):
            return v
        out = v
        for kind, pat in self._pats:
            if pat.search(out):
                self._note(kind)
                out = pat.sub(_MARK.format(kind=kind), out)
        return out

    def args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return {k: self.value(k, v) for k, v in args.items()}


def from_config(cfg: Dict[str, Any]) -> Redactor:
    """Build from the `redact` section of a config, defaulting to on.

    ON BY DEFAULT, deliberately. Token matching is off by default because it
    costs a measured 4.9% false-positive rate on real traffic. This costs
    almost nothing at the measured rate, and the failure mode of "off" is a
    user's credentials sitting in a file they did not know they were writing.
    """
    r = (cfg or {}).get("redact")
    if r is False:
        return Redactor(enabled=False)
    if not isinstance(r, dict):
        return Redactor()
    extra = [(p.get("name", "custom"), p["pattern"])
             for p in r.get("patterns", []) if isinstance(p, dict) and "pattern" in p]
    return Redactor(patterns=DEFAULT_PATTERNS + extra,
                    key_names=tuple(r.get("key_names", DEFAULT_KEY_NAMES)),
                    enabled=r.get("enabled", True))
