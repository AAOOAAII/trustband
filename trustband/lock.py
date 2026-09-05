"""The provenance lockfile: pin what the agent was approved to see, refuse drift.

THE ATTACK IT CLOSES
    A server ships a clean catalog, passes review, then changes a description
    or a schema; a client re-reads it without a word; the model obeys the new
    text. Clean-then-dirty is the pattern -- nobody ships poison in 1.0.0
    when they can ship it in 1.0.16 -- and a pin taken at approval catches
    exactly that. A pin says nothing about whether 1.0.0 was clean. Scanning
    does that, and it is a different tool run at a different time.

WHERE THE PIN LIVES, AND WHY THAT IS THE POINT
    The lockfile's digest is a field of the policy. The policy's digest is in
    every capability's MAC. So a capability minted under manifest v1 is dead
    under v2 at conjunct (G) -- policy currency, Phase 2, proved and
    deposited. Rug-pull revocation is a MAC failure at the gate, not a check
    a client could skip. Everyone else pins; this binds the pin to
    authorisation. The BINDING is machine-checked. The PINNING -- what is
    digested, when, and what drift refuses -- is held by the conformance
    suite, and every document says which is which.

ONE DIGEST, GLOBAL INVALIDATION
    A change on server X invalidates every outstanding capability for server
    Y until re-approval. Under shadow that is a flag; under enforce it is a
    stop. Stated on the page as the friction being the security, and the
    benign-drift rate is measured in shadow before enforce is recommended.
    A per-tool binding would be a new field in `Cap`, a proof change, and is
    not taken here.

CANONICAL, OR THE DIGEST LIES
    Item digests go through `policy.encode`: NFC-normalised strings, sorted
    maps, fixed-width ints. Two descriptions that render alike but differ in
    normalisation are the same pin; two that differ in one byte are not. The
    encoder rejects floats, which schemas can carry (`"minimum": 0.5`), so a
    float is written as its shortest round-trip repr, tagged, before
    encoding. Said here because a silent coercion is where digests diverge.

RE-APPROVAL IS A PERSON
    `accept()` is called by `trustband lock accept` after `trustband lock
    diff` has shown someone what changed. Never automatic. With nobody
    present, drift under enforce is a refusal, and the record says so.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from trustband.policy import encode as _encode

KINDS = ("tool", "server", "skill", "model")
LOCK_NAME = "trustband.lock"
PENDING_NAME = "lock_pending.json"


class LockError(ValueError):
    """A malformed lockfile or observation. Never raised on the decision path."""


def _on_domain(v: Any) -> Any:
    """Map a JSON-ish value onto the policy domain. Floats become tagged
    strings; anything else outside the domain becomes its repr, tagged, so
    an exotic schema can be pinned rather than crash the observer."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return f"float:{v!r}"
    if isinstance(v, (list, tuple)):
        return [_on_domain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _on_domain(x) for k, x in v.items()}
    return f"repr:{v!r}"


def item_digest(kind: str, name: str, description: Any = "", schema: Any = None,
                version: Any = None) -> str:
    if kind not in KINDS:
        raise LockError(f"kind must be one of {KINDS}, not {kind!r}")
    if not isinstance(name, str) or not name:
        raise LockError("an item needs a non-empty string name")
    rec = {"kind": kind, "name": name,
           "description": "" if description is None else str(description),
           "schema": _on_domain(schema), "version": None if version is None else str(version)}
    return hashlib.sha256(_encode(rec)).hexdigest()


def key_of(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def observe(kind: str, name: str, description: Any = "", schema: Any = None,
            version: Any = None) -> Dict[str, Any]:
    """One observed item, digested, with the summary a person will diff."""
    return {
        "kind": kind, "name": name,
        "digest": item_digest(kind, name, description, schema, version),
        "summary": {
            "description": ("" if description is None else str(description))[:600],
            "schema": _on_domain(schema),
            "version": None if version is None else str(version),
        },
    }


def _atomic_write(path: Path, text: str) -> None:
    # A fresh home has no directory yet; the first observation must not fail
    # on that. Found by the shadow case of the drift test.
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


class Lockfile:
    """`trustband.lock`: pinned items, and the one digest that binds them."""

    def __init__(self, path: Any) -> None:
        self.path = Path(path)
        self.items: Dict[str, Dict[str, Any]] = {}
        self.load()

    # -- persistence -----------------------------------------------------------
    @property
    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> None:
        self.items = {}
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1 or not isinstance(data.get("items"), dict):
                raise ValueError("wrong shape")
            for k, it in data["items"].items():
                if not isinstance(it, dict) or "digest" not in it:
                    raise ValueError(f"item {k} has no digest")
            self.items = data["items"]
        except Exception as exc:
            # A corrupt lockfile is not "no lockfile". Nothing is pinned and
            # nothing can be verified, so drift cannot be told from drift.
            # The caller treats an unloadable lock as everything drifted.
            raise LockError(f"{self.path} is unreadable ({exc}); refusing to "
                            f"guess what was pinned. Delete it and re-accept.") from None

    def save(self) -> None:
        _atomic_write(self.path, json.dumps({
            "version": 1, "digest": self.digest,
            "pinned_at": time.time(), "items": self.items}, indent=1, sort_keys=True))

    # -- the digest that goes into the policy ---------------------------------
    @property
    def digest(self) -> str:
        """Over the pinned digests only, keyed and sorted by the encoder, so
        the summaries a person reads never change the number the gate binds."""
        return hashlib.sha256(_encode(
            {k: it["digest"] for k, it in self.items.items()})).hexdigest()

    # -- drift -----------------------------------------------------------------
    def check(self, observed: List[Dict[str, Any]], kind: Optional[str] = None,
              full: bool = False) -> List[Dict[str, Any]]:
        """What differs between the pins and what was just seen.

        `full=True` means `observed` is the complete catalog of `kind` (an
        MCP `tools/list`), so a pinned item that is absent is `removed`.
        Order never matters: items are keyed, not listed.
        """
        seen = {key_of(o["kind"], o["name"]): o for o in observed}
        out: List[Dict[str, Any]] = []
        for k, o in seen.items():
            pinned = self.items.get(k)
            if pinned is None:
                out.append({"item": k, "change": "new", "from": None,
                            "to": o["digest"], "before": None, "after": o["summary"]})
            elif pinned["digest"] != o["digest"]:
                out.append({"item": k, "change": "changed", "from": pinned["digest"],
                            "to": o["digest"], "before": pinned.get("summary"),
                            "after": o["summary"]})
        if full and kind:
            for k, pinned in self.items.items():
                if pinned.get("kind") == kind and k not in seen:
                    out.append({"item": k, "change": "removed", "from": pinned["digest"],
                                "to": None, "before": pinned.get("summary"), "after": None})
        return out

    def accept(self, observed: List[Dict[str, Any]], remove: List[str] = ()) -> None:
        """Re-pin. A person has seen the diff; this writes it and nothing else."""
        for o in observed:
            self.items[key_of(o["kind"], o["name"])] = {
                "kind": o["kind"], "name": o["name"], "digest": o["digest"],
                "summary": o["summary"], "pinned_at": time.time()}
        for k in remove:
            self.items.pop(k, None)
        self.save()


# -- the pending file: what was seen and not yet accepted --------------------

def read_pending(home: Path) -> Dict[str, Dict[str, Any]]:
    p = Path(home) / PENDING_NAME
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_pending(home: Path, observed: List[Dict[str, Any]]) -> None:
    """Merge the latest observation of each item into the pending file."""
    cur = read_pending(home)
    for o in observed:
        cur[key_of(o["kind"], o["name"])] = o
    _atomic_write(Path(home) / PENDING_NAME, json.dumps(cur, indent=1, sort_keys=True))
