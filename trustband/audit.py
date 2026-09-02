"""Tamper-evident audit log — hash-chained, and sealed against a dedicated key.

Both aiAuthZ and `arXiv:2603.14332` treat the log as a first-class security
artifact rather than debug output, and they are right: for a regulated buyer the
log is often the thing being bought. Warrantable had `Decision` records in a
Python list and nothing durable.

WHY A HASH CHAIN ALONE IS NOT ENOUGH — the point most implementations miss
    Linking each entry to the hash of the previous one makes tampering *visible
    to someone who already knows the correct head*. It does nothing against an
    attacker who can rewrite the file, because they recompute every hash after
    the entry they changed and the chain verifies perfectly.

    A chain is an integrity structure, not an integrity guarantee. What supplies
    the guarantee is an anchor the attacker cannot forge: a MAC over the head.
    With external custody that key is not in this process, so an attacker
    holding the log file cannot produce a valid seal.

    THE SEALING KEY IS NOT THE EPOCH KEY. Sealing under `k_gov(epoch)` meant
    `govern_rotate` discarded the key the seal was made with, so a legitimate
    untampered log reported FAILURE after any rotation -- a false alarm, arriving
    exactly when history most needs checking. Capability revocation wants keys to
    die and audit verification wants them to persist; `Gate` keeps two stores for
    that reason.

    So: `append` chains, `seal` anchors, and `verify` checks both. An unsealed
    tail is explicitly reported as unsealed rather than silently accepted.

WHAT IS RECORDED
    Every decision, allowed and refused alike, with the model conjunct that
    produced it. A log of grants only would answer "what did we permit" and not
    "what did we stop", and the second is the one a security review asks about.

WHAT THIS DOES NOT DO
    - **It does not prove the action happened.** It records what the gate
      decided. Whether the tool call then executed, and with what effect, is
      outside this boundary.
    - **Truncation before the first seal is undetectable.** Removing entries
      from the end of an unsealed tail leaves a valid chain. Seal often; the
      seal interval is the exposure window, and it is an operator choice with
      the same shape as `gov_budget`.
    - **It is not append-only storage.** Nothing here stops a file being
      rewritten; it makes rewriting *detectable*. Append-only media, a remote
      witness or periodic external publication are complementary and absent.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

GENESIS = b"\x00" * 32
_ENTRY_DOMAIN = b"trustband.audit.entry.v1|"
_SEAL_DOMAIN = b"trustband.audit.seal.v1|"


class AuditError(Exception):
    """The log does not verify. Never raised for an ordinary refusal."""


def _canon(obj: Any) -> bytes:
    """Deterministic bytes for an entry. Sorted keys, no whitespace drift."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: bytes
    body: Dict[str, Any]
    digest: bytes

    def as_dict(self) -> Dict[str, Any]:
        return {"seq": self.seq, "prev": self.prev.hex(),
                "body": self.body, "digest": self.digest.hex()}


@dataclass(frozen=True)
class Seal:
    """A MAC over a chain head. The anchor a bare hash chain lacks."""

    seq: int
    head: bytes
    epoch: int
    mac: bytes

    def as_dict(self) -> Dict[str, Any]:
        return {"seq": self.seq, "head": self.head.hex(),
                "epoch": self.epoch, "mac": self.mac.hex()}


def entry_digest(seq: int, prev: bytes, body: Dict[str, Any]) -> bytes:
    return hashlib.sha256(
        _ENTRY_DOMAIN + seq.to_bytes(8, "big") + prev + _canon(body)).digest()


def seal_message(seq: int, head: bytes) -> bytes:
    return _SEAL_DOMAIN + seq.to_bytes(8, "big") + head


class AuditLog:
    """Hash-chained entries with periodic MAC seals.

    PERSISTENCE, AND WHY IT IS NOT OPTIONAL FOR THE PRODUCT
        Until 2026-09-02 this class was memory-only: no path, no writes, and
        `export()` called from nowhere. The adapter is a subprocess per tool
        call, so the chain never reached a second entry, while three documents
        and a comparison table claimed a tamper-evident log. The mechanism was
        real and the wiring was missing.

        Pass `path` and every appended entry is written as one JSON line, and
        the chain is resumed from that file on construction -- which is what
        makes the chain meaningful to a process that exits after one decision.

    A LOGGING FAILURE MUST NOT CHANGE A DECISION
        If the file cannot be written, `append` records the failure on
        `write_errors` and returns the entry anyway. The gate then decides
        exactly as it would have. The opposite choice -- refusing when the log
        is unavailable -- turns a full disk into a denial of service against
        the agent, and makes the audit path an attack surface. See P-F0.6.
    """

    def __init__(self, path: "Optional[Path]" = None) -> None:
        self.entries: List[Entry] = []
        self.seals: List[Seal] = []
        self.path = Path(path) if path is not None else None
        #: Write failures, surfaced rather than swallowed. Never affects a decision.
        self.write_errors: List[str] = []
        if self.path is not None and self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Rebuild the chain from disk so a new process continues it.

        A torn final line is dropped rather than fatal: a process killed
        mid-write must not make the whole log unreadable. The dropped line is
        recorded, because silently losing a decision is the thing this log
        exists to prevent.
        """
        assert self.path is not None
        try:
            raw = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:                       # unreadable: start empty
            self.write_errors.append(f"resume failed: {exc}")
            return
        for line in raw:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                self.entries.append(Entry(seq=d["seq"],
                                          prev=bytes.fromhex(d["prev"]),
                                          body=d["body"],
                                          digest=bytes.fromhex(d["digest"])))
            except Exception:
                self.write_errors.append("dropped a torn entry on resume")

    @property
    def head(self) -> bytes:
        return self.entries[-1].digest if self.entries else GENESIS

    def append(self, body: Dict[str, Any]) -> Entry:
        seq = len(self.entries)
        prev = self.head
        e = Entry(seq=seq, prev=prev, body=body,
                  digest=entry_digest(seq, prev, body))
        self.entries.append(e)
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(e.as_dict(), sort_keys=True) + "\n")
            except OSError as exc:
                # Recorded, never raised. A decision does not depend on a disk.
                self.write_errors.append(f"append failed at seq {seq}: {exc}")
        return e

    def seal(self, keys: Any, epoch: int) -> Seal:
        """Anchor the current head.

        `keys` is an `EpochKeyStore` — `Gate.audit_keys`, NOT the capability
        key store, so rotation cannot destroy verifiability. Under external
        custody the key never enters this process, so an attacker holding the
        log cannot forge a seal, which is the entire reason the seal exists.
        """
        if not self.entries:
            # seq would be -1 and `(-1).to_bytes(8, "big")` raises OverflowError.
            # Refusing plainly beats crashing: an empty log has no head worth
            # anchoring, and a caller sealing one has a bug of their own.
            raise AuditError("cannot seal an empty log: there is no head to anchor")
        seq = len(self.entries) - 1
        head = self.head
        mac = keys.tag(epoch, 0, 0, seq + 1,
                       policy=seal_message(seq, head), sess_epoch=0)
        s = Seal(seq=seq, head=head, epoch=epoch, mac=mac)
        self.seals.append(s)
        return s

    def verify(self, keys: Any) -> Tuple[bool, Dict[str, Any]]:
        """Recompute the chain and check every seal. Reports, never guesses."""
        report: Dict[str, Any] = {
            "entries": len(self.entries), "seals": len(self.seals),
            "chain_ok": True, "seals_ok": True,
            "broken_at": None, "bad_seals": [], "unsealed_tail": 0,
        }
        prev = GENESIS
        for e in self.entries:
            if e.prev != prev or e.digest != entry_digest(e.seq, e.prev, e.body):
                report["chain_ok"] = False
                report["broken_at"] = e.seq
                break
            prev = e.digest
        for s in self.seals:
            if s.seq >= len(self.entries):
                report["bad_seals"].append({"seq": s.seq, "why": "beyond the log"})
                continue
            expected_head = self.entries[s.seq].digest
            ok = False
            try:
                # Named arguments deliberately: `verify` gained a parameter when
                # Phase 3 was ported, and the positional call silently shifted
                # `seal_message` into `policy` and the MAC into `sess_epoch` --
                # every seal then failed on a clean log. Naming them makes the
                # next signature change a TypeError instead of a false alarm.
                ok = keys.verify(s.epoch, 0, 0, s.seq + 1,
                                 policy=seal_message(s.seq, expected_head),
                                 sess_epoch=0, presented=s.mac)
            except Exception as exc:                    # retired epoch, custody
                report["bad_seals"].append({"seq": s.seq, "why": str(exc)[:80]})
                continue
            if not ok:
                report["bad_seals"].append({"seq": s.seq, "why": "MAC mismatch"})
        report["seals_ok"] = not report["bad_seals"]
        last_sealed = max((s.seq for s in self.seals), default=-1)
        report["unsealed_tail"] = len(self.entries) - 1 - last_sealed
        return (report["chain_ok"] and report["seals_ok"]), report

    def export(self) -> Dict[str, Any]:
        return {"entries": [e.as_dict() for e in self.entries],
                "seals": [s.as_dict() for s in self.seals]}
