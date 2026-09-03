"""A named agent, bound into the key hierarchy the gate already runs on.

WHY A MAC AND NOT A SIGNATURE
    A signature buys third-party verifiability: someone without the secret can
    check it. A LOCAL identity has no such reader. The gate that mints it is
    the gate that checks it, and for that reader an HMAC under the epoch key is
    the correct tool, not a compromise -- every capability this product issues
    is exactly that. Cross-organisation identity stays an Open Agent Passport
    concern, and when a passport is consumed here its id is a *label* until its
    signature is verified, never an authorisation input. That is the same rule
    as tool descriptions: detected, not banded.

THREE EXISTING CONJUNCTS, ONE NEW IDENTIFIER
    A forged or absent tag refuses like (B). A tag from a retired epoch refuses
    like (F), by integer comparison before any key is touched. A revoked agent
    refuses like (H), by set membership. An identity minted for one session and
    presented in another refuses like (C). None of this is in the deposited
    proof; until a Phase 7b extends the model, the conformance suite holds it.

THE PRINCIPAL
    `AgentId.principal` is an integer derived from the verified tag. A caller
    that mints capabilities for the agent passes it where a session int goes,
    so a capability minted for the researcher and presented by the writer is
    dead at the gate's own conjunct (C), and revoking the agent kills every
    capability it holds at (H). `Cap` never moved.

CROSS-PROCESS, STATED HONESTLY
    A swarm split across processes means separate Guards, and a MAC only
    verifies where the key lives. `FileEpochKeys` puts the epoch key in one
    file so processes share it. Any process that can read that file holds the
    key; `describe_custody()` says so. The revocation set lives beside it and
    is re-read on every check, never cached, so a revocation in one process is
    honoured by the next call in another.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Tuple

from trustband.gate import CustodyError, EpochKeyStore

#: Domain prefix. A capability tag and an agent tag over identical bytes are
#: different MACs, so one can never be presented as the other.
DOMAIN = b"trustband.agent.v1|"


class IdentityError(ValueError):
    """A malformed identity request. Raised at minting, never at checking."""


@dataclass(frozen=True)
class AgentId:
    """A named agent. Frozen: an identity is a value."""

    name: str
    role: str
    session: str
    #: The epoch it was minted in. Compared by integer at check time BEFORE
    #: any key is consulted, so a stale identity is refused without the
    #: verifier ever minting a key for an attacker-chosen epoch.
    epoch: int
    tag: bytes

    @property
    def principal(self) -> int:
        """The session-shaped integer a capability is minted for.

        Same range as `guard._session_int`, so it slots into the gate's
        session field unchanged. Derived from the TAG, so two agents with the
        same name under different keys are different principals.
        """
        d = hashlib.sha256(DOMAIN + self.tag).digest()
        return int.from_bytes(d[:4], "big") % (2 ** 31)

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "role": self.role, "session": self.session,
                "epoch": self.epoch, "tag": self.tag.hex()}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AgentId":
        return cls(name=str(d["name"]), role=str(d.get("role", "")),
                   session=str(d["session"]), epoch=int(d["epoch"]),
                   tag=bytes.fromhex(str(d["tag"])))


# --------------------------------------------------------------------------
# the shared key file
# --------------------------------------------------------------------------

def _atomic_write(path: Path, data: bytes) -> None:
    """Temp file, fsync, rename. A reader sees the old file or the new one,
    never a partial one -- pair 3 of the registered joins."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _exclusive_create(path: Path, data: bytes) -> bool:
    """Create `path` only if it does not exist, atomically. Two processes on
    first run both try; exactly one wins and the other reads the winner's.
    Written via a temp file and `link`, so the loser can never observe a
    half-written winner."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.init")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
            return True
        except FileExistsError:
            return False
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


class FileEpochKeys(EpochKeyStore):
    """An `EpochKeyStore` whose keys live in one file, so processes share them.

    The file holds the current epoch and the key for it, and only that key:
    rotation discards the retired one exactly as the in-process store does.
    Every operation re-reads the file first, so a rotation performed by
    another process is seen by the next MAC here, and `current_epoch` answers
    from the file rather than from this process's memory.

    A partial or unreadable file REFUSES rather than minting under an empty
    key. A file readable by group or world refuses too: the whole property is
    that the key is shared by processes of one user, not by everyone.
    """

    def __init__(self, path: Any) -> None:
        self.path = Path(path)
        self._custody_mode = "shared_key_file"
        self._signer = None
        self._keys: Dict[int, bytes] = {}
        self._discarded: list = []
        self._file_epoch = 0
        self._sync()

    # -- the file --------------------------------------------------------------
    def _sync(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fresh = json.dumps({"epoch": 0, "keys": {"0": secrets.token_hex(32)},
                                "note": "trustband shared epoch key; owner-only"})
            _exclusive_create(self.path, fresh.encode())
        st = os.stat(self.path)
        if st.st_mode & 0o077:
            raise CustodyError(
                f"{self.path} is readable by others (mode {oct(st.st_mode & 0o777)}); "
                f"a shared epoch key must be owner-only. chmod 600 it.")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            epoch = int(data["epoch"])
            keys = {int(e): bytes.fromhex(k) for e, k in data["keys"].items()}
            if epoch not in keys or any(len(k) != 32 for k in keys.values()):
                raise ValueError("current epoch has no 32-byte key")
        except Exception as exc:
            raise CustodyError(
                f"{self.path} is partial or corrupt ({exc}); refusing to mint "
                f"under an empty key. Delete it to start a fresh epoch 0.") from None
        self._keys = keys
        self._file_epoch = epoch
        self._discarded = [e for e in range(epoch) if e not in keys]

    def _write(self) -> None:
        _atomic_write(self.path, json.dumps({
            "epoch": self._file_epoch,
            "keys": {str(e): k.hex() for e, k in self._keys.items()},
            "note": "trustband shared epoch key; owner-only"}).encode())

    # -- the store interface, file-first -------------------------------------
    def _ensure(self, epoch: int) -> None:
        # Never mint a key for an epoch the file does not know. An unknown
        # epoch is unavailable, which the gate treats as retired at (F).
        return

    def advance_to(self, epoch: int) -> None:
        self._sync()
        if epoch <= self._file_epoch:
            return
        self._keys = {epoch: secrets.token_bytes(32)}
        self._discarded = list(range(epoch))
        self._file_epoch = epoch
        self._write()

    def tag(self, *a: Any, **kw: Any) -> bytes:
        self._sync()
        return super().tag(*a, **kw)

    def mac(self, *a: Any, **kw: Any) -> bytes:
        self._sync()
        return super().mac(*a, **kw)

    @property
    def current_epoch(self) -> int:
        self._sync()
        return self._file_epoch

    def describe_custody(self) -> Dict[str, Any]:
        d = super().describe_custody()
        d["mode"] = self._custody_mode
        d["key_file"] = str(self.path)
        d["note"] = ("SHARED KEY FILE. Every process of this user that can read "
                     f"{self.path} holds the current epoch key and can mint "
                     "any capability or identity. That is what lets a swarm "
                     "split across processes share one identity space, and it "
                     "is stated because it is the whole custody claim.")
        return d


# --------------------------------------------------------------------------
# minting, checking, revoking
# --------------------------------------------------------------------------

class AgentRegistry:
    """Mint, check and revoke agent identities against one key store."""

    def __init__(self, keys: EpochKeyStore,
                 epoch_of: Optional[Callable[[], int]] = None,
                 revocations_path: Optional[Any] = None) -> None:
        self.keys = keys
        self._epoch_of = epoch_of
        self.revocations_path = Path(revocations_path) if revocations_path else None
        self._revoked: Set[str] = set()

    def _epoch(self) -> int:
        # A file-backed store knows the epoch better than this process does.
        if isinstance(self.keys, FileEpochKeys):
            return self.keys.current_epoch
        if self._epoch_of is not None:
            return int(self._epoch_of())
        return self.keys.current_epoch

    def mint(self, name: str, role: str, session: str) -> AgentId:
        for label, v in (("name", name), ("session", session)):
            if not isinstance(v, str) or not v.strip():
                raise IdentityError(f"an agent {label} must be a non-empty string")
        role = str(role or "")
        epoch = self._epoch()
        tag = self.keys.mac(epoch, DOMAIN, name.encode(), role.encode(),
                            session.encode())
        return AgentId(name=name, role=role, session=session, epoch=epoch, tag=tag)

    def verify(self, agent: Any) -> Tuple[bool, str, Optional[str]]:
        """(ok, reason, conjunct-shape). Order mirrors the gate: epoch by
        integer before any key is touched, then the MAC, then revocation."""
        if not isinstance(agent, AgentId) or not agent.tag:
            return (False, "no identity tag: the agent presented a name with "
                           "nothing binding it to this key", "B")
        cur = self._epoch()
        if agent.epoch != cur:
            return (False,
                    f"retired identity: minted in epoch {agent.epoch}, keys are "
                    f"at epoch {cur} (integer comparison; no MAC property used)",
                    "F")
        try:
            ok = self.keys.verify_mac(agent.epoch, DOMAIN, agent.tag,
                                      agent.name.encode(), agent.role.encode(),
                                      agent.session.encode())
        except KeyError:
            return (False, f"identity epoch {agent.epoch} key is gone", "F")
        if not ok:
            return (False, "identity tag does not verify: not the tag governance "
                           "would have computed for this name, role and session "
                           "under this key", "B")
        rev = self.revoked()
        if "*" in rev:
            return (False, "the revocation file is unreadable, so nothing can "
                           "be known to be unrevoked; failing closed", "H")
        if agent.name in rev:
            return (False, f"agent {agent.name!r} is revoked "
                           f"(set membership; no MAC property used)", "H")
        return (True, "identity verified", None)

    def _file_names(self) -> Tuple[Set[str], bool]:
        """(names in the file, readable). Missing is readable and empty."""
        if self.revocations_path is None or not self.revocations_path.exists():
            return set(), True
        try:
            data = json.loads(self.revocations_path.read_text(encoding="utf-8"))
            return {str(x) for x in data}, True
        except Exception:
            return set(), False

    def revoke(self, name: str) -> None:
        """Structural. Writes a name to a set, touches no key, and every later
        check refuses it. Shared through the file when there is one. A corrupt
        file is overwritten with what is known, never propagated."""
        self._revoked.add(name)
        if self.revocations_path is not None:
            names, _ = self._file_names()
            _atomic_write(self.revocations_path,
                          json.dumps(sorted(names | self._revoked)).encode())

    def revoked(self) -> Set[str]:
        """Re-read every time -- pair 6. A cached set is a stale set.

        An unreadable file fails CLOSED, signalled by the sentinel "*": nothing
        can be known to be unrevoked, and the safe direction is to refuse.
        """
        names, ok = self._file_names()
        return set(self._revoked) | names | (set() if ok else {"*"})
