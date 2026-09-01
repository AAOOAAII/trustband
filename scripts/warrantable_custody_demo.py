#!/usr/bin/env python3
"""Custody demonstration: the gate mints and verifies with no key in process.

WHAT THIS SHOWS, AND WHAT IT DOES NOT
    Shows: with an external signer, `EpochKeyStore` holds no key material,
    `k_gov()` and `leak()` refuse, and the gate still mints a capability,
    accepts a genuine tag and rejects a forged one. Extraction fails while the
    operation succeeds — that pair IS the custody claim.

    Does NOT show: that AWS KMS behaves as modelled. The client here is a fake
    that holds key material outside the caller and answers only through
    operations, which is the SHAPE of KMS, not KMS. Running this against a real
    account is a separate exercise and is not performed here.

Run:  python scripts/warrantable_custody_demo.py
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import platform
import secrets
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from trustband.custody import AwsKmsHmacSigner, CustodyBackendError  # noqa: E402
from trustband.gate import CustodyError, EpochKeyStore, Gate  # noqa: E402


class FakeKms:
    """Holds key material the way KMS does: outside the caller, reachable only
    through operations. Deliberately minimal — every method here is one the
    real client also has, with the same signature."""

    def __init__(self) -> None:
        self._cmk: Dict[str, bytes] = {}
        self._deleted: set = set()

    def create(self, key_id: str) -> str:
        self._cmk[key_id] = secrets.token_bytes(32)
        return key_id

    def generate_mac(self, *, KeyId: str, Message: bytes, MacAlgorithm: str):
        if KeyId in self._deleted:
            raise RuntimeError("KMSInvalidStateException: key pending deletion")
        if KeyId not in self._cmk:
            raise RuntimeError("NotFoundException")
        assert MacAlgorithm == "HMAC_SHA_256"
        return {"Mac": hmac.new(self._cmk[KeyId], Message, sha256).digest()}

    def schedule_key_deletion(self, *, KeyId: str, PendingWindowInDays: int):
        self._deleted.add(KeyId)
        return {"KeyId": KeyId, "PendingWindowInDays": PendingWindowInDays}


def main() -> int:
    kms = FakeKms()
    kms.create("cmk-epoch-0")
    kms.create("cmk-epoch-1")
    signer = AwsKmsHmacSigner(
        kms, key_ids={0: "cmk-epoch-0", 1: "cmk-epoch-1"})
    keys = EpochKeyStore(signer=signer)
    gate = Gate(budget=3, keys=keys)

    checks: list = []

    def check(name: str, got: Any, want: Any, note: str = "") -> None:
        ok = got == want
        checks.append({"check": name, "got": got, "want": want,
                       "pass": ok, "note": note})
        print(f"  [{'PASS' if ok else '*** FAIL'}] {name}: {got!r}")

    print("== custody, measured from live objects ==")
    c = keys.describe_custody()
    check("store.extractable", c["key_extractable_by_this_process"], False)
    check("store.extraction_probe", c["extraction_probe_succeeded"], False,
          "asking for the key must fail")
    check("store.mac_operation_probe", c["mac_operation_probe_succeeded"], True,
          "using the key must succeed — this pair is the claim")
    check("kms.key_bytes_in_process", signer.describe()["key_bytes_in_process_memory"], False)

    print("== key extraction refused ==")
    try:
        keys.k_gov(0)
        check("k_gov refused", False, True)
    except CustodyError:
        check("k_gov refused", True, True)
    try:
        keys.leak(0)
        check("leak refused", False, True)
    except CustodyError:
        check("leak refused", True, True, "cannot leak what is not held")

    print("== the gate works anyway ==")
    decision, cap = gate.govern_issue(sess=7, tier=2, nonce=99)
    check("govern_issue allowed", bool(decision), True)
    check("tag length", len(cap.tag) if cap else 0, 32)
    check("verify genuine", keys.verify(cap.epoch, *cap.bound_fields(), cap.tag), True)
    check("verify forged", keys.verify(cap.epoch, *cap.bound_fields(), b"\x00" * 32), False)
    check("key bytes in process after mint+verify", dict(keys._keys), {},
          "empty dict — no key material ever entered this process")

    print("== rotation retires the CMK ==")
    gate.govern_rotate()
    retired = signer.retire(0)
    check("retire scheduled deletion", retired["epoch"], 0)
    try:
        signer(0, b"probe")
        check("minting under retired CMK refused", False, True)
    except CustodyBackendError:
        check("minting under retired CMK refused", True, True,
              "and (F) rejects retired capabilities regardless, by integer "
              "comparison, using no MAC property")

    def _git(*a: str) -> str:
        try:
            return subprocess.run(("git", *a), cwd=str(REPO), capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except Exception:
            return "unavailable"

    # THE PATHSPEC MUST EXIST.
    #
    # This read `warrantable` until 2026-09-01. The package was renamed to
    # `trustband`, so the pathspec matched nothing, git returned empty stdout
    # with rc=0, and every artifact produced after the rename was stamped
    # tree_clean=True however dirty the tree was. A provenance stamp that
    # cannot say "dirty" is worse than no stamp, so a missing watched path is
    # now an explicit unknown rather than a silent pass.
    _watch = [p for p in ("trustband", "scripts/warrantable_custody_demo.py")
              if (REPO / p).exists()]
    if len(_watch) < 2:
        dirty = "PROVENANCE UNAVAILABLE: a watched path is missing"
    else:
        dirty = "\n".join(
            ln for ln in _git("status", "--porcelain", *_watch).splitlines()
            if "battery_results.json" not in ln
            and "custody_demo.json" not in ln)

    passed = sum(1 for c_ in checks if c_["pass"])
    envelope = {
        "artifact": "warrantable custody demonstration",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc)
                                  .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "tree_clean_for_these_paths": (dirty == ""),
        "uncommitted_paths": dirty.splitlines(),
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "source_sha256": {
            rel: hashlib.sha256((REPO / rel).read_bytes()).hexdigest()
            for rel in ("trustband/gate.py", "trustband/custody.py",
                        "scripts/warrantable_custody_demo.py")
        },
        "backend": "FakeKms — the SHAPE of AWS KMS, not AWS KMS. No account "
                   "was contacted. Running this against a real CMK is a "
                   "separate exercise and has not been performed.",
        "summary": {"checks": len(checks), "passed": passed,
                    "failed": len(checks) - passed},
        "checks": checks,
    }
    out = REPO / "trustband/custody_demo.json"
    out.write_text(json.dumps(envelope, indent=2, default=str))
    print(f"\n  checks: {passed}/{len(checks)} passed")
    print(f"  results: {out}")
    print(f"  commit {envelope['commit'][:12]} "
          f"tree_clean={envelope['tree_clean_for_these_paths']} "
          f"{envelope['generated_utc']}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
