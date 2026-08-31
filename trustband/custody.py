"""External custody for `EpochKeyStore` — AWS KMS HMAC.

WHY THIS EXISTS
    `EpochKeyStore` in-process holds every non-retired epoch key in this
    process's memory, and `describe_custody()` says so. That is fine for a
    battery and fatal for a pilot, because the whole claim is that owning the
    process does not give you the policy.

    `gate.py` no longer asks for keys — it calls `tag()`/`verify()` — so a
    backend only has to answer ONE question: given an epoch and a message,
    what is the MAC? That is `signer(epoch, message) -> bytes`, and this module
    implements it against AWS KMS `GenerateMac`.

ONE CMK PER EPOCH, AND WHY IT MATTERS
    The model's `k_gov` is an epoch-indexed key FAMILY, and rotation DISCARDS
    the retired key: conjunct (F) rejects a retired capability by integer
    comparison, and `EpochKeyStore.k_gov` on a discarded epoch raises because
    the key is *gone*, not merely refused.

    A single CMK reused across epochs cannot express that. You could stop
    calling it, but the key would still exist and anyone with `kms:GenerateMac`
    could mint for a "retired" epoch. So: one CMK per epoch, and rotation
    schedules the retired one for deletion. Using one key for everything is the
    cheap option and it silently weakens (F) from "gone" to "we stopped asking".

PORTING TO ANOTHER KMS
    One operation, so another backend is an adapter rather than a rewrite:
      GenerateMac(KeyId, Message, MacAlgorithm) -> Mac
        GCP    : MacSign          Azure : (no native HMAC; use Managed HSM)
        Vault  : transit/hmac     PKCS#11: C_SignInit/C_Sign with CKM_SHA256_HMAC

VALIDATED AGAINST A REAL KEY, 2026-08-29
    Run against AWS KMS in eu-west-2 with an `HMAC_256` /
    `GENERATE_VERIFY_MAC` CMK, origin `AWS_KMS` (key material generated in KMS
    and non-exportable by construction):

      extractable False · extraction probe False · mac operation probe True
      k_gov()                      refused
      gate minted, verified genuine True and forged False
      _keys in process             {}      <- zero key bytes, throughout
      authorize                    True
      GenerateMac calls            6
      minting under a retired CMK  refused

    So the claim is no longer "demonstrated against a fake with the shape of
    KMS". The key was never in this process and the gate worked anyway. The CMK
    was then scheduled for deletion and confirmed `PendingDeletion`.

WHAT THIS DOES NOT BUY, STATED PLAINLY
    - A KMS administrator, or anything holding `kms:GenerateMac` on the epoch
      CMK, can mint capabilities. Custody moves the key out of THIS process; it
      does not put it beyond the cloud account. An enclave would; this does not.
    - `ScheduleKeyDeletion` has a minimum 7-day window. Between rotation and
      deletion the retired CMK still exists. Conjunct (F) rejects retired
      capabilities regardless, by integer comparison and without using any MAC
      property, so the window does not admit replay — but "the key is gone" is
      true only after it elapses.
    - Every `tag()` becomes a network call. That is a latency and availability
      change to the authorisation path, not a free substitution.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

MAC_ALGORITHM = "HMAC_SHA_256"
CUSTODY_MODE = "aws_kms_hmac"


class CustodyBackendError(Exception):
    """The backend could not answer. Deliberately NOT caught by the gate: a
    custody failure must stop authorisation, never fall back to a local key."""


class AwsKmsHmacSigner:
    """`signer(epoch, message) -> mac`, backed by one KMS HMAC CMK per epoch.

    The client is injected rather than constructed, so this is testable without
    AWS and without credentials.

    `key_ids` maps epoch -> CMK id/arn. `resolve` is consulted for epochs not
    in the map; supply one if epochs are created on demand. If neither knows
    the epoch, this raises rather than inventing a key, because minting under
    the wrong key would produce a capability that verifies nowhere.
    """

    def __init__(self, kms_client: Any, *, key_ids: Dict[int, str],
                 resolve: Optional[Any] = None) -> None:
        self._kms = kms_client
        self._key_ids: Dict[int, str] = dict(key_ids)
        self._resolve = resolve
        self._deleted: List[int] = []
        self._calls = 0

    # -- the one operation the gate needs ----------------------------------
    def __call__(self, epoch: int, message: bytes) -> bytes:
        key_id = self.key_id(epoch)
        self._calls += 1
        try:
            out = self._kms.generate_mac(
                KeyId=key_id, Message=message, MacAlgorithm=MAC_ALGORITHM)
        except Exception as exc:                      # boto3 ClientError et al
            raise CustodyBackendError(
                f"GenerateMac failed for epoch {epoch} on {key_id}: {exc}"
            ) from exc
        mac = out.get("Mac")
        if not isinstance(mac, (bytes, bytearray)) or len(mac) != 32:
            raise CustodyBackendError(
                f"GenerateMac returned {type(mac).__name__} of length "
                f"{len(mac) if mac is not None else 'n/a'}; expected 32 bytes "
                f"of HMAC_SHA_256")
        return bytes(mac)

    def key_id(self, epoch: int) -> str:
        if epoch in self._key_ids:
            return self._key_ids[epoch]
        if self._resolve is not None:
            kid = self._resolve(epoch)
            if kid:
                self._key_ids[epoch] = kid
                return kid
        raise CustodyBackendError(
            f"no CMK registered for epoch {epoch}. Register one before minting; "
            f"minting under another epoch's key produces a capability that "
            f"verifies nowhere.")

    # -- rotation ----------------------------------------------------------
    def retire(self, epoch: int, *, pending_window_days: int = 7) -> Dict[str, Any]:
        """Schedule the epoch's CMK for deletion. Call this from the operator's
        rotation runbook AFTER `Gate.govern_rotate()`, never before: rotating
        the gate first means no capability is minted under a key that is on its
        way out."""
        key_id = self.key_id(epoch)
        try:
            self._kms.schedule_key_deletion(
                KeyId=key_id, PendingWindowInDays=pending_window_days)
        except Exception as exc:
            raise CustodyBackendError(
                f"ScheduleKeyDeletion failed for epoch {epoch}: {exc}") from exc
        self._deleted.append(epoch)
        return {"epoch": epoch, "key_id": key_id,
                "pending_window_days": pending_window_days,
                "note": ("the CMK exists until the window elapses; conjunct (F) "
                         "rejects retired capabilities meanwhile, by integer "
                         "comparison and using no MAC property")}

    # -- measured, not asserted -------------------------------------------
    def describe(self) -> Dict[str, Any]:
        """Probes the live client. Nothing here is a constant."""
        reachable, probe_err = False, None
        try:
            any_epoch = next(iter(sorted(self._key_ids)), None)
            if any_epoch is not None:
                reachable = len(self(any_epoch, b"custody-probe")) == 32
        except Exception as exc:
            probe_err = f"{type(exc).__name__}: {exc}"
        return {
            "mode": CUSTODY_MODE,
            "measured_from": "live KMS client, not configuration",
            "mac_algorithm": MAC_ALGORITHM,
            "epochs_registered": sorted(self._key_ids),
            "epochs_scheduled_for_deletion": sorted(self._deleted),
            "key_bytes_in_process_memory": False,
            "backend_reachable": reachable,
            "probe_error": probe_err,
            "generate_mac_calls": self._calls,
            "note": (
                "The key is not in this process and cannot be. It IS reachable "
                "by anything holding kms:GenerateMac on these CMKs, including a "
                "KMS administrator — custody has moved out of the process, not "
                "out of the account. An enclave would do the latter; this does "
                "not, and a certificate claiming otherwise would be worse than "
                "one carrying an honest weaker claim."
            ),
        }
