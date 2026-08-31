"""Signed, versioned policy bundles — distribute one policy to many agents.

WHY IT EXISTS
    An organisation running a policy across many agents wants a version, so a
    rollout and rollback are named, and a signature, so each agent enforces the
    policy the org published and not one swapped on disk.

    This is operational, not a defence. The gate already refuses anything a
    policy does not permit; a tampered bundle is caught when it fails to verify.
    It is a supply-chain check on the policy file, not a hole in enforcement.

BUILT ON WHAT IS ALREADY HERE
    `policy.encode` is canonical and injective, so a digest is stable across key
    order and formatting -- two policies that mean the same thing sign the same.
    `hmac` is the primitive the audit chain already seals with. The signature
    covers version AND digest AND bytes, so an old signed policy cannot be
    replayed under a new version, and a policy whose digest does not match its
    bytes cannot be presented.

NOT ASYMMETRIC
    HMAC: the verifier holds the signer's key. Right for one organisation
    distributing to its own agents. A public-key scheme is a later change of
    primitive, not of shape -- the same swap the KMS custody backend was.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional, Tuple

from trustband.policy import digest as policy_digest, encode as policy_encode


class BundleError(Exception):
    """A bundle that will not verify. Never loaded."""


def _sig_message(version: int, digest_hex: str, policy: Dict[str, Any]) -> bytes:
    """The bytes the signature covers: version, digest, and canonical policy.

    Canonical policy bytes, not the JSON text, so a bundle re-serialised with
    different whitespace still verifies -- the signature is over meaning, like
    the digest.
    """
    return (str(version).encode() + b"\x00" + digest_hex.encode() + b"\x00"
            + policy_encode(policy))


def make_bundle(policy: Dict[str, Any], version: int, key: bytes
                ) -> Dict[str, Any]:
    """Sign a policy into a bundle."""
    d = policy_digest(policy).hex()
    sig = hmac.new(key, _sig_message(version, d, policy), hashlib.sha256).hexdigest()
    return {"version": version, "policy": policy, "digest": d, "sig": sig}


def verify_bundle(bundle: Dict[str, Any], key: bytes,
                  min_version: Optional[int] = None) -> Dict[str, Any]:
    """Return the policy if the bundle verifies, else raise BundleError.

    Checks, in order and all fail-closed:
      * the digest matches the policy's canonical encoding
      * the signature matches version, digest and bytes under `key`
      * the version is at least `min_version`, if one is required
    """
    for field in ("version", "policy", "digest", "sig"):
        if field not in bundle:
            raise BundleError(f"bundle missing {field!r}")
    policy = bundle["policy"]
    version = bundle["version"]

    want_digest = policy_digest(policy).hex()
    if not hmac.compare_digest(want_digest, str(bundle["digest"])):
        raise BundleError(
            "digest does not match the policy bytes -- the policy was changed")

    want_sig = hmac.new(key, _sig_message(version, want_digest, policy),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want_sig, str(bundle["sig"])):
        raise BundleError(
            "signature does not verify -- wrong key, or version/digest altered")

    if min_version is not None and version < min_version:
        raise BundleError(
            f"bundle version {version} is below the required floor "
            f"{min_version} -- a rollback to an older signed policy is refused")

    return policy


def load_bundle_file(path: Any, key: Optional[bytes],
                     min_version: Optional[int] = None
                     ) -> Tuple[Dict[str, Any], bool]:
    """Read a bundle file. Returns (policy, verified).

    With no key the policy loads but `verified` is False -- the caller is told
    it was not verified rather than being left to assume it was. Verification
    without a key is not silently implied.
    """
    bundle = json.loads(open(path, encoding="utf-8").read())
    if key is None:
        if "policy" not in bundle:
            raise BundleError("not a bundle: no 'policy'")
        return bundle["policy"], False
    return verify_bundle(bundle, key, min_version), True
