"""Canonical policy encoding and digest — the implementation half of Phase 2.

The Verus crate proves that a capability's tag COMMITS to a policy digest. It
cannot prove that structurally equal policies produce equal digests, because it
models no bytes: `mac` is uninterpreted over typed arguments, not over an octet
string. That half lives here, and it is assumption **A12** of record.

This module implements the encoding specified in `warrantable/PHASE2_SERIALISATION.md`
before any proof source was written:

    encode(v) ::= tag_byte || len_u32_be || payload

  1. version byte first — two policies equal under different schema versions
     encode differently, deliberately;
  2. a distinct tag byte per type, with ABSENT and present-but-null distinct
     and never conflated;
  3. length prefixes on every value, so concatenation is unambiguous;
  4. maps sorted by ENCODED key, so iteration order cannot reach the digest;
  5. strings UTF-8, NFC-normalised before BOTH comparison and encoding —
     normalising only at encode time would make policies that compare unequal
     produce equal digests;
  6. integers fixed-width big-endian, so no value has two encodings.

WHAT IS GUARANTEED
    Total and injective **on the restricted domain**: finite maps, UTF-8 keys,
    values from the closed tag set, no cycles, no floats.

WHAT IS NOT
    Not total on an unrestricted domain. CaMeL's `Capabilities.other_metadata`
    is `dict[str, Any]` with no schema, and `Any` admits objects with no
    canonical encoding. **A partial encoder is unsound in the dangerous
    direction**: a policy that fails to encode either blocks issuance, or — if
    an implementer adds a fallback — silently collapses distinct policies onto
    one digest. So this module REJECTS AT CONSTRUCTION rather than at encode
    time, and there is deliberately no fallback path.

    Injectivity of the ENCODING is not collision resistance of
    `digest = sha256(encode(p))`. That is a cryptographic assumption; this crate
    assumes no algebraic property of any hash.
"""
from __future__ import annotations

import hashlib
import unicodedata
from typing import Any, Dict, List, Union

SCHEMA_VERSION = 1

# One tag per type. ABSENT exists so that "key missing" and "key present with
# value null" can never encode identically.
TAG_INT = 0x01
TAG_STR = 0x02
TAG_BOOL = 0x03
TAG_NULL = 0x04
TAG_LIST = 0x05
TAG_MAP = 0x06
TAG_ABSENT = 0x07

INT_WIDTH = 8  # fixed-width big-endian, signed

PolicyValue = Union[int, str, bool, None, List[Any], Dict[str, Any]]


class PolicyDomainError(ValueError):
    """A value outside the restricted domain. Raised AT CONSTRUCTION.

    Not at encode time, and never swallowed: the whole point of the restriction
    is that an unencodable policy must stop issuance rather than acquire a
    default digest.
    """


def _norm(s: str) -> str:
    """NFC, applied before comparison as well as encoding — see (5)."""
    return unicodedata.normalize("NFC", s)


def _check(v: Any, path: str = "$", _seen: frozenset = frozenset()) -> None:
    """Reject anything outside the domain, naming where it was found."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return
    if isinstance(v, int):
        lo, hi = -(2 ** (INT_WIDTH * 8 - 1)), 2 ** (INT_WIDTH * 8 - 1) - 1
        if not (lo <= v <= hi):
            raise PolicyDomainError(
                f"{path}: integer {v} exceeds the fixed {INT_WIDTH}-byte width; "
                f"a wider encoding would admit two encodings of one value")
        return
    if isinstance(v, float):
        raise PolicyDomainError(
            f"{path}: float rejected. IEEE NaN has no equality and signed zero "
            f"has two representations of one value; either would break "
            f"injectivity. Use an integer, or a string in a declared format.")
    if id(v) in _seen:
        raise PolicyDomainError(f"{path}: cycle detected; the domain is acyclic")
    if isinstance(v, list):
        seen = _seen | {id(v)}
        for i, item in enumerate(v):
            _check(item, f"{path}[{i}]", seen)
        return
    if isinstance(v, dict):
        seen = _seen | {id(v)}
        for k, item in v.items():
            if not isinstance(k, str):
                raise PolicyDomainError(
                    f"{path}: map key {k!r} is {type(k).__name__}, not str; "
                    f"non-string keys have no canonical ordering")
            _check(item, f"{path}.{k}", seen)
        return
    raise PolicyDomainError(
        f"{path}: {type(v).__name__} is outside the policy domain. The closed "
        f"set is int, str, bool, None, list, dict. Arbitrary objects have no "
        f"canonical encoding, and accepting one would make the digest a "
        f"function of object identity rather than of policy content.")


def _enc(v: Any) -> bytes:
    if v is None:
        return _frame(TAG_NULL, b"")
    if isinstance(v, bool):                      # BEFORE int — bool subclasses int
        return _frame(TAG_BOOL, b"\x01" if v else b"\x00")
    if isinstance(v, int):
        return _frame(TAG_INT, v.to_bytes(INT_WIDTH, "big", signed=True))
    if isinstance(v, str):
        return _frame(TAG_STR, _norm(v).encode("utf-8"))
    if isinstance(v, list):
        return _frame(TAG_LIST, b"".join(_enc(x) for x in v))
    if isinstance(v, dict):
        # Sorted by ENCODED key, not by the key string: (4). Sorting by the
        # Python string would let two keys that normalise alike order
        # differently from how they encode.
        items = sorted(((_enc(_norm(k)), _enc(val)) for k, val in v.items()),
                       key=lambda kv: kv[0])
        return _frame(TAG_MAP, b"".join(k + val for k, val in items))
    raise PolicyDomainError(f"unencodable: {type(v).__name__}")  # unreachable


def _frame(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(4, "big") + payload


def encode(policy: PolicyValue) -> bytes:
    """Canonical bytes for a policy. Raises PolicyDomainError off-domain."""
    _check(policy)
    return bytes([SCHEMA_VERSION]) + _enc(policy)


def digest(policy: PolicyValue) -> bytes:
    """sha256(encode(policy)). 32 bytes.

    Collision resistance of sha256 is assumed; nothing here proves it, and the
    Verus crate assumes no algebraic property of any hash or MAC.
    """
    return hashlib.sha256(encode(policy)).digest()


def equal(a: PolicyValue, b: PolicyValue) -> bool:
    """Structural equality that AGREES WITH THE DIGEST by construction.

    Comparing with `==` would disagree on NFC-distinct strings that encode
    alike, which is exactly the failure (5) exists to prevent.
    """
    return encode(a) == encode(b)
